package middleware

import (
	"context"
	"errors"
	"fmt"
	"net/http"
	"strings"
	"time"

	"github.com/gin-gonic/gin"
	"github.com/redis/go-redis/v9"
	"github.com/rs/zerolog/log"
)

var (
	// Error responses
	internalServerErrorResponse = gin.H{
		"message":    "Internal server error",
		"error":      "internal_server_error",
		"statusCode": http.StatusInternalServerError,
	}

	rateLimitExceededResponse = gin.H{
		"message":    "Rate limit exceeded. Try again later.",
		"error":      "rate_limit_exceeded",
		"statusCode": http.StatusTooManyRequests,
	}

	serviceUnavailableResponse = gin.H{
		"message":    "Service temporarily unavailable. Please try again later.",
		"error":      "service_unavailable",
		"statusCode": http.StatusServiceUnavailable,
	}

	// Custom errors for rate limiting
	ErrRedisConnectionFailed = errors.New("redis connection failed")
	ErrRedisTimeout          = errors.New("redis operation timed out")
	ErrRateLimitExceeded     = errors.New("rate limit exceeded")
	ErrInvalidConfiguration  = errors.New("invalid rate limiter configuration")
)

// RateLimitConfig holds configuration for the rate limiter
type RateLimitConfig struct {
	RateLimit   int64
	Window      time.Duration
	RedisClient *redis.Client
	FailOpen    bool // If true, allows requests when Redis is unavailable
	KeyPrefix   string
}

// validateConfig validates the rate limiter configuration
func validateConfig(config *RateLimitConfig) error {
	if config.RedisClient == nil {
		return fmt.Errorf("%w: redis client is nil", ErrInvalidConfiguration)
	}
	if config.RateLimit <= 0 {
		return fmt.Errorf("%w: rate limit must be positive, got %d", ErrInvalidConfiguration, config.RateLimit)
	}
	if config.Window <= 0 {
		return fmt.Errorf("%w: window duration must be positive, got %v", ErrInvalidConfiguration, config.Window)
	}
	return nil
}

// getClientIdentifier extracts a unique identifier for the client
func getClientIdentifier(ctx *gin.Context) string {
	// Try X-User-ID header first (for authenticated users)
	if userID := ctx.Request.Header.Get("X-User-ID"); userID != "" {
		return sanitizeKey(userID)
	}

	// Try X-Forwarded-For header (for clients behind proxies/load balancers)
	if xff := ctx.Request.Header.Get("X-Forwarded-For"); xff != "" {
		// Take the first IP in the chain (original client)
		if idx := strings.Index(xff, ","); idx > 0 {
			return sanitizeKey(strings.TrimSpace(xff[:idx]))
		}
		return sanitizeKey(strings.TrimSpace(xff))
	}

	// Try X-Real-IP header
	if realIP := ctx.Request.Header.Get("X-Real-IP"); realIP != "" {
		return sanitizeKey(realIP)
	}

	// Fallback to RemoteAddr
	ip := ctx.ClientIP()
	// log.Info().Str("clientIP", ip).Msg("RateLimiterMiddleware: using RemoteAddr as client identifier")
	return sanitizeKey(ip)
}

// sanitizeKey removes potentially dangerous characters from the key
func sanitizeKey(key string) string {
	// Remove newlines and other control characters that could cause issues
	key = strings.ReplaceAll(key, "\n", "")
	key = strings.ReplaceAll(key, "\r", "")
	key = strings.ReplaceAll(key, ":", "_") // Avoid conflicts with Redis key separator
	return key
}

// isRedisConnectionError checks if the error is a Redis connection-related error
func isRedisConnectionError(err error) bool {
	if err == nil {
		return false
	}

	errStr := err.Error()
	return strings.Contains(errStr, "connection refused") ||
		strings.Contains(errStr, "connection reset") ||
		strings.Contains(errStr, "no connection") ||
		strings.Contains(errStr, "i/o timeout") ||
		strings.Contains(errStr, "network is unreachable") ||
		errors.Is(err, context.DeadlineExceeded) ||
		errors.Is(err, redis.ErrClosed)
}

// RateLimiterMiddleware is a middleware that limits the number of requests per user/IP address.
// It uses a sliding window log algorithm to track requests and enforce limits.
// The middleware relies on a Redis cache to store request timestamps for each user/IP.
func RateLimiterMiddleware(config *RateLimitConfig) gin.HandlerFunc {
	// Validate configuration at startup
	if err := validateConfig(config); err != nil {
		log.Fatal().Err(err).Msg("RateLimiterMiddleware: invalid configuration")
	}

	return func(ctx *gin.Context) {
		clientID := getClientIdentifier(ctx)
		if clientID == "" {
			log.Warn().
				Str("path", ctx.Request.URL.Path).
				Str("method", ctx.Request.Method).
				Msg("RateLimiterMiddleware: could not determine client identifier")
			// Use a fallback identifier
			clientID = "unknown"
		}

		now := time.Now()
		nowUnix := now.Unix()
		key := config.KeyPrefix + clientID

		log.Info().
			Str("clientID", clientID).
			Str("key", key).
			Str("path", ctx.Request.URL.Path).
			Msg("RateLimiterMiddleware: processing request")

		// Check Redis connectivity with a timeout context
		redisCtx, cancel := context.WithTimeout(ctx.Request.Context(), 5*time.Second)
		defer cancel()

		// Start a Redis transaction
		pipe := config.RedisClient.TxPipeline()

		// Add the current timestamp to the sorted set (use nanoseconds for unique member)
		/*
			Score (Unix timestamp in seconds):
			- Used for ordering and range operations
			- Enables ZRemRangeByScore to efficiently remove old timestamps outside the time window
			- Allows Redis to keep entries sorted by time

			Member (Unix nanoseconds):
			- Acts as the unique identifier for each request
			- Prevents duplicate entries when the same timestamp occurs
			- Required by Redis sorted set data structure
		*/
		pipe.ZAdd(redisCtx, key, redis.Z{Score: float64(nowUnix), Member: now.UnixNano()})
		// Remove timestamps outside the sliding window
		windowStartTime := nowUnix - int64(config.Window.Seconds())
		pipe.ZRemRangeByScore(redisCtx, key, "0", fmt.Sprintf("%d", windowStartTime))
		// Get the count of requests in the current window
		countCmd := pipe.ZCard(redisCtx, key)
		// Set the expiration for the key to be slightly longer than the window
		pipe.Expire(redisCtx, key, config.Window+time.Second)

		// Execute the transaction
		_, err := pipe.Exec(redisCtx)
		if err != nil {
			// Handle context cancellation (client disconnected)
			if errors.Is(err, context.Canceled) {
				log.Warn().
					Str("clientID", clientID).
					Msg("RateLimiterMiddleware: request canceled by client")
				ctx.Abort()
				return
			}

			// Handle different types of Redis errors
			if isRedisConnectionError(err) {
				log.Error().
					Err(err).
					Str("clientID", clientID).
					Str("key", key).
					Str("path", ctx.Request.URL.Path).
					Str("method", ctx.Request.Method).
					Bool("failOpen", config.FailOpen).
					Msg("RateLimiterMiddleware: Redis connection error")

				if config.FailOpen {
					// Allow the request through when Redis is unavailable (fail-open mode)
					log.Warn().
						Str("clientID", clientID).
						Msg("RateLimiterMiddleware: allowing request due to fail-open mode")
					ctx.Next()
					return
				}

				// Fail closed - return service unavailable
				ctx.AbortWithStatusJSON(http.StatusServiceUnavailable, serviceUnavailableResponse)
				return
			}

			// Log unexpected errors with full details
			log.Error().
				Err(err).
				Str("clientID", clientID).
				Str("key", key).
				Str("path", ctx.Request.URL.Path).
				Str("method", ctx.Request.Method).
				Msg("RateLimiterMiddleware: unexpected Redis error")

			ctx.AbortWithStatusJSON(http.StatusInternalServerError, internalServerErrorResponse)
			return
		}

		requestCount := countCmd.Val()

		log.Info().
			Int64("requestCount", requestCount).
			Int64("rateLimit", config.RateLimit).
			Str("clientID", clientID).
			Msg("RateLimiterMiddleware: request count checked")

		if requestCount > config.RateLimit {
			retryAfterSeconds := int(config.Window.Seconds())

			log.Warn().
				Int64("requestCount", requestCount).
				Int64("rateLimit", config.RateLimit).
				Str("clientID", clientID).
				Str("path", ctx.Request.URL.Path).
				Int("retryAfter", retryAfterSeconds).
				Msg("RateLimiterMiddleware: rate limit exceeded")

			// Set standard rate limit headers
			// https://developer.mozilla.org/en-US/docs/Web/HTTP/Reference/Headers/Retry-After
			ctx.Header("Retry-After", fmt.Sprintf("%d", retryAfterSeconds))
			// Additional rate limit headers (draft standard)
			ctx.Header("X-RateLimit-Limit", fmt.Sprintf("%d", config.RateLimit))
			ctx.Header("X-RateLimit-Remaining", "0")
			ctx.Header("X-RateLimit-Reset", fmt.Sprintf("%d", nowUnix+int64(config.Window.Seconds())))

			ctx.AbortWithStatusJSON(http.StatusTooManyRequests, rateLimitExceededResponse)
			return
		}

		// Set informational rate limit headers for successful requests
		remaining := config.RateLimit - requestCount
		if remaining < 0 {
			remaining = 0
		}
		ctx.Header("X-RateLimit-Limit", fmt.Sprintf("%d", config.RateLimit))
		ctx.Header("X-RateLimit-Remaining", fmt.Sprintf("%d", remaining))
		ctx.Header("X-RateLimit-Reset", fmt.Sprintf("%d", nowUnix+int64(config.Window.Seconds())))

		ctx.Next()
	}
}

// Sliding Window Log Algorithm https://raphaeldelio.com/2025/01/22/sliding-window-log-rate-limiter-redis-java/
// func RateLimiterMiddleware(redisClient *redis.Client, rateLimit int64, window time.Duration) gin.HandlerFunc {
// 	return func(ctx *gin.Context) {
// 		userID := ctx.Request.Header.Get("X-User-ID")
// 		if userID == "" {
// 			userID = ctx.Request.RemoteAddr
// 		}

// 		now := time.Now()
// 		key := "rate_limit:" + userID
// 		log.Info().Msgf("RateLimiterMiddleware: userID=%s, key=%s", userID, key)

// 		requestCount, err := redisClient.HLen(ctx, key).Result()
// 		if err != nil {
// 			log.Error().Err(err).Msg("RateLimiterMiddleware: Redis HLen failed")
// 			ctx.AbortWithStatusJSON(http.StatusInternalServerError, internalServerErrorResponse)
// 			return
// 		}
// 		log.Info().Msgf("RateLimiterMiddleware: requestCount=%d", requestCount)

// 		if requestCount > rateLimit {
// 			// https://developer.mozilla.org/en-US/docs/Web/HTTP/Reference/Headers/Retry-After
// 			ctx.Header("Retry-After", fmt.Sprintf("%d", int(window.Seconds())))
// 			ctx.AbortWithStatusJSON(http.StatusTooManyRequests, rateLimitExceededResponse)
// 			return
// 		}

// 		// Start a Redis transaction
// 		pipe := redisClient.TxPipeline()

// 		value := fmt.Sprintf("%d", now.UnixNano())
// 		pipe.HSet(ctx, key, value, "")
// 		pipe.HExpire(ctx, key, window, value) // available only since valkey 9.0.0

// 		// Execute the transaction
// 		_, err = pipe.Exec(ctx)
// 		if err != nil {
// 			log.Error().Err(err).Msg("RateLimiterMiddleware: Redis transaction failed")
// 			ctx.AbortWithStatusJSON(http.StatusInternalServerError, internalServerErrorResponse)
// 			return
// 		}

// 		ctx.Next()
// 	}
// }
