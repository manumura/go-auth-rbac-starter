package middleware

import (
	"fmt"
	"net/http"
	"time"

	"github.com/gin-gonic/gin"
	"github.com/redis/go-redis/v9"
	"github.com/rs/zerolog/log"
)

// RateLimitingMiddleware is a middleware that limits the number of requests per user/IP address.
// It uses a sliding window log algorithm to track requests and enforce limits.
// The middleware relies on a Redis cache to store request timestamps for each user/IP.
// Sliding Window Log Algorithm https://raphaeldelio.com/2025/01/22/sliding-window-log-rate-limiter-redis-java/
func RateLimitingMiddleware(redisClient *redis.Client, rateLimit int64, window time.Duration) gin.HandlerFunc {
	return func(ctx *gin.Context) {
		userID := ctx.Request.Header.Get("X-User-ID")
		if userID == "" {
			userID = ctx.Request.RemoteAddr
		}

		now := time.Now()
		nowUnix := now.Unix()
		key := "rate_limit:" + userID
		log.Info().Msgf("RateLimitingMiddleware: userID=%s, key=%s\n", userID, key)

		// Start a Redis transaction
		pipe := redisClient.TxPipeline()
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
		pipe.ZAdd(ctx, key, redis.Z{Score: float64(nowUnix), Member: now.UnixNano()})
		// Remove timestamps outside the sliding window
		pipe.ZRemRangeByScore(ctx, key, "0", fmt.Sprintf("%d", nowUnix-int64(window.Seconds())))
		// Get the count of requests in the current window
		countCmd := pipe.ZCard(ctx, key)
		// Set the expiration for the key to be slightly longer than the window
		pipe.Expire(ctx, key, window+time.Second)

		// Execute the transaction
		_, err := pipe.Exec(ctx)
		if err != nil {
			ctx.AbortWithStatusJSON(http.StatusInternalServerError, gin.H{
				"message":    "Internal server error",
				"error":      "internal_server_error",
				"statusCode": http.StatusInternalServerError,
			})
			return
		}

		requestCount := countCmd.Val()
		log.Info().Msgf("RateLimitingMiddleware: requestCount=%d\n", requestCount)

		if requestCount > rateLimit {
			// https://developer.mozilla.org/en-US/docs/Web/HTTP/Reference/Headers/Retry-After
			ctx.Header("Retry-After", fmt.Sprintf("%d", int(window.Seconds())))
			ctx.AbortWithStatusJSON(http.StatusTooManyRequests, gin.H{
				"message":    "Rate limit exceeded. Try again later.",
				"error":      "rate_limit_exceeded",
				"statusCode": http.StatusTooManyRequests,
			})
			return
		}
		ctx.Next()
	}
}
