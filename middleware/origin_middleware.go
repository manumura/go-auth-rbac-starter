package middleware

import (
	"net/http"
	"net/url"
	"slices"
	"strings"

	"github.com/gin-gonic/gin"
	"github.com/manumura/go-auth-rbac-starter/exception"
	"github.com/rs/zerolog/log"
)

// OriginMiddleware validates the Origin or Referer header for state-changing requests
// This provides defense-in-depth against CSRF attacks
func OriginMiddleware(allowedOrigins []string) gin.HandlerFunc {
	return func(ctx *gin.Context) {
		// Skip validation for safe methods (GET, HEAD, OPTIONS, TRACE)
		if slices.Contains(safeHttpMethods, ctx.Request.Method) {
			ctx.Next()
			return
		}

		// Get Origin header (preferred)
		origin := ctx.GetHeader("Origin")

		// Fall back to Referer header if Origin is not present
		if origin == "" {
			referer := ctx.GetHeader("Referer")
			if referer != "" {
				parsedReferer, err := url.Parse(referer)
				if err == nil {
					origin = parsedReferer.Scheme + "://" + parsedReferer.Host
				}
			}
		}

		// If neither Origin nor Referer is present, block the request
		if origin == "" {
			log.Warn().
				Str("method", ctx.Request.Method).
				Str("path", ctx.Request.URL.Path).
				Msg("Request blocked: missing Origin and Referer headers")
			ctx.AbortWithStatusJSON(http.StatusForbidden, exception.ErrorResponse{
				Message:    ErrInvalidOrigin,
				StatusCode: http.StatusForbidden,
				Error:      http.StatusText(http.StatusForbidden),
			})
			return
		}

		// Validate origin against allowed origins
		if !isOriginAllowed(origin, allowedOrigins) {
			log.Warn().
				Str("origin", origin).
				Str("method", ctx.Request.Method).
				Str("path", ctx.Request.URL.Path).
				Strs("allowedOrigins", allowedOrigins).
				Msg("Request blocked: origin not allowed")
			ctx.AbortWithStatusJSON(http.StatusForbidden, exception.ErrorResponse{
				Message:    ErrInvalidOrigin,
				StatusCode: http.StatusForbidden,
				Error:      http.StatusText(http.StatusForbidden),
			})
			return
		}

		ctx.Next()
	}
}

// isOriginAllowed checks if the given origin is in the allowed list
func isOriginAllowed(origin string, allowedOrigins []string) bool {
	// Normalize origin (remove trailing slash if present)
	origin = normalizeOrigin(origin)

	for _, allowed := range allowedOrigins {
		normalizedAllowed := normalizeOrigin(allowed)

		// Exact match
		if origin == normalizedAllowed {
			return true
		}

		// Wildcard match (e.g., "*" allows all origins - use with caution)
		if normalizedAllowed == "*" {
			return true
		}
	}

	return false
}

// normalizeOrigin removes trailing slashes and converts to lowercase
func normalizeOrigin(origin string) string {
	if len(origin) > 0 && origin[len(origin)-1] == '/' {
		origin = origin[:len(origin)-1]
	}
	return strings.ToLower(origin)
}
