package middleware

import (
	"net/http"
	"slices"

	"github.com/gin-gonic/gin"
	"github.com/manumura/go-auth-rbac-starter/common"
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

		origin := common.GetOriginFromHeader(ctx)

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
		if !common.IsOriginAllowed(origin, allowedOrigins) {
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
