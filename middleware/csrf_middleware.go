package middleware

import (
	"net/http"
	"slices"

	"github.com/gin-gonic/gin"
	"github.com/manumura/go-auth-rbac-starter/cache"
	"github.com/manumura/go-auth-rbac-starter/csrf"
	"github.com/manumura/go-auth-rbac-starter/exception"
	"github.com/manumura/go-auth-rbac-starter/security"
	"github.com/rs/zerolog/log"
)

// CSRFMiddleware validates session-bound CSRF tokens for authenticated routes
// It compares the CSRF token from the X-CSRF-Token header with the token stored in Redis
// This middleware MUST be used after AuthMiddleware as it requires the authenticated user
// Only validates CSRF for state-changing methods (POST, PUT, DELETE, PATCH)
// https://cheatsheetseries.owasp.org/cheatsheets/Cross-Site_Request_Forgery_Prevention_Cheat_Sheet.html
// https://codyaray.com/2020/08/vulnerable-csrf-attacks
// Another approach : https://www.samueladebayo.dev/posts/golang-cross-origin-protection/
func CSRFMiddleware(cacheService cache.CacheService) gin.HandlerFunc {
	return func(ctx *gin.Context) {
		// Skip CSRF validation for safe methods (GET, HEAD, OPTIONS, TRACE)
		if slices.Contains(safeHttpMethods, ctx.Request.Method) {
			ctx.Next()
			return
		}

		// Get authenticated user from context (set by AuthMiddleware)
		authenticatedUser, err := security.GetUserFromContext(ctx)
		if err != nil {
			log.Error().Err(err).Msg("cannot get user from context for CSRF validation")
			ctx.AbortWithStatusJSON(http.StatusUnauthorized, exception.ErrorResponse{
				Message:    "Unauthorized",
				StatusCode: http.StatusUnauthorized,
				Error:      http.StatusText(http.StatusUnauthorized),
			})
			return
		}

		// Extract token from header
		headerToken := csrf.ExtractCSRFTokenFromHeader(ctx)
		if headerToken == "" {
			log.Error().Str("userUUID", authenticatedUser.Uuid.String()).Msg(ErrCSRFTokenMissing)
			ctx.AbortWithStatusJSON(http.StatusForbidden, exception.ErrorResponse{
				Message:    ErrCSRFTokenMissing,
				StatusCode: http.StatusForbidden,
				Error:      http.StatusText(http.StatusForbidden),
			})
			return
		}

		// Validate token against stored session token in Redis
		valid, err := csrf.ValidateSessionToken(ctx, cacheService, authenticatedUser.Uuid.String(), headerToken)
		if err != nil {
			log.Error().Err(err).Str("userUUID", authenticatedUser.Uuid.String()).Msg("error validating CSRF token")
			ctx.AbortWithStatusJSON(http.StatusForbidden, exception.ErrorResponse{
				Message:    ErrCSRFTokenInvalid,
				StatusCode: http.StatusForbidden,
				Error:      http.StatusText(http.StatusForbidden),
			})
			return
		}

		if !valid {
			log.Error().Str("userUUID", authenticatedUser.Uuid.String()).Msg(ErrCSRFTokenInvalid)
			ctx.AbortWithStatusJSON(http.StatusForbidden, exception.ErrorResponse{
				Message:    ErrCSRFTokenInvalid,
				StatusCode: http.StatusForbidden,
				Error:      http.StatusText(http.StatusForbidden),
			})
			return
		}

		ctx.Next()
	}
}
