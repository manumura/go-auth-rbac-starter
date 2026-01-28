package csrf

import (
	"context"
	"crypto/rand"
	"crypto/subtle"
	"encoding/base64"
	"fmt"
	"net/http"
	"time"

	"github.com/gin-gonic/gin"
	"github.com/manumura/go-auth-rbac-starter/cache"
	"github.com/manumura/go-auth-rbac-starter/config"
	"github.com/manumura/go-auth-rbac-starter/cookie"
)

const (
	CsrfTokenCookie = "csrf_token"
	CsrfTokenHeader = "X-CSRF-Token"
	csrfTokenLength = 32
	cookieMaxAge    = 60 * 60 * 24 // 24 hours
	// Redis key prefix for session-bound CSRF tokens
	csrfKeyPrefix = "csrf:"
)

// GenerateToken creates a cryptographically secure random CSRF token
func GenerateToken() (string, error) {
	bytes := make([]byte, csrfTokenLength)
	if _, err := rand.Read(bytes); err != nil {
		return "", err
	}
	return base64.URLEncoding.EncodeToString(bytes), nil
}

// GenerateAndStoreSessionToken generates a CSRF token and stores it in Redis tied to the user's session
func GenerateAndStoreSessionToken(ctx context.Context, cacheService cache.CacheService, cfg config.Config, userUUID string) (string, error) {
	token, err := GenerateToken()
	if err != nil {
		return "", err
	}

	key := fmt.Sprintf("%s%s", csrfKeyPrefix, userUUID)
	expiration := time.Duration(cfg.AccessTokenExpiresInAsSeconds) * time.Second
	err = cacheService.Set(ctx, key, token, expiration)
	if err != nil {
		return "", err
	}

	return token, nil
}

// ValidateSessionToken validates a CSRF token against the stored session token
func ValidateSessionToken(ctx context.Context, cacheService cache.CacheService, userUUID string, token string) (bool, error) {
	key := fmt.Sprintf("%s%s", csrfKeyPrefix, userUUID)
	storedToken, err := cacheService.Get(ctx, key)
	if err != nil {
		return false, err
	}

	// Constant-time comparison to prevent timing attacks
	return subtle.ConstantTimeCompare([]byte(token), []byte(storedToken)) == 1, nil
}

// DeleteSessionToken removes the CSRF token from Redis (e.g., on logout)
func DeleteSessionToken(ctx context.Context, cacheService cache.CacheService, userUUID string) error {
	key := fmt.Sprintf("%s%s", csrfKeyPrefix, userUUID)
	return cacheService.Delete(ctx, key)
}

// ExtractCSRFTokenFromHeader extracts the CSRF token from the request header
func ExtractCSRFTokenFromHeader(c *gin.Context) string {
	return c.GetHeader(CsrfTokenHeader)
}

// SetCSRFCookie sets the CSRF token as a cookie
// HttpOnly is false so JavaScript can read it on the client side
func SetCSRFCookie(c *gin.Context, token string, params cookie.CookieParams) {
	c.SetSameSite(http.SameSiteLaxMode)
	c.SetCookie(
		CsrfTokenCookie,
		token,
		cookieMaxAge,
		"/",
		params.Domain,
		params.Secure,
		false, // HttpOnly=false so JS can read the cookie
	)
}

// DeleteCSRFCookie removes the CSRF token cookie
func DeleteCSRFCookie(c *gin.Context, params cookie.CookieParams) {
	c.SetSameSite(http.SameSiteLaxMode)
	c.SetCookie(CsrfTokenCookie, "", -1, "/", params.Domain, params.Secure, false)
}
