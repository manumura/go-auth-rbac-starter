package cookie

import (
	"net/http"

	"github.com/gin-gonic/gin"
)

const (
	accessToken          = "accessToken"
	refreshToken         = "refreshToken"
	accessTokenExpiresAt = "accessTokenExpiresAt"
	idToken              = "idToken"
	cookieMaxAge         = 60 * 60 * 24 // 24 hours
)

func SetAuthCookies(c *gin.Context, authCookieParams AuthCookieParams) {
	secure := c.Request.TLS != nil
	c.SetSameSite(http.SameSiteLaxMode)
	c.SetCookie(accessToken, authCookieParams.AccessToken, cookieMaxAge, "/", "", secure, true)
	c.SetCookie(refreshToken, authCookieParams.RefreshToken, cookieMaxAge, "/", "", secure, true)
	c.SetCookie(accessTokenExpiresAt, authCookieParams.AccessTokenExpiresAt.Format("20060102150405"), cookieMaxAge, "/", "", secure, true)
	c.SetCookie(idToken, authCookieParams.IdToken, cookieMaxAge, "/", "", secure, true)
}

func DeleteAuthCookies(c *gin.Context) {
	secure := c.Request.TLS != nil
	c.SetSameSite(http.SameSiteLaxMode)
	c.SetCookie(accessToken, "", -1, "/", "", secure, true)
	c.SetCookie(refreshToken, "", -1, "/", "", secure, true)
	c.SetCookie(accessTokenExpiresAt, "", -1, "/", "", secure, true)
	c.SetCookie(idToken, "", -1, "/", "", secure, true)
}

func ExtractAccessTokenFromCookie(ctx *gin.Context) (string, error) {
	return extractFromCookie(ctx, accessToken)
}

func ExtractRefreshTokenFromCookie(ctx *gin.Context) (string, error) {
	return extractFromCookie(ctx, refreshToken)
}

func extractFromCookie(ctx *gin.Context, name string) (string, error) {
	cookie, err := ctx.Cookie(name)
	if err != nil {
		return "", err
	}
	return cookie, nil
}
