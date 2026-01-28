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

func SetAuthCookies(c *gin.Context, cookieParams CookieParams, authCookieParams AuthCookieParams) {
	c.SetSameSite(http.SameSiteLaxMode)
	c.SetCookie(accessToken, authCookieParams.AccessToken, cookieMaxAge, "/", cookieParams.Domain, cookieParams.Secure, true)
	c.SetCookie(refreshToken, authCookieParams.RefreshToken, cookieMaxAge, "/", cookieParams.Domain, cookieParams.Secure, true)
	c.SetCookie(accessTokenExpiresAt, authCookieParams.AccessTokenExpiresAt.Format("20060102150405"), cookieMaxAge, "/", cookieParams.Domain, cookieParams.Secure, true)
	c.SetCookie(idToken, authCookieParams.IdToken, cookieMaxAge, "/", cookieParams.Domain, cookieParams.Secure, true)
}

func DeleteAuthCookies(c *gin.Context, cookieParams CookieParams) {
	c.SetSameSite(http.SameSiteLaxMode)
	c.SetCookie(accessToken, "", -1, "/", cookieParams.Domain, cookieParams.Secure, true)
	c.SetCookie(refreshToken, "", -1, "/", cookieParams.Domain, cookieParams.Secure, true)
	c.SetCookie(accessTokenExpiresAt, "", -1, "/", cookieParams.Domain, cookieParams.Secure, true)
	c.SetCookie(idToken, "", -1, "/", cookieParams.Domain, cookieParams.Secure, true)
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
