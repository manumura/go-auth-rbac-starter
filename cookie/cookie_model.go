package cookie

import "time"

type CookieParams struct {
	Domain string
	Secure bool
}

type AuthCookieParams struct {
	AccessToken          string
	RefreshToken         string
	AccessTokenExpiresAt time.Time
	IdToken              string
}
