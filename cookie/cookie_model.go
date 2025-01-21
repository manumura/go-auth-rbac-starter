package cookie

import "time"

type AuthCookieParams struct {
	AccessToken          string
	RefreshToken         string
	AccessTokenExpiresAt time.Time
	IdToken              string
}
