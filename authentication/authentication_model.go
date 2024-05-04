package authentication

import "time"

type LoginRequest struct {
	Email    string `json:"email"`
	Password string `json:"password"`
}

type LoginResponse struct {
	AccessToken          string    `json:"accessToken"`
	RefreshToken         string    `json:"refreshToken"`
	IdToken              string    `json:"idToken"`
	AccessTokenExpiresAt time.Time `json:"accessTokenExpiresAt"`
}
