package authentication

import "time"

// Uses https://github.com/go-playground/validator for validation
type LoginRequest struct {
	Email    string `json:"email" validate:"required,email"`
	Password string `json:"password" validate:"required"`
}

type LoginResponse struct {
	AccessToken          string    `json:"accessToken"`
	RefreshToken         string    `json:"refreshToken"`
	IdToken              string    `json:"idToken"`
	AccessTokenExpiresAt time.Time `json:"accessTokenExpiresAt"`
}
