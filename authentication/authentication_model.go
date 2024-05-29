package authentication

import "time"

// Uses https://github.com/go-playground/validator for validation
type LoginRequest struct {
	Email    string `json:"email" validate:"required,email"`
	Password string `json:"password" validate:"required"`
}

type AuthenticationRequest struct {
	UserID                int64     `json:"userId"`
	AccessToken           string    `json:"accessToken"`
	RefreshToken          string    `json:"refreshToken"`
	AccessTokenExpiresAt  time.Time `json:"accessTokenExpiresAt"`
	RefreshTokenExpiresAt time.Time `json:"refreshTokenExpiresAt"`
}

type AuthenticationResponse struct {
	AccessToken          string    `json:"accessToken"`
	RefreshToken         string    `json:"refreshToken"`
	IdToken              string    `json:"idToken"`
	AccessTokenExpiresAt time.Time `json:"accessTokenExpiresAt"`
}
