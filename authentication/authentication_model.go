package authentication

import "time"

// Uses https://github.com/go-playground/validator for validation
type LoginRequest struct {
	Email    string `json:"email" validate:"required,email"`
	Password string `json:"password" validate:"required"`
}

type Oauth2FacebookLoginRequest struct {
	ID    string `json:"id" validate:"required"`
	Email string `json:"email" validate:"required,email"`
	Name  string `json:"name" validate:"required"`
	// Picture string `json:"picture"`
}

type Oauth2GoogleLoginRequest struct {
	Token string `json:"token" validate:"required"`
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

type VerifyEmailRequest struct {
	Token string `json:"token" validate:"required"`
}
