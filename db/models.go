// Code generated by sqlc. DO NOT EDIT.
// versions:
//   sqlc v1.26.0

package db

import (
	"database/sql"
)

type AuthenticationToken struct {
	UserID                int64  `json:"userId"`
	AccessToken           string `json:"accessToken"`
	AccessTokenExpiresAt  string `json:"accessTokenExpiresAt"`
	RefreshToken          string `json:"refreshToken"`
	RefreshTokenExpiresAt string `json:"refreshTokenExpiresAt"`
	CreatedAt             string `json:"createdAt"`
}

type OauthProvider struct {
	ID   int64  `json:"id"`
	Name string `json:"name"`
}

type OauthUser struct {
	OauthProviderID int64       `json:"oauthProviderId"`
	UserID          int64       `json:"userId"`
	ExternalUserID  string      `json:"externalUserId"`
	Email           interface{} `json:"email"`
}

type ResetPasswordToken struct {
	UserID    int64          `json:"userId"`
	Token     string         `json:"token"`
	ExpiresAt string         `json:"expiresAt"`
	CreatedAt string         `json:"createdAt"`
	UpdatedAt sql.NullString `json:"updatedAt"`
}

type Role struct {
	ID          int64  `json:"id"`
	Name        string `json:"name"`
	Description string `json:"description"`
}

type User struct {
	ID        int64          `json:"id"`
	Uuid      string         `json:"uuid"`
	Name      string         `json:"name"`
	IsActive  int64          `json:"isActive"`
	ImageID   sql.NullString `json:"imageId"`
	ImageUrl  sql.NullString `json:"imageUrl"`
	CreatedAt string         `json:"createdAt"`
	UpdatedAt sql.NullString `json:"updatedAt"`
	RoleID    int64          `json:"roleId"`
}

type UserCredentials struct {
	UserID          interface{} `json:"userId"`
	Password        string      `json:"password"`
	Email           string      `json:"email"`
	IsEmailVerified int64       `json:"isEmailVerified"`
}

type VerifyEmailToken struct {
	UserID    int64          `json:"userId"`
	Token     string         `json:"token"`
	ExpiredAt string         `json:"expiredAt"`
	CreatedAt string         `json:"createdAt"`
	UpdatedAt sql.NullString `json:"updatedAt"`
}
