// Code generated by sqlc. DO NOT EDIT.
// versions:
//   sqlc v1.26.0

package db

import (
	"database/sql"
)

type AuthenticationToken struct {
	UserID               int64  `json:"userId"`
	AccessToken          string `json:"accessToken"`
	AccessTokenExpireAt  string `json:"accessTokenExpireAt"`
	RefreshToken         string `json:"refreshToken"`
	RefreshTokenExpireAt string `json:"refreshTokenExpireAt"`
	CreatedAt            string `json:"createdAt"`
}

type ResetPasswordToken struct {
	UserID    int64          `json:"userId"`
	Token     string         `json:"token"`
	ExpiredAt string         `json:"expiredAt"`
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
	Password  string         `json:"password"`
	Email     string         `json:"email"`
	Name      string         `json:"name"`
	IsActive  int64          `json:"isActive"`
	ImageID   sql.NullString `json:"imageId"`
	ImageUrl  sql.NullString `json:"imageUrl"`
	CreatedAt string         `json:"createdAt"`
	UpdatedAt sql.NullString `json:"updatedAt"`
	RoleID    int64          `json:"roleId"`
}
