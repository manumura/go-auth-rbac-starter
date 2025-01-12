// Code generated by sqlc. DO NOT EDIT.
// versions:
//   sqlc v1.26.0

package db

import (
	"context"
)

type Querier interface {
	CreateAuthenticationToken(ctx context.Context, arg CreateAuthenticationTokenParams) (AuthenticationToken, error)
	CreateOauthUser(ctx context.Context, arg CreateOauthUserParams) (OauthUser, error)
	CreateResetPasswordToken(ctx context.Context, arg CreateResetPasswordTokenParams) (ResetPasswordToken, error)
	CreateUser(ctx context.Context, arg CreateUserParams) (User, error)
	CreateUserCredentials(ctx context.Context, arg CreateUserCredentialsParams) (UserCredentials, error)
	CreateVerifyEmailToken(ctx context.Context, arg CreateVerifyEmailTokenParams) (VerifyEmailToken, error)
	DeleteAuthenticationToken(ctx context.Context, userID int64) error
	DeleteResetPasswordToken(ctx context.Context, userID int64) error
	DeleteVerifyEmailToken(ctx context.Context, userID int64) error
	// SELECT user.*, user_credentials.*
	GetAllUsers(ctx context.Context) ([]GetAllUsersRow, error)
	GetAuthenticationTokenByAccessToken(ctx context.Context, accessToken string) (AuthenticationToken, error)
	GetAuthenticationTokenByRefreshToken(ctx context.Context, refreshToken string) (AuthenticationToken, error)
	GetOauthProviders(ctx context.Context) ([]OauthProvider, error)
	GetRoles(ctx context.Context) ([]Role, error)
	// SELECT user.*, user_credentials.*
	GetUserByEmail(ctx context.Context, email string) (GetUserByEmailRow, error)
	// SELECT user.*, user_credentials.*
	GetUserByID(ctx context.Context, id int64) (GetUserByIDRow, error)
	GetUserByOauthProvider(ctx context.Context, arg GetUserByOauthProviderParams) (GetUserByOauthProviderRow, error)
	GetUserByResetPasswordToken(ctx context.Context, token string) (GetUserByResetPasswordTokenRow, error)
	// SELECT user.*, user_credentials.*
	GetUserByUUID(ctx context.Context, uuid string) (GetUserByUUIDRow, error)
	GetUserByVerifyEmailToken(ctx context.Context, token string) (GetUserByVerifyEmailTokenRow, error)
	GetVerifyEmailTokenByToken(ctx context.Context, token string) (VerifyEmailToken, error)
	UpdateUser(ctx context.Context, arg UpdateUserParams) (User, error)
	UpdateUserIsEmailVerified(ctx context.Context, arg UpdateUserIsEmailVerifiedParams) error
	UpdateUserPassword(ctx context.Context, arg UpdateUserPasswordParams) error
}

var _ Querier = (*Queries)(nil)
