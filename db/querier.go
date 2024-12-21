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
	CreateUser(ctx context.Context, arg CreateUserParams) (User, error)
	CreateUserCredentials(ctx context.Context, arg CreateUserCredentialsParams) (UserCredentials, error)
	CreateVerifyEmailToken(ctx context.Context, arg CreateVerifyEmailTokenParams) (VerifyEmailToken, error)
	DeleteAuthenticationToken(ctx context.Context, userID int64) error
	DeleteVerifyEmailToken(ctx context.Context, userID int64) error
	// SELECT user.*, user_credentials.*
	GetAllUsers(ctx context.Context) ([]GetAllUsersRow, error)
	GetAuthenticationTokenByAccessToken(ctx context.Context, accessToken string) (AuthenticationToken, error)
	GetOauthProviders(ctx context.Context) ([]OauthProvider, error)
	GetRoles(ctx context.Context) ([]Role, error)
	// SELECT user.*, user_credentials.*
	GetUserByEmail(ctx context.Context, email string) (GetUserByEmailRow, error)
	// SELECT user.*, user_credentials.*
	GetUserByID(ctx context.Context, id int64) (GetUserByIDRow, error)
	GetUserByOauthProvider(ctx context.Context, arg GetUserByOauthProviderParams) (GetUserByOauthProviderRow, error)
	GetUserByVerifyEmailToken(ctx context.Context, token string) (GetUserByVerifyEmailTokenRow, error)
	GetVerifyEmailTokenByToken(ctx context.Context, token string) (VerifyEmailToken, error)
	UpdateUserIsEmailVerified(ctx context.Context, arg UpdateUserIsEmailVerifiedParams) error
}

var _ Querier = (*Queries)(nil)
