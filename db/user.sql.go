// Code generated by sqlc. DO NOT EDIT.
// versions:
//   sqlc v1.26.0
// source: user.sql

package db

import (
	"context"
	"database/sql"
)

const createOauthUser = `-- name: CreateOauthUser :one
INSERT INTO oauth_user (
        oauth_provider_id,
        user_id,
        external_user_id,
        email
    )
VALUES (?, ?, ?, ?)
RETURNING oauth_provider_id, user_id, external_user_id, email
`

type CreateOauthUserParams struct {
	OauthProviderID int64       `json:"oauthProviderId"`
	UserID          int64       `json:"userId"`
	ExternalUserID  string      `json:"externalUserId"`
	Email           interface{} `json:"email"`
}

func (q *Queries) CreateOauthUser(ctx context.Context, arg CreateOauthUserParams) (OauthUser, error) {
	row := q.db.QueryRowContext(ctx, createOauthUser,
		arg.OauthProviderID,
		arg.UserID,
		arg.ExternalUserID,
		arg.Email,
	)
	var i OauthUser
	err := row.Scan(
		&i.OauthProviderID,
		&i.UserID,
		&i.ExternalUserID,
		&i.Email,
	)
	return i, err
}

const createUser = `-- name: CreateUser :one
INSERT INTO user (
        uuid,
        name,
        is_active,
        image_id,
        image_url,
        created_at,
        updated_at,
        role_id
    )
VALUES (?, ?, ?, ?, ?, ?, ?, ?)
RETURNING id, uuid, name, is_active, image_id, image_url, created_at, updated_at, role_id
`

type CreateUserParams struct {
	Uuid      string         `json:"uuid"`
	Name      string         `json:"name"`
	IsActive  int64          `json:"isActive"`
	ImageID   sql.NullString `json:"imageId"`
	ImageUrl  sql.NullString `json:"imageUrl"`
	CreatedAt string         `json:"createdAt"`
	UpdatedAt sql.NullString `json:"updatedAt"`
	RoleID    int64          `json:"roleId"`
}

func (q *Queries) CreateUser(ctx context.Context, arg CreateUserParams) (User, error) {
	row := q.db.QueryRowContext(ctx, createUser,
		arg.Uuid,
		arg.Name,
		arg.IsActive,
		arg.ImageID,
		arg.ImageUrl,
		arg.CreatedAt,
		arg.UpdatedAt,
		arg.RoleID,
	)
	var i User
	err := row.Scan(
		&i.ID,
		&i.Uuid,
		&i.Name,
		&i.IsActive,
		&i.ImageID,
		&i.ImageUrl,
		&i.CreatedAt,
		&i.UpdatedAt,
		&i.RoleID,
	)
	return i, err
}

const createUserCredentials = `-- name: CreateUserCredentials :one
INSERT INTO user_credentials (
        user_id,
        password,
        email,
        is_email_verified
    )
VALUES (?, ?, ?, ?)
RETURNING user_id, password, email, is_email_verified
`

type CreateUserCredentialsParams struct {
	UserID          interface{} `json:"userId"`
	Password        string      `json:"password"`
	Email           string      `json:"email"`
	IsEmailVerified int64       `json:"isEmailVerified"`
}

func (q *Queries) CreateUserCredentials(ctx context.Context, arg CreateUserCredentialsParams) (UserCredentials, error) {
	row := q.db.QueryRowContext(ctx, createUserCredentials,
		arg.UserID,
		arg.Password,
		arg.Email,
		arg.IsEmailVerified,
	)
	var i UserCredentials
	err := row.Scan(
		&i.UserID,
		&i.Password,
		&i.Email,
		&i.IsEmailVerified,
	)
	return i, err
}

const deleteUser = `-- name: DeleteUser :exec
DELETE FROM user 
WHERE uuid = ?
`

func (q *Queries) DeleteUser(ctx context.Context, uuid string) error {
	_, err := q.db.ExecContext(ctx, deleteUser, uuid)
	return err
}

const getAllUsers = `-- name: GetAllUsers :many
SELECT user.id, user.uuid, user.name, user.is_active, user.image_id, user.image_url, user.created_at, user.updated_at, user.role_id, user_credentials.user_id, user_credentials.password, user_credentials.email, user_credentials.is_email_verified
FROM user 
INNER JOIN user_credentials ON user.id = user_credentials.user_id
`

type GetAllUsersRow struct {
	User            User            `json:"user"`
	UserCredentials UserCredentials `json:"userCredentials"`
}

// SELECT user.*, user_credentials.*
func (q *Queries) GetAllUsers(ctx context.Context) ([]GetAllUsersRow, error) {
	rows, err := q.db.QueryContext(ctx, getAllUsers)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	items := []GetAllUsersRow{}
	for rows.Next() {
		var i GetAllUsersRow
		if err := rows.Scan(
			&i.User.ID,
			&i.User.Uuid,
			&i.User.Name,
			&i.User.IsActive,
			&i.User.ImageID,
			&i.User.ImageUrl,
			&i.User.CreatedAt,
			&i.User.UpdatedAt,
			&i.User.RoleID,
			&i.UserCredentials.UserID,
			&i.UserCredentials.Password,
			&i.UserCredentials.Email,
			&i.UserCredentials.IsEmailVerified,
		); err != nil {
			return nil, err
		}
		items = append(items, i)
	}
	if err := rows.Close(); err != nil {
		return nil, err
	}
	if err := rows.Err(); err != nil {
		return nil, err
	}
	return items, nil
}

const getUserByEmail = `-- name: GetUserByEmail :one
SELECT user.id, user.uuid, user.name, user.is_active, user.image_id, user.image_url, user.created_at, user.updated_at, user.role_id, user_credentials.user_id, user_credentials.password, user_credentials.email, user_credentials.is_email_verified
FROM user 
INNER JOIN user_credentials ON user.id = user_credentials.user_id
WHERE user_credentials.email = ?
`

type GetUserByEmailRow struct {
	User            User            `json:"user"`
	UserCredentials UserCredentials `json:"userCredentials"`
}

// SELECT user.*, user_credentials.*
func (q *Queries) GetUserByEmail(ctx context.Context, email string) (GetUserByEmailRow, error) {
	row := q.db.QueryRowContext(ctx, getUserByEmail, email)
	var i GetUserByEmailRow
	err := row.Scan(
		&i.User.ID,
		&i.User.Uuid,
		&i.User.Name,
		&i.User.IsActive,
		&i.User.ImageID,
		&i.User.ImageUrl,
		&i.User.CreatedAt,
		&i.User.UpdatedAt,
		&i.User.RoleID,
		&i.UserCredentials.UserID,
		&i.UserCredentials.Password,
		&i.UserCredentials.Email,
		&i.UserCredentials.IsEmailVerified,
	)
	return i, err
}

const getUserByID = `-- name: GetUserByID :one
SELECT user.id, user.uuid, user.name, user.is_active, user.image_id, user.image_url, user.created_at, user.updated_at, user.role_id
FROM user 
WHERE id = ?
`

type GetUserByIDRow struct {
	User User `json:"user"`
}

// SELECT user.*, user_credentials.*
func (q *Queries) GetUserByID(ctx context.Context, id int64) (GetUserByIDRow, error) {
	row := q.db.QueryRowContext(ctx, getUserByID, id)
	var i GetUserByIDRow
	err := row.Scan(
		&i.User.ID,
		&i.User.Uuid,
		&i.User.Name,
		&i.User.IsActive,
		&i.User.ImageID,
		&i.User.ImageUrl,
		&i.User.CreatedAt,
		&i.User.UpdatedAt,
		&i.User.RoleID,
	)
	return i, err
}

const getUserByOauthProvider = `-- name: GetUserByOauthProvider :one
SELECT user.id, user.uuid, user.name, user.is_active, user.image_id, user.image_url, user.created_at, user.updated_at, user.role_id, oauth_user.oauth_provider_id, oauth_user.user_id, oauth_user.external_user_id, oauth_user.email
FROM user 
INNER JOIN oauth_user ON user.id = oauth_user.user_id
WHERE oauth_user.external_user_id = ? AND oauth_user.oauth_provider_id = ?
`

type GetUserByOauthProviderParams struct {
	ExternalUserID  string `json:"externalUserId"`
	OauthProviderID int64  `json:"oauthProviderId"`
}

type GetUserByOauthProviderRow struct {
	User      User      `json:"user"`
	OauthUser OauthUser `json:"oauthUser"`
}

func (q *Queries) GetUserByOauthProvider(ctx context.Context, arg GetUserByOauthProviderParams) (GetUserByOauthProviderRow, error) {
	row := q.db.QueryRowContext(ctx, getUserByOauthProvider, arg.ExternalUserID, arg.OauthProviderID)
	var i GetUserByOauthProviderRow
	err := row.Scan(
		&i.User.ID,
		&i.User.Uuid,
		&i.User.Name,
		&i.User.IsActive,
		&i.User.ImageID,
		&i.User.ImageUrl,
		&i.User.CreatedAt,
		&i.User.UpdatedAt,
		&i.User.RoleID,
		&i.OauthUser.OauthProviderID,
		&i.OauthUser.UserID,
		&i.OauthUser.ExternalUserID,
		&i.OauthUser.Email,
	)
	return i, err
}

const getUserByResetPasswordToken = `-- name: GetUserByResetPasswordToken :one
SELECT user.id, user.uuid, user.name, user.is_active, user.image_id, user.image_url, user.created_at, user.updated_at, user.role_id, reset_password_token.user_id, reset_password_token.token, reset_password_token.expires_at, reset_password_token.created_at, reset_password_token.updated_at
FROM user
INNER JOIN reset_password_token ON user.id = reset_password_token.user_id
WHERE reset_password_token.token = ?
`

type GetUserByResetPasswordTokenRow struct {
	User               User               `json:"user"`
	ResetPasswordToken ResetPasswordToken `json:"resetPasswordToken"`
}

func (q *Queries) GetUserByResetPasswordToken(ctx context.Context, token string) (GetUserByResetPasswordTokenRow, error) {
	row := q.db.QueryRowContext(ctx, getUserByResetPasswordToken, token)
	var i GetUserByResetPasswordTokenRow
	err := row.Scan(
		&i.User.ID,
		&i.User.Uuid,
		&i.User.Name,
		&i.User.IsActive,
		&i.User.ImageID,
		&i.User.ImageUrl,
		&i.User.CreatedAt,
		&i.User.UpdatedAt,
		&i.User.RoleID,
		&i.ResetPasswordToken.UserID,
		&i.ResetPasswordToken.Token,
		&i.ResetPasswordToken.ExpiresAt,
		&i.ResetPasswordToken.CreatedAt,
		&i.ResetPasswordToken.UpdatedAt,
	)
	return i, err
}

const getUserByUUID = `-- name: GetUserByUUID :one
SELECT user.id, user.uuid, user.name, user.is_active, user.image_id, user.image_url, user.created_at, user.updated_at, user.role_id, user_credentials.user_id, user_credentials.password, user_credentials.email, user_credentials.is_email_verified, oauth_user.oauth_provider_id, oauth_user.user_id, oauth_user.external_user_id, oauth_user.email
FROM user 
LEFT JOIN user_credentials ON user.id = user_credentials.user_id
LEFT JOIN oauth_user ON user.id = oauth_user.user_id
WHERE uuid = ?
`

type GetUserByUUIDRow struct {
	ID              int64          `json:"id"`
	Uuid            string         `json:"uuid"`
	Name            string         `json:"name"`
	IsActive        int64          `json:"isActive"`
	ImageID         sql.NullString `json:"imageId"`
	ImageUrl        sql.NullString `json:"imageUrl"`
	CreatedAt       string         `json:"createdAt"`
	UpdatedAt       sql.NullString `json:"updatedAt"`
	RoleID          int64          `json:"roleId"`
	UserID          sql.NullInt64  `json:"userId"`
	Password        sql.NullString `json:"password"`
	Email           sql.NullString `json:"email"`
	IsEmailVerified sql.NullInt64  `json:"isEmailVerified"`
	OauthProviderID sql.NullInt64  `json:"oauthProviderId"`
	UserID_2        sql.NullInt64  `json:"userId2"`
	ExternalUserID  sql.NullString `json:"externalUserId"`
	Email_2         interface{}    `json:"email2"`
}

// SELECT sqlc.embed(user), sqlc.embed(user_credentials), sqlc.embed(oauth_user)
func (q *Queries) GetUserByUUID(ctx context.Context, uuid string) (GetUserByUUIDRow, error) {
	row := q.db.QueryRowContext(ctx, getUserByUUID, uuid)
	var i GetUserByUUIDRow
	err := row.Scan(
		&i.ID,
		&i.Uuid,
		&i.Name,
		&i.IsActive,
		&i.ImageID,
		&i.ImageUrl,
		&i.CreatedAt,
		&i.UpdatedAt,
		&i.RoleID,
		&i.UserID,
		&i.Password,
		&i.Email,
		&i.IsEmailVerified,
		&i.OauthProviderID,
		&i.UserID_2,
		&i.ExternalUserID,
		&i.Email_2,
	)
	return i, err
}

const getUserByVerifyEmailToken = `-- name: GetUserByVerifyEmailToken :one
SELECT user.id, user.uuid, user.name, user.is_active, user.image_id, user.image_url, user.created_at, user.updated_at, user.role_id, verify_email_token.user_id, verify_email_token.token, verify_email_token.expires_at, verify_email_token.created_at, verify_email_token.updated_at
FROM user
INNER JOIN verify_email_token ON user.id = verify_email_token.user_id
WHERE verify_email_token.token = ?
`

type GetUserByVerifyEmailTokenRow struct {
	User             User             `json:"user"`
	VerifyEmailToken VerifyEmailToken `json:"verifyEmailToken"`
}

func (q *Queries) GetUserByVerifyEmailToken(ctx context.Context, token string) (GetUserByVerifyEmailTokenRow, error) {
	row := q.db.QueryRowContext(ctx, getUserByVerifyEmailToken, token)
	var i GetUserByVerifyEmailTokenRow
	err := row.Scan(
		&i.User.ID,
		&i.User.Uuid,
		&i.User.Name,
		&i.User.IsActive,
		&i.User.ImageID,
		&i.User.ImageUrl,
		&i.User.CreatedAt,
		&i.User.UpdatedAt,
		&i.User.RoleID,
		&i.VerifyEmailToken.UserID,
		&i.VerifyEmailToken.Token,
		&i.VerifyEmailToken.ExpiresAt,
		&i.VerifyEmailToken.CreatedAt,
		&i.VerifyEmailToken.UpdatedAt,
	)
	return i, err
}

const updateUser = `-- name: UpdateUser :one
UPDATE user
SET 
    name = COALESCE(?1, name), 
    image_id = COALESCE(?2, image_id),
    image_url = COALESCE(?3, image_url),
    is_active = COALESCE(?4, is_active),
    updated_at = ?5
WHERE 
    uuid = ?6
RETURNING id, uuid, name, is_active, image_id, image_url, created_at, updated_at, role_id
`

type UpdateUserParams struct {
	Name      sql.NullString `json:"name"`
	ImageID   sql.NullString `json:"imageId"`
	ImageUrl  sql.NullString `json:"imageUrl"`
	IsActive  sql.NullInt64  `json:"isActive"`
	UpdatedAt sql.NullString `json:"updatedAt"`
	Uuid      string         `json:"uuid"`
}

func (q *Queries) UpdateUser(ctx context.Context, arg UpdateUserParams) (User, error) {
	row := q.db.QueryRowContext(ctx, updateUser,
		arg.Name,
		arg.ImageID,
		arg.ImageUrl,
		arg.IsActive,
		arg.UpdatedAt,
		arg.Uuid,
	)
	var i User
	err := row.Scan(
		&i.ID,
		&i.Uuid,
		&i.Name,
		&i.IsActive,
		&i.ImageID,
		&i.ImageUrl,
		&i.CreatedAt,
		&i.UpdatedAt,
		&i.RoleID,
	)
	return i, err
}

const updateUserIsEmailVerified = `-- name: UpdateUserIsEmailVerified :exec
UPDATE user_credentials
SET is_email_verified = ?
WHERE user_id = ?
`

type UpdateUserIsEmailVerifiedParams struct {
	IsEmailVerified int64       `json:"isEmailVerified"`
	UserID          interface{} `json:"userId"`
}

func (q *Queries) UpdateUserIsEmailVerified(ctx context.Context, arg UpdateUserIsEmailVerifiedParams) error {
	_, err := q.db.ExecContext(ctx, updateUserIsEmailVerified, arg.IsEmailVerified, arg.UserID)
	return err
}

const updateUserPassword = `-- name: UpdateUserPassword :exec
UPDATE user_credentials
SET password = ?
WHERE user_id = ?
`

type UpdateUserPasswordParams struct {
	Password string      `json:"password"`
	UserID   interface{} `json:"userId"`
}

func (q *Queries) UpdateUserPassword(ctx context.Context, arg UpdateUserPasswordParams) error {
	_, err := q.db.ExecContext(ctx, updateUserPassword, arg.Password, arg.UserID)
	return err
}
