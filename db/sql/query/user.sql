-- name: CreateUser :one
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
RETURNING *;

-- name: CreateUserCredentials :one
INSERT INTO user_credentials (
        user_id,
        password,
        email,
        is_email_verified
    )
VALUES (?, ?, ?, ?)
RETURNING *;

-- name: CreateOauthUser :one
INSERT INTO oauth_user (
        oauth_provider_id,
        user_id,
        external_user_id,
        email
    )
VALUES (?, ?, ?, ?)
RETURNING *;

-- name: GetAllUsers :many
SELECT sqlc.embed(user), sqlc.embed(user_credentials)
-- SELECT user.*, user_credentials.*
FROM user 
INNER JOIN user_credentials ON user.id = user_credentials.user_id;

-- name: GetUserByEmail :one
SELECT sqlc.embed(user), sqlc.embed(user_credentials)
-- SELECT user.*, user_credentials.*
FROM user 
INNER JOIN user_credentials ON user.id = user_credentials.user_id
WHERE user_credentials.email = ?;

-- name: GetUserByID :one
SELECT sqlc.embed(user), sqlc.embed(user_credentials)
-- SELECT user.*, user_credentials.*
FROM user 
INNER JOIN user_credentials ON user.id = user_credentials.user_id
WHERE id = ?;

-- name: GetUserByUUID :one
SELECT user.*
FROM user
WHERE uuid = ?;

-- name: GetUserByOauthProvider :one
SELECT sqlc.embed(user), sqlc.embed(oauth_user)
FROM user 
INNER JOIN oauth_user ON user.id = oauth_user.user_id
WHERE oauth_user.external_user_id = ? AND oauth_user.oauth_provider_id = ?;

-- name: GetUserByVerifyEmailToken :one
SELECT sqlc.embed(user), sqlc.embed(verify_email_token)
FROM user
INNER JOIN verify_email_token ON user.id = verify_email_token.user_id
WHERE verify_email_token.token = ?;

-- name: UpdateUserIsEmailVerified :exec
UPDATE user_credentials
SET is_email_verified = ?
WHERE user_id = ?;
