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
FROM user INNER JOIN user_credentials ON user.id = user_credentials.user_id;

-- name: GetUserByEmail :one
SELECT sqlc.embed(user), sqlc.embed(user_credentials)
-- SELECT user.*, user_credentials.*
FROM user INNER JOIN user_credentials ON user.id = user_credentials.user_id
WHERE user_credentials.email = ?;

-- name: GetUserByID :one
SELECT sqlc.embed(user), sqlc.embed(user_credentials)
-- SELECT user.*, user_credentials.*
FROM user INNER JOIN user_credentials ON user.id = user_credentials.user_id
WHERE id = ?;
