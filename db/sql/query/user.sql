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

-- name: DeleteUser :exec
DELETE FROM user 
WHERE uuid = ?;

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
-- SELECT sqlc.embed(user), sqlc.embed(user_credentials)
SELECT user.*, user_credentials.*, oauth_user.*
FROM user 
LEFT JOIN user_credentials ON user.id = user_credentials.user_id
LEFT JOIN oauth_user ON user.id = oauth_user.user_id
WHERE role_id = COALESCE(sqlc.narg(role_id), role_id)
ORDER BY created_at DESC
LIMIT COALESCE(CAST(sqlc.narg(limit) AS int), 10) 
OFFSET COALESCE(CAST(sqlc.narg(offset) AS int), 0);

-- name: CountAllUsers :one
-- SELECT sqlc.embed(user), sqlc.embed(user_credentials)
SELECT COUNT(*)
FROM user 
WHERE role_id = COALESCE(sqlc.narg(role_id), role_id)
ORDER BY created_at DESC;

-- name: GetUserByEmail :one
SELECT sqlc.embed(user), sqlc.embed(user_credentials)
-- SELECT user.*, user_credentials.*
FROM user 
INNER JOIN user_credentials ON user.id = user_credentials.user_id
WHERE user_credentials.email = ?;

-- name: GetUserByID :one
SELECT sqlc.embed(user)
-- SELECT user.*, user_credentials.*
FROM user 
WHERE id = ?;

-- name: GetUserByUUID :one
-- SELECT sqlc.embed(user), sqlc.embed(user_credentials), sqlc.embed(oauth_user)
SELECT user.*, user_credentials.*, oauth_user.*
FROM user 
LEFT JOIN user_credentials ON user.id = user_credentials.user_id
LEFT JOIN oauth_user ON user.id = oauth_user.user_id
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

-- name: GetUserByResetPasswordToken :one
SELECT sqlc.embed(user), sqlc.embed(reset_password_token)
FROM user
INNER JOIN reset_password_token ON user.id = reset_password_token.user_id
WHERE reset_password_token.token = ?;

-- name: UpdateUserCredentials :one
UPDATE user_credentials
SET 
    email = COALESCE(sqlc.narg(email), email),
    password = COALESCE(sqlc.narg(password), password),
    is_email_verified = COALESCE(sqlc.narg(is_email_verified), is_email_verified)
WHERE 
    user_id = sqlc.arg(user_id)
RETURNING *;

-- name: UpdateUser :one
UPDATE user
SET 
    name = COALESCE(sqlc.narg(name), name), 
    image_id = COALESCE(sqlc.narg(image_id), image_id),
    image_url = COALESCE(sqlc.narg(image_url), image_url),
    is_active = COALESCE(sqlc.narg(is_active), is_active),
    role_id = COALESCE(sqlc.narg(role_id), role_id),
    updated_at = sqlc.narg(updated_at)
WHERE 
    uuid = sqlc.arg(uuid)
RETURNING *;
