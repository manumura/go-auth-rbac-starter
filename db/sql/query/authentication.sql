-- name: CreateAuthenticationToken :one
INSERT INTO authentication_token (
        user_id,
        access_token,
        access_token_expires_at,
        refresh_token,
        refresh_token_expires_at,
        created_at
    )
VALUES (?, ?, ?, ?, ?, ?)
RETURNING *;

-- name: DeleteAuthenticationToken :exec
DELETE FROM authentication_token
WHERE user_id = ?;

-- name: GetAuthenticationTokenByAccessToken :one
SELECT * FROM authentication_token
WHERE access_token = ?;

-- name: GetAuthenticationTokenByRefreshToken :one
SELECT * FROM authentication_token
WHERE refresh_token = ?;
