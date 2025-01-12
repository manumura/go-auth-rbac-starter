-- name: CreateVerifyEmailToken :one
INSERT INTO verify_email_token (
        user_id,
        token,
        expires_at,
        created_at,
        updated_at
    )
VALUES (?, ?, ?, ?, ?)
RETURNING *;

-- name: DeleteVerifyEmailToken :exec
DELETE FROM verify_email_token
WHERE user_id = ?;

-- name: GetVerifyEmailTokenByToken :one
SELECT * FROM verify_email_token
WHERE token = ?;
