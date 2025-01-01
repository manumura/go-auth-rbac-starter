-- name: CreateResetPasswordToken :one
INSERT INTO reset_password_token (
        user_id,
        token,
        expires_at,
        created_at,
        updated_at
    )
VALUES (?, ?, ?, ?, ?)
RETURNING *;

-- name: DeleteResetPasswordToken :exec
DELETE FROM reset_password_token
WHERE user_id = ?;
