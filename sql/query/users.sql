-- name: CreateUser :one
INSERT INTO user (
        id,
        uuid,
        password,
        email,
        name,
        is_active,
        image_id,
        image_url,
        created_at,
        updated_at,
        role_id
    )
VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
RETURNING *;

-- name: GetUserByEmail :one
SELECT *
FROM user
WHERE email = ?;