-- name: CreateUser :one
INSERT INTO user (
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
VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
RETURNING *;

-- name: GetAllUsers :many
SELECT *
FROM user;

-- name: GetUserByEmail :one
SELECT *
FROM user
WHERE email = ?;

-- name: GetUserByID :one
SELECT *
FROM user
WHERE id = ?;
