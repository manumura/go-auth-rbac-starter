-- +goose Up
-- pwd = 12345678
INSERT INTO user
("uuid", "password", "email", "name", "is_active", "created_at", "updated_at", "role_id")
VALUES(lower(hex( randomblob(4)) || '-' || hex( randomblob(2))
        || '-' || '4' || substr( hex( randomblob(2)), 2) || '-'
        || substr('AB89', 1 + (abs(random()) % 4) , 1)  ||
        substr(hex(randomblob(2)), 2) || '-' || hex(randomblob(6))),
'$2b$12$hr2oZlCgSzak1g6fx3OqJOcuVW4dcHYNO0Z6frMexrQGmaFEi9/06', 'admin@email.com', 'admin', 1, datetime(), datetime(), 1);

-- +goose Down
DELETE FROM user WHERE email = 'admin@email.com';
