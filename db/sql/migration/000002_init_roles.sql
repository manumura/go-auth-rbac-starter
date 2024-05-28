-- +goose Up
INSERT INTO role(name, description) VALUES
('ADMIN', 'Role Admin'),
('USER', 'Role User');

-- +goose Down
DELETE FROM role WHERE name = 'ADMIN' OR name = 'USER';
