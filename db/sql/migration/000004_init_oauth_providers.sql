-- +goose Up
INSERT INTO oauth_provider(name)
VALUES
('GOOGLE'),
('FACEBOOK');

-- +goose Down
DELETE FROM oauth_provider WHERE name = 'GOOGLE' OR name = 'FACEBOOK';
