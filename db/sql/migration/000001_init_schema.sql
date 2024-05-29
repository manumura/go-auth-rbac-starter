-- +goose Up
CREATE TABLE role (
	"id" INTEGER PRIMARY KEY AUTOINCREMENT,
	"name" text NOT NULL,
	"description" text NOT NULL
);
CREATE UNIQUE INDEX "IDX_role_name" ON role (name);

CREATE TABLE user (
	"id" INTEGER PRIMARY KEY AUTOINCREMENT,
	"uuid" text NOT NULL,
	"password" text NOT NULL,
	"email" text NOT NULL,
	"name" text NOT NULL,
	"is_active" INTEGER NOT NULL,
	"image_id" text,
	"image_url" text,
	"created_at" text NOT NULL,
	"updated_at" text,
	"role_id" INTEGER NOT NULL,
    CONSTRAINT "FK_user_role_id_role_id" FOREIGN KEY (role_id) REFERENCES role (id) ON DELETE SET NULL ON UPDATE CASCADE
);
CREATE INDEX "AK_user_role_id" ON user (role_id);
CREATE UNIQUE INDEX "IDX_user_email" ON user (email);
CREATE UNIQUE INDEX "IDX_user_uuid" ON user (uuid);

CREATE TABLE authentication_token (
	"user_id" INTEGER PRIMARY KEY,
	"access_token" text NOT NULL,
	"access_token_expires_at" text NOT NULL,
	"refresh_token" text NOT NULL,
	"refresh_token_expires_at" text NOT NULL,
	"created_at" text NOT NULL,
	CONSTRAINT "FK_authentication_token_user_id_user_id" FOREIGN KEY (user_id) REFERENCES user (id) ON DELETE CASCADE ON UPDATE CASCADE
);
CREATE UNIQUE INDEX "IDX_authentication_token_access_token" ON authentication_token (access_token);
CREATE UNIQUE INDEX "IDX_authentication_token_refresh_token" ON authentication_token (refresh_token);
CREATE UNIQUE INDEX "REL_authentication_token_user_id" ON authentication_token (user_id);

CREATE TABLE reset_password_token (
	"user_id" INTEGER PRIMARY KEY,
	"token" text NOT NULL,
	"expires_at" text NOT NULL,
	"created_at" text NOT NULL,
	"updated_at" text,
	CONSTRAINT "FK_reset_password_token_user_id_user_id" FOREIGN KEY (user_id) REFERENCES user (id) ON DELETE CASCADE ON UPDATE CASCADE
);
CREATE UNIQUE INDEX "IDX_reset_password_token_token" ON reset_password_token (token);
CREATE UNIQUE INDEX "REL_reset_password_token_user_id" ON reset_password_token (user_id);

-- +goose Down
DROP TABLE IF EXISTS reset_password_token;
DROP TABLE IF EXISTS authentication_token;
DROP TABLE IF EXISTS user;
DROP TABLE IF EXISTS role;
