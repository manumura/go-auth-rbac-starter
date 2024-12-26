-- +goose Up
CREATE TABLE oauth_provider (
	"id" INTEGER PRIMARY KEY AUTOINCREMENT,
	"name" text NOT NULL
);
CREATE UNIQUE INDEX "IDX_oauth_provider_name" ON oauth_provider (name);

CREATE TABLE role (
	"id" INTEGER PRIMARY KEY AUTOINCREMENT,
	"name" text NOT NULL,
	"description" text NOT NULL
);
CREATE UNIQUE INDEX "IDX_role_name" ON role (name);

CREATE TABLE user (
	"id" INTEGER PRIMARY KEY AUTOINCREMENT,
	"uuid" text NOT NULL,
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
CREATE UNIQUE INDEX "IDX_user_uuid" ON user (uuid);

CREATE TABLE user_credentials (
	"user_id" int4 INTEGER PRIMARY KEY,
	"password" varchar(255) NOT NULL,
	"email" varchar(255) NOT NULL,
	"is_email_verified" INTEGER DEFAULT 0 NOT NULL,
	CONSTRAINT "FK_user_credentials_user_id_user_id" FOREIGN KEY (user_id) REFERENCES "user" (id) ON DELETE CASCADE ON UPDATE CASCADE
);
CREATE UNIQUE INDEX "IDX_user_email" ON user_credentials (email);
CREATE UNIQUE INDEX "REL_user_credentials_user_id" ON user_credentials (user_id);

CREATE TABLE verify_email_token (
	"user_id" INTEGER PRIMARY KEY,
	"token" varchar(50) NOT NULL,
	"expires_at" text NOT NULL,
	"created_at" text NOT NULL,
	"updated_at" text,
	CONSTRAINT "FK_verify_email_token_user_id_user_id" FOREIGN KEY (user_id) REFERENCES "user" (id) ON DELETE CASCADE ON UPDATE CASCADE
);
CREATE UNIQUE INDEX "IDX_verify_email_token_token" ON verify_email_token (token);
CREATE UNIQUE INDEX "REL_verify_email_token_user_id" ON verify_email_token (user_id);

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

CREATE TABLE oauth_user (
	"oauth_provider_id" INTEGER NOT NULL,
	"user_id" INTEGER NOT NULL,
	"external_user_id" text NOT NULL,
	"email" text NULL,
	CONSTRAINT oauth_user_pkey PRIMARY KEY (oauth_provider_id, user_id),
	CONSTRAINT oauth_user_oauth_provider_id_fkey FOREIGN KEY (oauth_provider_id) REFERENCES oauth_provider(id) ON DELETE CASCADE ON UPDATE CASCADE,
	CONSTRAINT oauth_user_user_id_fkey FOREIGN KEY (user_id) REFERENCES "user"(id) ON DELETE CASCADE ON UPDATE CASCADE
);
CREATE UNIQUE INDEX oauth_user_email_oauth_provider_id_key ON oauth_user (email, oauth_provider_id);
CREATE UNIQUE INDEX oauth_user_external_user_id_oauth_provider_id_key ON oauth_user (external_user_id, oauth_provider_id);

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
DROP TABLE IF EXISTS verify_email_token;
DROP TABLE IF EXISTS oauth_user;
DROP TABLE IF EXISTS user_credentials;
DROP TABLE IF EXISTS user;
DROP TABLE IF EXISTS role;
DROP TABLE IF EXISTS oauth_provider;
