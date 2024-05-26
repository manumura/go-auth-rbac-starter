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
	"name" varchar(100),
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
