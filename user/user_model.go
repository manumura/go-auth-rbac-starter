package user

import (
	"time"

	"github.com/google/uuid"
	oauthprovider "github.com/manumura/go-auth-rbac-starter/oauth_provider"
	"github.com/manumura/go-auth-rbac-starter/role"
)

type UserEntity struct {
	ID                 int64                    `json:"id"`
	Uuid               uuid.UUID                `json:"uuid"`
	Name               string                   `json:"name"`
	IsActive           bool                     `json:"isActive"`
	ImageID            string                   `json:"imageId"`
	ImageUrl           string                   `json:"imageUrl"`
	Role               role.Role                `json:"role"`
	CreatedAt          *time.Time               `json:"createdAt"`
	UpdatedAt          *time.Time               `json:"updatedAt"`
	UserCredentials    UserCredentialsEntity    `json:"userCredentials"`
	OauthUserProvider  OauthUserProviderEntity  `json:"oauthProvider"`
	VerifyEmailToken   VerifyEmailTokenEntity   `json:"verifyEmailToken"`
	ResetPasswordToken ResetPasswordTokenEntity `json:"resetPasswordToken"`
}

type UserCredentialsEntity struct {
	Password        string `json:"password"`
	Email           string `json:"email"`
	IsEmailVerified bool   `json:"isEmailVerified"`
}

type OauthUserProviderEntity struct {
	ExternalUserID  string `json:"externalUserId"`
	OauthProviderID int64  `json:"oauthProviderId"`
	Email           string `json:"email"`
}

type VerifyEmailTokenEntity struct {
	Token     string `json:"token"`
	ExpiresAt string `json:"expiresAt"`
}

type ResetPasswordTokenEntity struct {
	Token     string `json:"token"`
	ExpiresAt string `json:"expiresAt"`
}

type AuthenticatedUser struct {
	Uuid      uuid.UUID  `json:"uuid"`
	Name      string     `json:"name"`
	IsActive  bool       `json:"isActive"`
	ImageID   string     `json:"imageId"`
	ImageUrl  string     `json:"imageUrl"`
	Role      role.Role  `json:"role"`
	CreatedAt *time.Time `json:"createdAt"`
	UpdatedAt *time.Time `json:"updatedAt"`
}

type User struct {
	Uuid      uuid.UUID            `json:"uuid"`
	Name      string               `json:"name"`
	IsActive  bool                 `json:"isActive"`
	ImageID   string               `json:"imageId"`
	ImageUrl  string               `json:"imageUrl"`
	Role      role.Role            `json:"role"`
	CreatedAt *time.Time           `json:"createdAt"`
	UpdatedAt *time.Time           `json:"updatedAt"`
	Email     *string              `json:"email,omitempty"`
	Providers *[]OauthUserProvider `json:"providers,omitempty"`
}

type OauthUserProvider struct {
	ExternalUserID string      `json:"externalUserId"`
	OauthProvider  string      `json:"provider"`
	Email          interface{} `json:"email"`
}

type RegisterRequest struct {
	Name     string `json:"name" validate:"required,min=6,max=100"`
	Email    string `json:"email" validate:"required,email"`
	Password string `json:"password" validate:"required"`
}

type CreateUserRequest struct {
	Name  string    `json:"name" validate:"required,min=6,max=100"`
	Email string    `json:"email" validate:"required,email"`
	Role  role.Role `json:"role" validate:"required,alpha"`
}

type CreateUserParams struct {
	Name            string    `json:"name" validate:"required,min=6,max=100"`
	Email           string    `json:"email" validate:"required,email"`
	Password        string    `json:"password" validate:"required"`
	Role            role.Role `json:"role" validate:"required,alpha"`
	IsEmailVerified bool      `json:"isEmailVerified" validate:"required"`
}

type CreateOauthUserParams struct {
	Name           string                      `json:"name" validate:"required,min=6,max=100"`
	Role           role.Role                   `json:"role" validate:"required,alpha"`
	Email          string                      `json:"email" validate:"required,email"`
	OauthProvider  oauthprovider.OauthProvider `json:"oauthProvider" validate:"required,alpha"`
	ExternalUserID string                      `json:"externalUserId" validate:"required"`
}
