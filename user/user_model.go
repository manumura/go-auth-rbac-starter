package user

import (
	"time"

	"github.com/google/uuid"
	oauthprovider "github.com/manumura/go-auth-rbac-starter/oauth_provider"
	"github.com/manumura/go-auth-rbac-starter/role"
)

type UserEntity struct {
	ID                int64             `json:"id"`
	Uuid              uuid.UUID         `json:"uuid"`
	Name              string            `json:"name"`
	IsActive          bool              `json:"isActive"`
	ImageID           string            `json:"imageId"`
	ImageUrl          string            `json:"imageUrl"`
	Role              role.Role         `json:"role"`
	CreatedAt         *time.Time        `json:"createdAt"`
	UpdatedAt         *time.Time        `json:"updatedAt"`
	UserCredentials   UserCredentials   `json:"userCredentials"`
	OauthUserProvider OauthUserProvider `json:"oauthProvider"`
}

type UserCredentials struct {
	Password        string `json:"password"`
	Email           string `json:"email"`
	IsEmailVerified bool   `json:"isEmailVerified"`
}

type OauthUserProvider struct {
	OauthProviderID int64       `json:"oauthProviderId"`
	ExternalUserID  string      `json:"externalUserId"`
	Email           interface{} `json:"email"`
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

type CreateUserRequest struct {
	Name     string    `json:"name" validate:"required,min=6,max=100"`
	Email    string    `json:"email" validate:"required,email"`
	Password string    `json:"password" validate:"required"`
	Role     role.Role `json:"role" validate:"required,alpha"`
}

type CreateOauthUserRequest struct {
	Name           string                      `json:"name" validate:"required,min=6,max=100"`
	Role           role.Role                   `json:"role" validate:"required,alpha"`
	Email          string                      `json:"email" validate:"required,email"`
	OauthProvider  oauthprovider.OauthProvider `json:"oauthProvider" validate:"required,alpha"`
	ExternalUserID string                      `json:"externalUserId" validate:"required"`
}

type RegisterRequest struct {
	Name     string `json:"name" validate:"required,min=6,max=100"`
	Email    string `json:"email" validate:"required,email"`
	Password string `json:"password" validate:"required"`
}
