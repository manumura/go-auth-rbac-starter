package user

import (
	"fmt"
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

type CreateUserRequest struct {
	Name  string    `json:"name" validate:"required,min=5,max=100"`
	Email string    `json:"email" validate:"required,email"`
	Role  role.Role `json:"role" validate:"required,alpha"`
}

type CreateUserParams struct {
	Name            string    `json:"name" validate:"required,min=5,max=100"`
	Email           string    `json:"email" validate:"required,email"`
	Password        string    `json:"password" validate:"required"`
	Role            role.Role `json:"role" validate:"required,alpha"`
	IsEmailVerified bool      `json:"isEmailVerified" validate:"required"`
}

type CreateOauthUserParams struct {
	Name           string                      `json:"name" validate:"required,min=5,max=100"`
	Role           role.Role                   `json:"role" validate:"required,alpha"`
	Email          string                      `json:"email" validate:"required,email"`
	OauthProvider  oauthprovider.OauthProvider `json:"oauthProvider" validate:"required,alpha"`
	ExternalUserID string                      `json:"externalUserId" validate:"required"`
}

type UpdateUserRequest struct {
	Name     *string    `json:"name" validate:"omitempty,min=5,max=100"`
	Email    *string    `json:"email" validate:"omitempty,email"`
	Password *string    `json:"password"`
	Role     *role.Role `json:"role" validate:"omitempty,alpha"`
	IsActive *bool      `json:"active"`
}

type UpdateUserParams struct {
	Name     *string    `json:"name" validate:"omitempty,min=5,max=100"`
	Email    *string    `json:"email" validate:"omitempty,email"`
	Password *string    `json:"password"`
	Role     *role.Role `json:"role" validate:"omitempty,alpha"`
	IsActive *bool      `json:"active"`
}

type GetUsersRequest struct {
	Role     role.Role `json:"role" validate:"omitempty,alpha"`
	Page     int       `json:"page" validate:"omitempty,number"`
	PageSize int       `json:"pageSize" validate:"omitempty,number"`
}

type GetUsersParams struct {
	Role   *role.Role `json:"role" validate:"omitempty,alpha"`
	Limit  int        `json:"limit" validate:"omitempty,number"`
	Offset int        `json:"offset" validate:"omitempty,number"`
}

type CountUsersParams struct {
	Role *role.Role `json:"role" validate:"omitempty,alpha"`
}

type UserChangeEvent struct {
	ID    string              `json:"id"`
	Type  UserChangeEventType `json:"type"`
	Retry int                 `json:"retry"`
	Data  UserEventModel      `json:"data"`
}

func NewUserChangeEvent(t UserChangeEventType, user User, auditUserUuid uuid.UUID) UserChangeEvent {
	now := time.Now().Format("20060102150405")
	id := fmt.Sprintf("%s-%s-%s", t.String(), user.Uuid.String(), now)

	return UserChangeEvent{
		ID:   id,
		Type: t,
		Data: UserEventModel{
			User:          user,
			AuditUserUUID: auditUserUuid,
		},
	}
}

type UserEventModel struct {
	User          User      `json:"user"`
	AuditUserUUID uuid.UUID `json:"auditUserUuid"`
}

type UserChangeEventType string

const (
	CREATED UserChangeEventType = "USER_CREATED"
	UPDATED UserChangeEventType = "USER_UPDATED"
	DELETED UserChangeEventType = "USER_DELETED"
)

func (t UserChangeEventType) String() string {
	return string(t)
}
