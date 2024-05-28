package user

import (
	"time"

	"github.com/google/uuid"
	"github.com/manumura/go-auth-rbac-starter/role"
)

type UserResponse struct {
	Uuid      uuid.UUID  `json:"uuid"`
	Name      string     `json:"name"`
	Email     string     `json:"email"`
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

type RegisterRequest struct {
	Name     string `json:"name" validate:"required,min=6,max=100"`
	Email    string `json:"email" validate:"required,email"`
	Password string `json:"password" validate:"required"`
}
