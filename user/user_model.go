package user

import (
	"time"

	"github.com/google/uuid"
)

type Role string

const (
	ADMIN Role = "ADMIN"
	USER  Role = "USER"
)

type UserResponse struct {
	Id    string    `json:"id"`
	Uuid  uuid.UUID `json:"uuid"`
	Name  string    `json:"name"`
	Email string    `json:"email"`
	// Password string `json:"password"`
	IsActive  bool      `json:"isActive"`
	ImageId   string    `json:"imageId"`
	ImageUrl  string    `json:"imageUrl"`
	Role      Role      `json:"role"`
	CreatedAt time.Time `json:"createdAt"`
	UpdatedAt time.Time `json:"updatedAt"`
}

type RegisterRequest struct {
	Name     string `json:"name"`
	Email    string `json:"email"`
	Password string `json:"password"`
}
