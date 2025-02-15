package security

import (
	"errors"
	"time"

	"github.com/gin-gonic/gin"
	"github.com/google/uuid"
	"github.com/manumura/go-auth-rbac-starter/role"
)

const (
	AuthenticatedUserContextKey = "user"
)

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

func GetUserFromContext(ctx *gin.Context) (AuthenticatedUser, error) {
	val, exists := ctx.Get(AuthenticatedUserContextKey)
	if !exists {
		return AuthenticatedUser{}, errors.New("user not found in context")
	}

	u, ok := val.(AuthenticatedUser)
	if !ok {
		return AuthenticatedUser{}, errors.New("user not found in context")
	}

	return u, nil
}
