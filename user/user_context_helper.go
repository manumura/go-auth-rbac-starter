package user

import (
	"errors"

	"github.com/gin-gonic/gin"
	"github.com/manumura/go-auth-rbac-starter/common"
)

func GetUserFromContext(ctx *gin.Context) (AuthenticatedUser, error) {
	val, exists := ctx.Get(common.AuthenticatedUserContextKey)
	if !exists {
		return AuthenticatedUser{}, errors.New("user not found in context")
	}

	u, ok := val.(AuthenticatedUser)
	if !ok {
		return AuthenticatedUser{}, errors.New("user not found in context")
	}

	return u, nil
}
