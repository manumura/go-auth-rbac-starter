package authentication

import (
	"errors"

	"github.com/gin-gonic/gin"
)

const AuthenticatedUserKey = "user"

func GetUserFromContext(ctx *gin.Context) (AuthenticatedUser, error) {
	val, exists := ctx.Get(AuthenticatedUserKey)
	if !exists {
		return AuthenticatedUser{}, errors.New("user not found in context")
	}

	u, ok := val.(AuthenticatedUser)
	if !ok {
		return AuthenticatedUser{}, errors.New("user not found in context")
	}

	return u, nil
}
