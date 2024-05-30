package profile

import (
	"errors"
	"net/http"

	"github.com/gin-gonic/gin"
	"github.com/manumura/go-auth-rbac-starter/exception"
	"github.com/manumura/go-auth-rbac-starter/middleware"
	"github.com/manumura/go-auth-rbac-starter/user"
)

type ProfileHandler struct {
	user.UserService
}

func NewProfileHandler(userService user.UserService) ProfileHandler {
	return ProfileHandler{
		userService,
	}
}

func (h *ProfileHandler) GetProfile(ctx *gin.Context) {
	val, exists := ctx.Get(middleware.AuthenticatedUserKey)
	if !exists {
		ctx.AbortWithStatusJSON(http.StatusUnauthorized, exception.ErrorResponse(errors.New("user not authenticated")))
		return
	}

	u, ok := val.(user.UserResponse)
	if !ok {
		ctx.AbortWithStatusJSON(http.StatusUnauthorized, exception.ErrorResponse(errors.New("user not authenticated")))
		return
	}

	ctx.JSON(http.StatusOK, u)
}
