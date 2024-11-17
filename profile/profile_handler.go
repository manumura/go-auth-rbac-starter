package profile

import (
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
		ctx.AbortWithStatusJSON(http.StatusUnauthorized, exception.ErrorResponse(exception.ErrUnauthorized, http.StatusUnauthorized))
		return
	}

	u, ok := val.(user.AuthenticatedUser)
	if !ok {
		ctx.AbortWithStatusJSON(http.StatusUnauthorized, exception.ErrorResponse(exception.ErrUnauthorized, http.StatusUnauthorized))
		return
	}

	ctx.JSON(http.StatusOK, u)
}
