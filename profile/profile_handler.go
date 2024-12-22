package profile

import (
	"net/http"

	"github.com/gin-gonic/gin"
	"github.com/manumura/go-auth-rbac-starter/exception"
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
	u, err := user.GetUserFromContext(ctx)
	if err != nil {
		ctx.AbortWithStatusJSON(http.StatusUnauthorized, exception.ErrorResponse(exception.ErrUnauthorized, http.StatusUnauthorized))
		return
	}

	ctx.JSON(http.StatusOK, u)
}
