package profile

import (
	"net/http"

	"github.com/gin-gonic/gin"
	"github.com/manumura/go-auth-rbac-starter/db"
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
		ctx.AbortWithStatusJSON(http.StatusUnauthorized, gin.H{"error": "unauthorized"})
		return
	}

	u, ok := val.(db.User)
	if !ok {
		ctx.AbortWithStatusJSON(http.StatusUnauthorized, gin.H{"error": "unauthorized"})
		return
	}

	userResponse := user.ToUserResponse(u)
	ctx.JSON(http.StatusOK, userResponse)
}
