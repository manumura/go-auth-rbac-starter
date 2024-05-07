package authentication

import (
	"fmt"
	"net/http"
	"time"

	"github.com/gin-gonic/gin"
	"github.com/manumura/go-auth-rbac-starter/exception"
	"github.com/manumura/go-auth-rbac-starter/user"
)

type AuthenticationHandler struct {
	user.UserService
}

func NewAuthenticationHandler(service *user.UserService) *AuthenticationHandler {
	return &AuthenticationHandler{
		*service,
	}
}

func (h *AuthenticationHandler) Login(ctx *gin.Context) {
	var req LoginRequest
	if err := ctx.ShouldBindJSON(&req); err != nil {
		ctx.Error(exception.ErrInvalidRequest)
		return
	}

	user, err := h.GetByEmail(ctx, req.Email)
	if err != nil {
		ctx.Error(exception.ErrNotFound)
		return
	}

	// Comparing the password with the hash
	err = h.CheckPassword(req.Password, user.Password)
	fmt.Println(err != nil) // true
	if err != nil {
		ctx.Error(exception.ErrInvalidPassword)
		return
	}

	loginResponse := LoginResponse{
		AccessToken:          "accessToken",
		RefreshToken:         "refreshToken",
		IdToken:              "idToken",
		AccessTokenExpiresAt: time.Now(),
	}

	ctx.JSON(http.StatusOK, loginResponse)
}
