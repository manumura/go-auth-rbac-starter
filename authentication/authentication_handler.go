package authentication

import (
	"net/http"
	"time"

	"github.com/gin-gonic/gin"
	"github.com/go-playground/validator/v10"
	"github.com/golang-jwt/jwt/v5"
	"github.com/jaevor/go-nanoid"
	"github.com/manumura/go-auth-rbac-starter/config"
	"github.com/manumura/go-auth-rbac-starter/exception"
	"github.com/manumura/go-auth-rbac-starter/user"
	"github.com/rs/zerolog/log"
)

type AuthenticationHandler struct {
	user.UserService
	config.Config
	*validator.Validate
}

func NewAuthenticationHandler(service *user.UserService, conf config.Config, validate *validator.Validate) *AuthenticationHandler {
	return &AuthenticationHandler{
		*service,
		conf,
		validate,
	}
}

func (h *AuthenticationHandler) Login(ctx *gin.Context) {
	var req LoginRequest
	if err := ctx.ShouldBindJSON(&req); err != nil {
		ctx.Error(exception.ErrInvalidRequest)
		return
	}

	// returns nil or ValidationErrors ( []FieldError )
	err := h.Validate.Struct(req)
	if err != nil {
		log.Error().Err(err).Msg("validation error")
		ctx.Error(exception.ErrInvalidRequest)
		return
	}

	u, err := h.GetByEmail(ctx, req.Email)
	if err != nil {
		ctx.Error(exception.ErrNotFound)
		return
	}

	if !u.IsActive {
		log.Error().Msg("user is not active")
		ctx.Error(exception.ErrNotFound)
		return
	}

	// Comparing the password with the hash
	err = h.CheckPassword(req.Password, u.Password)
	if err != nil {
		ctx.Error(exception.ErrInvalidPassword)
		return
	}

	accessToken, err := nanoid.Standard(21)
	if err != nil {
		log.Error().Err(err).Msg("failed to generate access token")
		ctx.Error(exception.ErrInternalServer)
		return
	}
	accessTokenAsString := accessToken()

	refreshToken, err := nanoid.Standard(21)
	if err != nil {
		log.Error().Err(err).Msg("failed to generate refresh token")
		ctx.Error(exception.ErrInternalServer)
		return
	}
	refreshTokenAsString := refreshToken()

	now := time.Now()
	accessTokenExpiresAt := now.Add(time.Duration(h.AccessTokenExpiresInAsSeconds) * time.Second)
	// refreshTokenExpiresAt := now.Add(time.Duration(h.RefreshTokenExpiresInAsSeconds) * time.Second)
	idTokenExpiresAt := now.Add(time.Duration(h.IdTokenExpiresInAsSeconds) * time.Second)

	userResponse := user.ToUserResponse(u)
	idToken := jwt.NewWithClaims(jwt.SigningMethodHS256, jwt.MapClaims{
		"iat":  now,
		"exp":  idTokenExpiresAt,
		"user": userResponse,
	})

	idTokenAsString, err := idToken.SignedString([]byte(h.JwtSecret))
	if err != nil {
		log.Error().Err(err).Msg("failed to create id token")
		ctx.Error(exception.ErrInternalServer)
		return
	}

	loginResponse := LoginResponse{
		AccessToken:          accessTokenAsString,
		RefreshToken:         refreshTokenAsString,
		IdToken:              idTokenAsString,
		AccessTokenExpiresAt: accessTokenExpiresAt,
	}

	ctx.JSON(http.StatusOK, loginResponse)
}
