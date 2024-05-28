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

func NewAuthenticationHandler(service user.UserService, conf config.Config, validate *validator.Validate) AuthenticationHandler {
	return AuthenticationHandler{
		service,
		conf,
		validate,
	}
}

func (h *AuthenticationHandler) Login(ctx *gin.Context) {
	var req LoginRequest
	if err := ctx.ShouldBindJSON(&req); err != nil {
		ctx.AbortWithStatusJSON(http.StatusBadRequest, exception.ErrorResponse(exception.ErrInvalidRequest))
		return
	}

	// returns nil or ValidationErrors ( []FieldError )
	err := h.Validate.Struct(req)
	if err != nil {
		log.Error().Err(err).Msg("validation error")
		ctx.AbortWithStatusJSON(http.StatusBadRequest, exception.ErrorResponse(err))
		return
	}

	u, err := h.GetByEmail(ctx, req.Email)
	if err != nil {
		ctx.AbortWithStatusJSON(http.StatusUnauthorized, exception.ErrorResponse(exception.ErrNotFound))
		return
	}

	if u.IsActive != 1 {
		log.Error().Msg("user is not active")
		ctx.AbortWithStatusJSON(http.StatusUnauthorized, exception.ErrorResponse(exception.ErrNotFound))
		return
	}

	// Comparing the password with the hash
	err = h.CheckPassword(req.Password, u.Password)
	if err != nil {
		ctx.AbortWithStatusJSON(http.StatusUnauthorized, exception.ErrorResponse(exception.ErrInvalidPassword))
		return
	}

	now := time.Now().UTC()
	userResponse := user.ToUserResponse(u)

	accessToken, err := nanoid.Standard(21)
	if err != nil {
		log.Error().Err(err).Msg("failed to generate access token")
		ctx.AbortWithStatusJSON(http.StatusInternalServerError, exception.ErrorResponse(exception.ErrInternalServer))
		return
	}
	accessTokenAsString := accessToken()
	accessTokenExpiresAt := now.Add(time.Duration(h.AccessTokenExpiresInAsSeconds) * time.Second)

	refreshToken, err := nanoid.Standard(21)
	if err != nil {
		log.Error().Err(err).Msg("failed to generate refresh token")
		ctx.AbortWithStatusJSON(http.StatusInternalServerError, exception.ErrorResponse(exception.ErrInternalServer))
		return
	}
	refreshTokenAsString := refreshToken()
	// refreshTokenExpiresAt := now.Add(time.Duration(h.RefreshTokenExpiresInAsSeconds) * time.Second)

	idTokenExpiresAt := now.Add(time.Duration(h.IdTokenExpiresInAsSeconds) * time.Second)
	idToken := jwt.NewWithClaims(jwt.SigningMethodHS256, jwt.MapClaims{
		"iat":  now.Format(time.DateTime),
		"exp":  idTokenExpiresAt,
		"user": userResponse,
	})

	idTokenAsString, err := idToken.SignedString([]byte(h.JwtSecret))
	if err != nil {
		log.Error().Err(err).Msg("failed to create id token")
		ctx.AbortWithStatusJSON(http.StatusInternalServerError, exception.ErrorResponse(exception.ErrInternalServer))
		return
	}

	authResponse := AuthenticationResponse{
		AccessToken:          accessTokenAsString,
		RefreshToken:         refreshTokenAsString,
		IdToken:              idTokenAsString,
		AccessTokenExpiresAt: accessTokenExpiresAt,
	}

	ctx.JSON(http.StatusOK, authResponse)
}
