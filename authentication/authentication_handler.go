package authentication

import (
	"database/sql"
	"errors"
	"net/http"
	"time"

	"github.com/gin-gonic/gin"
	"github.com/go-playground/validator/v10"
	"github.com/golang-jwt/jwt/v5"
	"github.com/jaevor/go-nanoid"
	"github.com/manumura/go-auth-rbac-starter/config"
	"github.com/manumura/go-auth-rbac-starter/exception"
	oauthprovider "github.com/manumura/go-auth-rbac-starter/oauth_provider"
	"github.com/manumura/go-auth-rbac-starter/role"
	"github.com/manumura/go-auth-rbac-starter/user"
	"github.com/rs/zerolog/log"
)

type AuthenticationHandler struct {
	user.UserService
	AuthenticationService
	config.Config
	*validator.Validate
}

func NewAuthenticationHandler(userService user.UserService, authenticationService AuthenticationService, config config.Config, validate *validator.Validate) AuthenticationHandler {
	return AuthenticationHandler{
		userService,
		authenticationService,
		config,
		validate,
	}
}

func (h *AuthenticationHandler) Login(ctx *gin.Context) {
	var req LoginRequest
	if err := ctx.ShouldBindJSON(&req); err != nil {
		ctx.AbortWithStatusJSON(http.StatusBadRequest, exception.ErrorResponse(exception.ErrInvalidRequest, http.StatusBadRequest))
		return
	}

	// returns nil or ValidationErrors ( []FieldError )
	err := h.Validate.Struct(req)
	if err != nil {
		log.Error().Err(err).Msg("validation error")
		ctx.AbortWithStatusJSON(http.StatusBadRequest, exception.ErrorResponse(err, http.StatusBadRequest))
		return
	}

	u, err := h.GetByEmail(ctx, req.Email)
	if err != nil {
		ctx.AbortWithStatusJSON(http.StatusUnauthorized, exception.ErrorResponse(exception.ErrLogin, http.StatusUnauthorized))
		return
	}

	if !u.IsActive {
		log.Error().Msg("user is not active")
		ctx.AbortWithStatusJSON(http.StatusUnauthorized, exception.ErrorResponse(exception.ErrLogin, http.StatusUnauthorized))
		return
	}

	// Comparing the password with the hash
	err = h.CheckPassword(req.Password, u.UserCredentials.Password)
	if err != nil {
		ctx.AbortWithStatusJSON(http.StatusUnauthorized, exception.ErrorResponse(exception.ErrLogin, http.StatusUnauthorized))
		return
	}

	authenticatedUser := user.ToAuthenticatedUser(u)

	t, err := h.generateTokens(authenticatedUser)
	if err != nil {
		log.Error().Err(err).Msg("failed to generate authentication tokens")
		ctx.AbortWithStatusJSON(http.StatusInternalServerError, exception.ErrorResponse(exception.ErrInternalServer, http.StatusInternalServerError))
		return
	}

	// Save the tokens in the database
	authReq := AuthenticationRequest{
		UserID:                u.ID,
		AccessToken:           t.AccessToken,
		RefreshToken:          t.RefreshToken,
		AccessTokenExpiresAt:  t.AccessTokenExpiresAt,
		RefreshTokenExpiresAt: t.RefreshTokenExpiresAt,
	}
	_, err = h.CreateAuthentication(ctx, authReq)
	if err != nil {
		log.Error().Err(err).Msg("failed to save authentication token")
		ctx.AbortWithStatusJSON(http.StatusInternalServerError, exception.ErrorResponse(exception.ErrInternalServer, http.StatusInternalServerError))
		return
	}

	authResponse := AuthenticationResponse{
		AccessToken:          t.AccessToken,
		RefreshToken:         t.RefreshToken,
		IdToken:              t.IdToken,
		AccessTokenExpiresAt: t.AccessTokenExpiresAt,
	}

	ctx.JSON(http.StatusOK, authResponse)
}

func (h *AuthenticationHandler) Oauth2FacebookLogin(ctx *gin.Context) {
	var req Oauth2FacebookLoginRequest
	if err := ctx.ShouldBindJSON(&req); err != nil {
		ctx.AbortWithStatusJSON(http.StatusBadRequest, exception.ErrorResponse(exception.ErrInvalidRequest, http.StatusBadRequest))
		return
	}

	// returns nil or ValidationErrors ( []FieldError )
	err := h.Validate.Struct(req)
	if err != nil {
		log.Error().Err(err).Msg("validation error")
		ctx.AbortWithStatusJSON(http.StatusBadRequest, exception.ErrorResponse(err, http.StatusBadRequest))
		return
	}

	var u user.UserEntity
	u, err = h.GetUserByOauthProvider(ctx, oauthprovider.FACEBOOK, req.ID)
	if err != nil && !errors.Is(err, sql.ErrNoRows) {
		ctx.AbortWithStatusJSON(http.StatusUnauthorized, exception.ErrorResponse(exception.ErrLogin, http.StatusUnauthorized))
		return
	}

	if errors.Is(err, sql.ErrNoRows) {
		// create user
		u, err = h.CreateOauth(ctx, user.CreateOauthUserRequest{
			Name:           req.Name,
			Email:          req.Email,
			Role:           role.USER,
			OauthProvider:  oauthprovider.FACEBOOK,
			ExternalUserID: req.ID,
		})

		if err != nil {
			ctx.AbortWithStatusJSON(http.StatusInternalServerError, exception.ErrorResponse(err, http.StatusInternalServerError))
			return
		}
	}

	authenticatedUser := user.ToAuthenticatedUser(u)

	t, err := h.generateTokens(authenticatedUser)
	if err != nil {
		log.Error().Err(err).Msg("failed to generate authentication tokens")
		ctx.AbortWithStatusJSON(http.StatusInternalServerError, exception.ErrorResponse(exception.ErrInternalServer, http.StatusInternalServerError))
		return
	}

	// Save the tokens in the database
	authReq := AuthenticationRequest{
		UserID:                u.ID,
		AccessToken:           t.AccessToken,
		RefreshToken:          t.RefreshToken,
		AccessTokenExpiresAt:  t.AccessTokenExpiresAt,
		RefreshTokenExpiresAt: t.RefreshTokenExpiresAt,
	}
	_, err = h.CreateAuthentication(ctx, authReq)
	if err != nil {
		log.Error().Err(err).Msg("failed to save authentication token")
		ctx.AbortWithStatusJSON(http.StatusInternalServerError, exception.ErrorResponse(exception.ErrInternalServer, http.StatusInternalServerError))
		return
	}

	authResponse := AuthenticationResponse{
		AccessToken:          t.AccessToken,
		RefreshToken:         t.RefreshToken,
		IdToken:              t.IdToken,
		AccessTokenExpiresAt: t.AccessTokenExpiresAt,
	}

	ctx.JSON(http.StatusOK, authResponse)
}

func (h *AuthenticationHandler) Oauth2GoogleLogin(ctx *gin.Context) {
	var req Oauth2GoogleLoginRequest
	if err := ctx.ShouldBindJSON(&req); err != nil {
		ctx.AbortWithStatusJSON(http.StatusBadRequest, exception.ErrorResponse(exception.ErrInvalidRequest, http.StatusBadRequest))
		return
	}

	// returns nil or ValidationErrors ( []FieldError )
	err := h.Validate.Struct(req)
	if err != nil {
		log.Error().Err(err).Msg("validation error")
		ctx.AbortWithStatusJSON(http.StatusBadRequest, exception.ErrorResponse(err, http.StatusBadRequest))
		return
	}

	// TODO
	// h.GetUserByOauthProvider
}

type authenticationToken struct {
	IdToken               string
	AccessToken           string
	RefreshToken          string
	AccessTokenExpiresAt  time.Time
	RefreshTokenExpiresAt time.Time
}

func (h *AuthenticationHandler) generateTokens(authenticatedUser user.AuthenticatedUser) (authenticationToken, error) {
	now := time.Now().UTC()
	accessToken, err := nanoid.Standard(21)
	if err != nil {
		log.Error().Err(err).Msg("failed to generate access token")
		return authenticationToken{}, err
	}
	accessTokenAsString := accessToken()
	accessTokenExpiresAt := now.Add(time.Duration(h.AccessTokenExpiresInAsSeconds) * time.Second)

	refreshToken, err := nanoid.Standard(21)
	if err != nil {
		log.Error().Err(err).Msg("failed to generate refresh token")
		return authenticationToken{}, err
	}
	refreshTokenAsString := refreshToken()
	refreshTokenExpiresAt := now.Add(time.Duration(h.RefreshTokenExpiresInAsSeconds) * time.Second)

	idTokenExpiresAt := now.Add(time.Duration(h.IdTokenExpiresInAsSeconds) * time.Second)
	idToken := jwt.NewWithClaims(jwt.SigningMethodHS256, jwt.MapClaims{
		"iat":  now.Format(time.DateTime),
		"exp":  idTokenExpiresAt,
		"user": authenticatedUser,
	})

	idTokenAsString, err := idToken.SignedString([]byte(h.JwtSecret))
	if err != nil {
		log.Error().Err(err).Msg("failed to create id token")
		return authenticationToken{}, err
	}

	return authenticationToken{
		AccessToken:           accessTokenAsString,
		RefreshToken:          refreshTokenAsString,
		IdToken:               idTokenAsString,
		AccessTokenExpiresAt:  accessTokenExpiresAt,
		RefreshTokenExpiresAt: refreshTokenExpiresAt,
	}, nil
}
