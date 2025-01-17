package authentication

import (
	"context"
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
	"google.golang.org/api/idtoken"
)

type AuthenticationHandler struct {
	user.UserService
	AuthenticationService
	config.Config
	*validator.Validate
}

type authenticationToken struct {
	IdToken               string
	AccessToken           string
	RefreshToken          string
	AccessTokenExpiresAt  time.Time
	RefreshTokenExpiresAt time.Time
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

	authResponse, authenticatedUser, err := h.createTokens(u, ctx)
	if err != nil {
		ctx.AbortWithStatusJSON(http.StatusInternalServerError, exception.ErrorResponse(err, http.StatusInternalServerError))
		return
	}

	log.Info().Msgf("user %s logged in", authenticatedUser.Uuid)
	ctx.JSON(http.StatusOK, authResponse)
}

func (h *AuthenticationHandler) RefreshToken(ctx *gin.Context) {
	authenticatedUser, err := user.GetUserFromContext(ctx)
	log.Info().Msgf("user %s regresh out", authenticatedUser.Uuid)
	if err != nil {
		ctx.AbortWithStatusJSON(http.StatusUnauthorized, exception.ErrorResponse(exception.ErrUnauthorized, http.StatusUnauthorized))
		return
	}

	u, err := h.GetByUUID(ctx, authenticatedUser.Uuid.String())
	if err != nil {
		ctx.AbortWithStatusJSON(http.StatusNotFound, exception.ErrorResponse(exception.ErrNotFound, http.StatusNotFound))
		return
	}

	authResponse, authenticatedUser, err := h.createTokens(u, ctx)
	if err != nil {
		ctx.AbortWithStatusJSON(http.StatusInternalServerError, exception.ErrorResponse(err, http.StatusInternalServerError))
		return
	}

	log.Info().Msgf("user %s token refreshed", authenticatedUser.Uuid)
	ctx.JSON(http.StatusOK, authResponse)
}

func (h *AuthenticationHandler) Logout(ctx *gin.Context) {
	authenticatedUser, err := user.GetUserFromContext(ctx)
	if err != nil {
		ctx.AbortWithStatusJSON(http.StatusUnauthorized, exception.ErrorResponse(exception.ErrUnauthorized, http.StatusUnauthorized))
		return
	}

	u, err := h.GetByUUID(ctx, authenticatedUser.Uuid.String())
	if err != nil {
		ctx.AbortWithStatusJSON(http.StatusNotFound, exception.ErrorResponse(exception.ErrNotFound, http.StatusNotFound))
		return
	}

	err = h.DeleteAuthenticationTokenByUserID(ctx, u.ID)
	if err != nil {
		ctx.AbortWithStatusJSON(http.StatusInternalServerError, exception.ErrorResponse(exception.ErrInternalServer, http.StatusInternalServerError))
		return
	}

	log.Info().Msgf("user %s logged out", authenticatedUser.Uuid)
	ctx.JSON(http.StatusOK, authenticatedUser)
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
		log.Error().Err(err).Msg("invalid request")
		ctx.AbortWithStatusJSON(http.StatusBadRequest, exception.ErrorResponse(err, http.StatusBadRequest))
		return
	}

	authResponse, authenticatedUser, err := h.authenticate(req.ID, oauthprovider.FACEBOOK, req.Name, req.Email, ctx)
	if err != nil {
		statusCode := http.StatusInternalServerError
		if err == exception.ErrLogin {
			statusCode = http.StatusUnauthorized
		}
		ctx.AbortWithStatusJSON(statusCode, exception.ErrorResponse(err, statusCode))
		return
	}

	log.Info().Msgf("user %s logged in", authenticatedUser.Uuid)
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

	tokenPayload, err := verifyGoogleToken(req.Token, h.Config.GoogleClientId)
	if err != nil {
		log.Error().Err(err).Msg("invalid token")
		ctx.AbortWithStatusJSON(http.StatusBadRequest, exception.ErrorResponse(err, http.StatusBadRequest))
		return
	}

	id := tokenPayload.Subject
	email := tokenPayload.Claims["email"].(string)
	name := tokenPayload.Claims["name"].(string)

	authResponse, authenticatedUser, err := h.authenticate(id, oauthprovider.GOOGLE, name, email, ctx)
	if err != nil {
		statusCode := http.StatusInternalServerError
		if err == exception.ErrLogin {
			statusCode = http.StatusUnauthorized
		}
		ctx.AbortWithStatusJSON(statusCode, exception.ErrorResponse(err, statusCode))
		return
	}

	log.Info().Msgf("user %s logged in", authenticatedUser.Uuid)
	ctx.JSON(http.StatusOK, authResponse)
}

func (h *AuthenticationHandler) authenticate(id string, p oauthprovider.OauthProvider, name string, email string, ctx context.Context) (AuthenticationResponse, user.AuthenticatedUser, error) {
	var u user.UserEntity
	u, err := h.GetByOauthProvider(ctx, p, id)
	// Error is other than user not found
	if err != nil && !errors.Is(err, sql.ErrNoRows) {
		// ctx.AbortWithStatusJSON(http.StatusUnauthorized, exception.ErrorResponse(exception.ErrLogin, http.StatusUnauthorized))
		return AuthenticationResponse{}, user.AuthenticatedUser{}, exception.ErrLogin
	}

	if errors.Is(err, sql.ErrNoRows) {
		// User not found : create it
		u, err = h.CreateOauth(ctx, user.CreateOauthUserParams{
			Name:           name,
			Email:          email,
			Role:           role.USER,
			OauthProvider:  p,
			ExternalUserID: id,
		})

		if err != nil {
			// ctx.AbortWithStatusJSON(http.StatusInternalServerError, exception.ErrorResponse(err, http.StatusInternalServerError))
			return AuthenticationResponse{}, user.AuthenticatedUser{}, err
		}
	}

	return h.createTokens(u, ctx)
}

func (h *AuthenticationHandler) createTokens(u user.UserEntity, ctx context.Context) (AuthenticationResponse, user.AuthenticatedUser, error) {
	authenticatedUser := user.ToAuthenticatedUser(u)

	t, err := h.generateTokens(authenticatedUser)
	if err != nil {
		log.Error().Err(err).Msg("failed to generate authentication tokens")
		// ctx.AbortWithStatusJSON(http.StatusInternalServerError, exception.ErrorResponse(exception.ErrInternalServer, http.StatusInternalServerError))
		return AuthenticationResponse{}, user.AuthenticatedUser{}, exception.ErrInternalServer
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
		// ctx.AbortWithStatusJSON(http.StatusInternalServerError, exception.ErrorResponse(exception.ErrInternalServer, http.StatusInternalServerError))
		return AuthenticationResponse{}, user.AuthenticatedUser{}, exception.ErrInternalServer
	}

	authResponse := AuthenticationResponse{
		AccessToken:          t.AccessToken,
		RefreshToken:         t.RefreshToken,
		IdToken:              t.IdToken,
		AccessTokenExpiresAt: t.AccessTokenExpiresAt,
	}

	return authResponse, authenticatedUser, nil
}

// TODO encrypt SHA256 ?
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

func verifyGoogleToken(token string, googleClientId string) (*idtoken.Payload, error) {
	tokenValidator, err := idtoken.NewValidator(context.Background())
	if err != nil {
		return &idtoken.Payload{}, err
	}

	payload, err := tokenValidator.Validate(context.Background(), token, googleClientId)
	if err != nil {
		return &idtoken.Payload{}, err
	}

	return payload, nil
}
