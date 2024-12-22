package middleware

import (
	"errors"
	"fmt"
	"net/http"
	"strings"
	"time"

	"github.com/gin-gonic/gin"
	"github.com/manumura/go-auth-rbac-starter/authentication"
	"github.com/manumura/go-auth-rbac-starter/db"
	"github.com/manumura/go-auth-rbac-starter/exception"
	"github.com/manumura/go-auth-rbac-starter/user"
	"github.com/rs/zerolog/log"
)

const (
	authorizationHeaderKey  = "authorization"
	authorizationTypeBearer = "bearer"
)

func AuthMiddleware(authenticationService authentication.AuthenticationService, userService user.UserService) gin.HandlerFunc {
	return func(ctx *gin.Context) {
		a, err := getAuthenticationToken(ctx, authenticationService)
		if err != nil {
			ctx.AbortWithStatusJSON(http.StatusUnauthorized, exception.ErrorResponse(exception.ErrorAccessInvalidToken, http.StatusUnauthorized))
			return
		}

		accessTokenExpiresAt, err := time.Parse(time.DateTime, a.AccessTokenExpiresAt)
		if err != nil {
			log.Error().Err(err).Msg("error parsing access token expiry time")
			ctx.AbortWithStatusJSON(http.StatusUnauthorized, exception.ErrorResponse(exception.ErrorAccessInvalidToken, http.StatusUnauthorized))
			return
		}

		now := time.Now().UTC()
		if accessTokenExpiresAt.Before(now) {
			log.Error().Msg("access token expired")
			ctx.AbortWithStatusJSON(http.StatusUnauthorized, exception.ErrorResponse(exception.ErrorAccessInvalidToken, http.StatusUnauthorized))
			return
		}

		u, err := userService.GetByID(ctx, a.UserID)
		if err != nil {
			log.Error().Err(err).Msg("error getting user from DB")
			ctx.AbortWithStatusJSON(http.StatusUnauthorized, exception.ErrorResponse(exception.ErrorAccessInvalidToken, http.StatusUnauthorized))
			return
		}

		authenticatedUser := user.ToAuthenticatedUser(u)
		log.Info().Msgf("authenticated user: %s", authenticatedUser.Uuid)
		ctx.Set(user.AuthenticatedUserKey, authenticatedUser)
		ctx.Next()
	}
}

func LogoutMiddleware(authenticationService authentication.AuthenticationService, userService user.UserService) gin.HandlerFunc {
	return func(ctx *gin.Context) {
		a, err := getAuthenticationToken(ctx, authenticationService)
		if err != nil {
			ctx.AbortWithStatusJSON(http.StatusUnauthorized, exception.ErrorResponse(exception.ErrorAccessInvalidToken, http.StatusUnauthorized))
			return
		}

		// No need to check validity of token here, as we are logging out
		u, err := userService.GetByID(ctx, a.UserID)
		if err != nil {
			log.Error().Err(err).Msg("error getting user from DB")
			ctx.AbortWithStatusJSON(http.StatusUnauthorized, exception.ErrorResponse(exception.ErrorAccessInvalidToken, http.StatusUnauthorized))
			return
		}

		authenticatedUser := user.ToAuthenticatedUser(u)
		log.Info().Msgf("authenticated user: %s", authenticatedUser.Uuid)
		ctx.Set(user.AuthenticatedUserKey, authenticatedUser)
		ctx.Next()
	}
}

func getAuthenticationToken(ctx *gin.Context, authenticationService authentication.AuthenticationService) (db.AuthenticationToken, error) {
	accessToken, err := extractAccessTokenFromHeader(ctx)
	if err != nil {
		log.Error().Err(err).Msg("error extracting access token from header")
		return db.AuthenticationToken{}, err
	}

	a, err := authenticationService.GetByAccessToken(ctx, accessToken)
	if err != nil {
		log.Error().Err(err).Msg("error getting authentication from DB")
		return db.AuthenticationToken{}, err
	}

	return a, nil
}

func extractAccessTokenFromHeader(ctx *gin.Context) (string, error) {
	authorizationHeader := ctx.GetHeader(authorizationHeaderKey)

	if len(authorizationHeader) == 0 {
		err := errors.New("authorization header not found")
		return "", err
	}

	fields := strings.Fields(authorizationHeader)
	if len(fields) < 2 {
		err := errors.New("invalid authorization header")
		return "", err
	}

	authorizationType := strings.ToLower(fields[0])
	if authorizationType != authorizationTypeBearer {
		err := fmt.Errorf("unsupported authorization type %s", authorizationType)
		return "", err
	}

	accessToken := fields[1]
	return accessToken, nil
}
