package middleware

import (
	"errors"
	"fmt"
	"net/http"
	"strings"
	"time"

	"github.com/gin-gonic/gin"
	"github.com/manumura/go-auth-rbac-starter/authentication"
	"github.com/manumura/go-auth-rbac-starter/cookie"
	"github.com/manumura/go-auth-rbac-starter/db"
	"github.com/manumura/go-auth-rbac-starter/exception"
	"github.com/manumura/go-auth-rbac-starter/security"
	"github.com/manumura/go-auth-rbac-starter/user"
	"github.com/rs/zerolog/log"
)

func AuthMiddleware(authenticationService authentication.AuthenticationService, userService user.UserService) gin.HandlerFunc {
	return func(ctx *gin.Context) {
		a, err := getAuthenticationFromAccessToken(ctx, authenticationService)
		if err != nil {
			ctx.AbortWithStatusJSON(http.StatusUnauthorized, exception.GetErrorResponse(exception.ErrorInvalidAccessToken, http.StatusUnauthorized))
			return
		}

		// Check validity of token
		accessTokenExpiresAt, err := time.Parse(time.DateTime, a.AccessTokenExpiresAt)
		if err != nil {
			log.Error().Err(err).Msg("error parsing access token expiry time")
			ctx.AbortWithStatusJSON(http.StatusUnauthorized, exception.GetErrorResponse(exception.ErrorInvalidAccessToken, http.StatusUnauthorized))
			return
		}

		now := time.Now().UTC()
		if accessTokenExpiresAt.Before(now) {
			log.Error().Msg("access token expired")
			ctx.AbortWithStatusJSON(http.StatusUnauthorized, exception.GetErrorResponse(exception.ErrorInvalidAccessToken, http.StatusUnauthorized))
			return
		}

		u, err := userService.GetByID(ctx, a.UserID)
		if err != nil {
			log.Error().Err(err).Msg("error getting user from DB")
			ctx.AbortWithStatusJSON(http.StatusUnauthorized, exception.GetErrorResponse(exception.ErrorInvalidAccessToken, http.StatusUnauthorized))
			return
		}

		if !u.IsActive {
			log.Error().Msg("user is not active")
			ctx.AbortWithStatusJSON(http.StatusUnauthorized, exception.GetErrorResponse(exception.ErrorInvalidAccessToken, http.StatusUnauthorized))
			return
		}

		authenticatedUser := user.ToAuthenticatedUser(u)
		// log.Info().Msgf("authenticated user: %s", authenticatedUser.Uuid)
		ctx.Set(security.AuthenticatedUserContextKey, authenticatedUser)
		ctx.Next()
	}
}

func RefreshAuthMiddleware(authenticationService authentication.AuthenticationService, userService user.UserService) gin.HandlerFunc {
	return func(ctx *gin.Context) {
		a, err := getAuthenticationFromRefreshToken(ctx, authenticationService)
		if err != nil {
			ctx.AbortWithStatusJSON(http.StatusUnauthorized, exception.GetErrorResponse(exception.ErrorInvalidRefreshToken, http.StatusUnauthorized))
			return
		}

		// Check validity of token
		refreshTokenExpiresAt, err := time.Parse(time.DateTime, a.RefreshTokenExpiresAt)
		if err != nil {
			log.Error().Err(err).Msg("error parsing refresh token expiry time")
			ctx.AbortWithStatusJSON(http.StatusUnauthorized, exception.GetErrorResponse(exception.ErrorInvalidRefreshToken, http.StatusUnauthorized))
			return
		}

		now := time.Now().UTC()
		if refreshTokenExpiresAt.Before(now) {
			log.Error().Msg("refresh token expired")
			ctx.AbortWithStatusJSON(http.StatusUnauthorized, exception.GetErrorResponse(exception.ErrorInvalidRefreshToken, http.StatusUnauthorized))
			return
		}

		u, err := userService.GetByID(ctx, a.UserID)
		if err != nil {
			log.Error().Err(err).Msg("error getting user from DB")
			ctx.AbortWithStatusJSON(http.StatusUnauthorized, exception.GetErrorResponse(exception.ErrorInvalidRefreshToken, http.StatusUnauthorized))
			return
		}

		if !u.IsActive {
			log.Error().Msg("user is not active")
			ctx.AbortWithStatusJSON(http.StatusUnauthorized, exception.GetErrorResponse(exception.ErrorInvalidAccessToken, http.StatusUnauthorized))
			return
		}

		authenticatedUser := user.ToAuthenticatedUser(u)
		log.Info().Msgf("authenticated user: %s", authenticatedUser.Uuid)
		ctx.Set(security.AuthenticatedUserContextKey, authenticatedUser)
		ctx.Next()
	}
}

func LogoutAuthMiddleware(authenticationService authentication.AuthenticationService, userService user.UserService) gin.HandlerFunc {
	return func(ctx *gin.Context) {
		a, err := getAuthenticationFromAccessToken(ctx, authenticationService)
		if err != nil {
			ctx.AbortWithStatusJSON(http.StatusUnauthorized, exception.GetErrorResponse(exception.ErrorInvalidAccessToken, http.StatusUnauthorized))
			return
		}

		// No need to check validity of token or user active here, as we are logging out
		u, err := userService.GetByID(ctx, a.UserID)
		if err != nil {
			log.Error().Err(err).Msg("error getting user from DB")
			ctx.AbortWithStatusJSON(http.StatusUnauthorized, exception.GetErrorResponse(exception.ErrorInvalidAccessToken, http.StatusUnauthorized))
			return
		}

		authenticatedUser := user.ToAuthenticatedUser(u)
		log.Info().Msgf("authenticated user: %s", authenticatedUser.Uuid)
		ctx.Set(security.AuthenticatedUserContextKey, authenticatedUser)
		ctx.Next()
	}
}

func getAuthenticationFromAccessToken(ctx *gin.Context, authenticationService authentication.AuthenticationService) (db.AuthenticationToken, error) {
	accessToken, err := cookie.ExtractAccessTokenFromCookie(ctx)
	if err != nil {
		log.Error().Err(err).Msg("error extracting access token from cookie")
		accessToken, err = extractTokenFromHeader(ctx)
		if err != nil {
			log.Error().Err(err).Msg("error extracting access token from header")
			return db.AuthenticationToken{}, err
		}
	}

	a, err := authenticationService.GetByAccessToken(ctx, accessToken)
	if err != nil {
		log.Error().Err(err).Msg("error getting authentication from DB")
		return db.AuthenticationToken{}, err
	}

	return a, nil
}

func getAuthenticationFromRefreshToken(ctx *gin.Context, authenticationService authentication.AuthenticationService) (db.AuthenticationToken, error) {
	refreshToken, err := cookie.ExtractRefreshTokenFromCookie(ctx)
	if err != nil {
		log.Error().Err(err).Msg("error extracting access token from cookie")
		refreshToken, err = extractTokenFromHeader(ctx)
		if err != nil {
			log.Error().Err(err).Msg("error extracting refresh token from header")
			return db.AuthenticationToken{}, err
		}
	}

	a, err := authenticationService.GetByRefreshToken(ctx, refreshToken)
	if err != nil {
		log.Error().Err(err).Msg("error getting authentication from DB")
		return db.AuthenticationToken{}, err
	}

	return a, nil
}

func extractTokenFromHeader(ctx *gin.Context) (string, error) {
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
