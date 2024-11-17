package middleware

import (
	"errors"
	"fmt"
	"net/http"
	"strings"
	"time"

	"github.com/gin-gonic/gin"
	"github.com/manumura/go-auth-rbac-starter/authentication"
	"github.com/manumura/go-auth-rbac-starter/exception"
	"github.com/manumura/go-auth-rbac-starter/user"
	"github.com/rs/zerolog/log"
)

const (
	authorizationHeaderKey  = "authorization"
	authorizationTypeBearer = "bearer"
	AuthenticatedUserKey    = "user"
)

func AuthMiddleware(authenticationService authentication.AuthenticationService, userService user.UserService) gin.HandlerFunc {
	return func(ctx *gin.Context) {
		authorizationHeader := ctx.GetHeader(authorizationHeaderKey)

		if len(authorizationHeader) == 0 {
			err := errors.New("authorization header not found")
			ctx.AbortWithStatusJSON(http.StatusUnauthorized, exception.ErrorResponse(err, http.StatusUnauthorized))
			return
		}

		fields := strings.Fields(authorizationHeader)
		if len(fields) < 2 {
			err := errors.New("invalid authorization header")
			ctx.AbortWithStatusJSON(http.StatusUnauthorized, exception.ErrorResponse(err, http.StatusUnauthorized))
			return
		}

		authorizationType := strings.ToLower(fields[0])
		if authorizationType != authorizationTypeBearer {
			err := fmt.Errorf("unsupported authorization type %s", authorizationType)
			ctx.AbortWithStatusJSON(http.StatusUnauthorized, exception.ErrorResponse(err, http.StatusUnauthorized))
			return
		}

		accessToken := fields[1]
		a, err := authenticationService.GetByAccessToken(ctx, accessToken)
		if err != nil {
			log.Error().Err(err).Msg("error getting authentication from DB")
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
		ctx.Set(AuthenticatedUserKey, authenticatedUser)
		ctx.Next()
	}
}
