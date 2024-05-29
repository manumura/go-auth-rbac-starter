package middleware

import (
	"errors"
	"fmt"
	"net/http"
	"strings"

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
			ctx.AbortWithStatusJSON(http.StatusUnauthorized, exception.ErrorResponse(err))
			return
		}

		fields := strings.Fields(authorizationHeader)
		if len(fields) < 2 {
			err := errors.New("invalid authorization header")
			ctx.AbortWithStatusJSON(http.StatusUnauthorized, exception.ErrorResponse(err))
			return
		}

		authorizationType := strings.ToLower(fields[0])
		if authorizationType != authorizationTypeBearer {
			err := fmt.Errorf("unsupported authorization type %s", authorizationType)
			ctx.AbortWithStatusJSON(http.StatusUnauthorized, exception.ErrorResponse(err))
			return
		}

		accessToken := fields[1]
		t, err := authenticationService.GetByAccessToken(ctx, accessToken)
		if err != nil {
			log.Error().Err(err).Msg("error getting authentication token from DB")
			ctx.AbortWithStatusJSON(http.StatusUnauthorized, exception.ErrorResponse(errors.New("invalid access token")))
			return
		}

		u, err := userService.GetByID(ctx, t.UserID)
		if err != nil {
			log.Error().Err(err).Msg("error getting user from DB")
			ctx.AbortWithStatusJSON(http.StatusUnauthorized, exception.ErrorResponse(errors.New("invalid access token")))
			return
		}

		ctx.Set(AuthenticatedUserKey, u)
		ctx.Next()
	}
}
