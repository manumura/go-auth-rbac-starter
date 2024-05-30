package middleware

import (
	"errors"
	"fmt"
	"net/http"
	"slices"

	"github.com/gin-gonic/gin"
	"github.com/manumura/go-auth-rbac-starter/exception"
	"github.com/manumura/go-auth-rbac-starter/role"
	"github.com/manumura/go-auth-rbac-starter/user"
)

func RoleMiddleware(roles []role.Role) gin.HandlerFunc {
	return func(ctx *gin.Context) {
		val, exists := ctx.Get(AuthenticatedUserKey)
		if !exists {
			ctx.AbortWithStatusJSON(http.StatusForbidden, exception.ErrorResponse(errors.New("user not authenticated")))
			return
		}

		u, ok := val.(user.UserResponse)
		if !ok {
			ctx.AbortWithStatusJSON(http.StatusForbidden, exception.ErrorResponse(errors.New("user not authenticated")))
			return
		}

		fmt.Println(u)
		ok = slices.Contains(roles, u.Role)

		if !ok {
			ctx.AbortWithStatusJSON(http.StatusForbidden, exception.ErrorResponse(errors.New("user not allowed to access this resource")))
			return
		}

		ctx.Next()
	}
}
