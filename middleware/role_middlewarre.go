package middleware

import (
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
		val, exists := ctx.Get(user.AuthenticatedUserKey)
		if !exists {
			ctx.AbortWithStatusJSON(http.StatusForbidden, exception.ErrorResponse(exception.ErrForbidden, http.StatusForbidden))
			return
		}

		u, ok := val.(user.AuthenticatedUser)
		if !ok {
			ctx.AbortWithStatusJSON(http.StatusForbidden, exception.ErrorResponse(exception.ErrForbidden, http.StatusForbidden))
			return
		}

		fmt.Println(u)
		ok = slices.Contains(roles, u.Role)

		if !ok {
			ctx.AbortWithStatusJSON(http.StatusForbidden, exception.ErrorResponse(exception.ErrForbidden, http.StatusForbidden))
			return
		}

		ctx.Next()
	}
}
