package middleware

import (
	"net/http"
	"slices"

	"github.com/gin-gonic/gin"
	"github.com/manumura/go-auth-rbac-starter/common"
	"github.com/manumura/go-auth-rbac-starter/exception"
	"github.com/manumura/go-auth-rbac-starter/role"
	"github.com/manumura/go-auth-rbac-starter/user"
)

func RoleMiddleware(roles []role.Role) gin.HandlerFunc {
	return func(ctx *gin.Context) {
		val, exists := ctx.Get(common.AuthenticatedUserContextKey)
		if !exists {
			ctx.AbortWithStatusJSON(http.StatusForbidden, exception.GetErrorResponse(exception.ErrForbidden, http.StatusForbidden))
			return
		}

		u, ok := val.(user.AuthenticatedUser)
		if !ok {
			ctx.AbortWithStatusJSON(http.StatusForbidden, exception.GetErrorResponse(exception.ErrForbidden, http.StatusForbidden))
			return
		}

		ok = slices.Contains(roles, u.Role)
		if !ok {
			ctx.AbortWithStatusJSON(http.StatusForbidden, exception.GetErrorResponse(exception.ErrForbidden, http.StatusForbidden))
			return
		}

		ctx.Next()
	}
}
