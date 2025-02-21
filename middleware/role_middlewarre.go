package middleware

import (
	"net/http"
	"slices"

	"github.com/gin-gonic/gin"
	"github.com/manumura/go-auth-rbac-starter/exception"
	"github.com/manumura/go-auth-rbac-starter/role"
	"github.com/manumura/go-auth-rbac-starter/security"
)

func RoleMiddleware(roles []role.Role) gin.HandlerFunc {
	return func(ctx *gin.Context) {
		authenticatedUser, err := security.GetUserFromContext(ctx)
		if err != nil {
			ctx.AbortWithStatusJSON(http.StatusForbidden, exception.GetErrorResponse(exception.ErrForbidden, http.StatusForbidden))
			return
		}

		ok := slices.Contains(roles, authenticatedUser.Role)
		if !ok {
			ctx.AbortWithStatusJSON(http.StatusForbidden, exception.GetErrorResponse(exception.ErrForbidden, http.StatusForbidden))
			return
		}

		ctx.Next()
	}
}
