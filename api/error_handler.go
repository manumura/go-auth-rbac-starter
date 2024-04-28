package api

import (
	"net/http"

	"github.com/gin-gonic/gin"
	"github.com/go-errors/errors"
	"github.com/manumura/go-auth-rbac-starter/middleware"
)

var (
	ErrNotFound        = errors.New("resource could not be found")
	ErrAlreadyExists   = errors.New("resource already exists")
	ErrInvalidPassword = errors.New("username or password is invalid")
)

var errorToResponseMap = middleware.MapErrorsToResponse(
	middleware.ErrorMap{
		Errors:   []error{ErrNotFound},
		Response: notFoundErrorHandler,
	},
	middleware.ErrorMap{
		Errors:   []error{ErrAlreadyExists},
		Response: badRequestErrorHandler,
	},
	middleware.ErrorMap{
		Errors:   []error{ErrInvalidPassword},
		Response: unauthorizedErrorHandler,
	},
)

func notFoundErrorHandler(ctx *gin.Context, err error) {
	ctx.JSON(http.StatusNotFound, gin.H{
		"error": err.Error(),
	})
}

func badRequestErrorHandler(ctx *gin.Context, err error) {
	ctx.JSON(http.StatusBadRequest, gin.H{
		"error": err.Error(),
	})
}

func unauthorizedErrorHandler(ctx *gin.Context, err error) {
	ctx.JSON(http.StatusUnauthorized, gin.H{
		"error": err.Error(),
	})
}

func uncaughtErrorHandler(ctx *gin.Context, err any) {
	goErr := errors.Wrap(err, 2)
	ctx.AbortWithStatusJSON(http.StatusInternalServerError, gin.H{
		"error": goErr.Error(),
	})
}
