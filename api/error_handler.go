package api

import (
	"net/http"

	"github.com/gin-gonic/gin"
	"github.com/go-errors/errors"
)

var (
	ErrNotFound      = errors.New("resource could not be found")
	ErrAlreadyExists = errors.New("resource already exists")
	ErrUnauthorized  = errors.New("username or password is invalid")
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
