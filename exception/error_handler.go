package exception

import (
	"net/http"

	"github.com/gin-gonic/gin"
	"github.com/go-errors/errors"
)

func UncaughtErrorHandler(ctx *gin.Context, err any) {
	goErr := errors.Wrap(err, 2)
	ctx.AbortWithStatusJSON(http.StatusInternalServerError, gin.H{
		"error": goErr.Error(),
	})
}

func InternalServerErrorHandler(ctx *gin.Context, err error) {
	ctx.JSON(http.StatusInternalServerError, gin.H{
		"error": err.Error(),
	})
}

func NotFoundErrorHandler(ctx *gin.Context, err error) {
	ctx.JSON(http.StatusNotFound, gin.H{
		"error": err.Error(),
	})
}

func BadRequestErrorHandler(ctx *gin.Context, err error) {
	ctx.JSON(http.StatusBadRequest, gin.H{
		"error": err.Error(),
	})
}

func UnauthorizedErrorHandler(ctx *gin.Context, err error) {
	ctx.JSON(http.StatusUnauthorized, gin.H{
		"error": err.Error(),
	})
}
