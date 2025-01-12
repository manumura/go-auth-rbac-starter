package exception

import (
	"net/http"

	"github.com/gin-gonic/gin"
	"github.com/go-errors/errors"
)

func UncaughtErrorHandler(ctx *gin.Context, err any) {
	goErr := errors.Wrap(err, 2)
	ctx.AbortWithStatusJSON(http.StatusInternalServerError, gin.H{
		"message":    goErr.Error(),
		"error":      http.StatusText(http.StatusInternalServerError),
		"statusCode": http.StatusInternalServerError,
	})
}
