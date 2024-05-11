package api

import (
	"fmt"
	"net/http"

	"github.com/gin-gonic/gin"
	"github.com/manumura/go-auth-rbac-starter/exception"
)

func (server *HttpServer) index(ctx *gin.Context) {
	msg := fmt.Sprintf("Welcome to Go starter ^^! %s", server.config.Environment)
	ctx.JSON(http.StatusOK, gin.H{
		"message": msg,
	})
}

func (server *HttpServer) test(ctx *gin.Context) {
	test, ok := ctx.GetQuery("test")
	if !ok {
		ctx.AbortWithStatusJSON(http.StatusBadRequest, exception.ErrorResponse(exception.ErrNotFound))
		return
	}

	if test == "error" {
		ctx.AbortWithStatusJSON(http.StatusConflict, exception.ErrorResponse(exception.ErrAlreadyExists))
		return
	}

	ctx.JSON(http.StatusOK, gin.H{
		"test": test,
	})
}
