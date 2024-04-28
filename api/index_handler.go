package api

import (
	"fmt"
	"net/http"

	"github.com/gin-gonic/gin"
)

func (server *HttpServer) index(ctx *gin.Context) {
	msg := fmt.Sprintf("Welcome to Go starter ^^! %s", server.config.Environment)
	ctx.JSON(http.StatusOK, gin.H{
		"message": msg,
	})
}

// TODO remove test
func (server *HttpServer) test(ctx *gin.Context) {
	test, ok := ctx.GetQuery("test")
	if !ok {
		ctx.Error(ErrNotFound)
		return
	}

	if test == "error" {
		ctx.Error(ErrAlreadyExists)
		return
	}

	ctx.JSON(http.StatusOK, gin.H{
		"test": test,
	})
}
