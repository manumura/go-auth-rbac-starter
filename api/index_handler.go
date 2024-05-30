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
