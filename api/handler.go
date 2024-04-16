package api

import (
	"fmt"
	"net/http"

	"github.com/gin-gonic/gin"
)

func (server *Server) index(ctx *gin.Context) {
	msg := fmt.Sprintf("Welcome! %s", server.config.Environment)
	ctx.JSON(http.StatusOK, gin.H{
		"message": msg,
	})
}

func (server *Server) test(ctx *gin.Context) {
	ctx.Error(ErrAlreadyExists)
}
