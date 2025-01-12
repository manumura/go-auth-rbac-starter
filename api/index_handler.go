package api

import (
	"fmt"
	"net/http"
	"os"

	"github.com/gin-gonic/gin"
	"github.com/manumura/go-auth-rbac-starter/constant"
)

func (server *HttpServer) index(ctx *gin.Context) {
	msg := fmt.Sprintf("Welcome to Go starter ^^! %s", os.Getenv(constant.ENVIRONMENT))
	ctx.JSON(http.StatusOK, gin.H{
		"message": msg,
	})
}
