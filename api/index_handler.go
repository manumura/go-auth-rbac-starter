package api

import (
	"fmt"
	"net/http"
	"os"

	"github.com/gin-gonic/gin"
	"github.com/manumura/go-auth-rbac-starter/constant"
	"github.com/rs/zerolog/log"
)

func (server *HttpServer) index(ctx *gin.Context) {
	msg := fmt.Sprintf("Welcome to Go starter ^^! %s", os.Getenv(constant.ENVIRONMENT))
	ctx.JSON(http.StatusOK, gin.H{
		"message": msg,
	})
}

func (server *HttpServer) info(ctx *gin.Context) {
	log.Info().Msgf("info API, user agent detected: %s, hostname: %s", ctx.Request.UserAgent(), ctx.Request.Host)
	ctx.JSON(http.StatusOK, gin.H{
		"env":       os.Getenv(constant.ENVIRONMENT),
		"hostname":  ctx.Request.Host,
		"ip":        ctx.ClientIP(),
		"userAgent": ctx.Request.UserAgent(),
	})
}
