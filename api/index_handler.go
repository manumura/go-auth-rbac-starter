package api

import (
	"fmt"
	"net/http"
	"os"

	"github.com/gin-gonic/gin"
	"github.com/manumura/go-auth-rbac-starter/common"
	"github.com/rs/zerolog/log"
)

// @BasePath /api
// Welcome godoc
// @Summary welcome message
// @Schemes
// @Description welcome message
// @Tags index
// @Accept json
// @Produce json
// @Success 200 {object} common.MessageResponse
// @Router /v1/index [get]
func (server *HttpServer) index(ctx *gin.Context) {
	msg := fmt.Sprintf("Welcome to Go starter ^^! %s", os.Getenv(common.ENVIRONMENT))
	ctx.JSON(http.StatusOK, common.MessageResponse{Message: msg})
}

// @BasePath /api
// Info godoc
// @Summary get app info
// @Schemes
// @Description get app info
// @Tags index
// @Accept json
// @Produce json
// @Success 200 {object} common.InfoResponse
// @Router /v1/info [get]
func (server *HttpServer) info(ctx *gin.Context) {
	log.Info().Msgf("info API, user agent detected: %s, hostname: %s", ctx.Request.UserAgent(), ctx.Request.Host)
	ctx.JSON(http.StatusOK, common.InfoResponse{
		Env:       os.Getenv(common.ENVIRONMENT),
		Hostname:  ctx.Request.Host,
		IP:        ctx.ClientIP(),
		UserAgent: ctx.Request.UserAgent(),
	})
}
