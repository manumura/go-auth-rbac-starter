package api

import (
	"context"
	"fmt"
	"net/http"

	"github.com/gin-gonic/gin"
	"github.com/manumura/go-auth-rbac-starter/config"
)

type Server struct {
	config     config.Config
	httpServer *http.Server
}

func NewServer(config config.Config) (*Server, error) {
	server := &Server{
		config: config,
	}

	router := server.setupRouter()

	httpServer := &http.Server{
		Addr:    config.HTTPServerAddress,
		Handler: router,
	}
	server.httpServer = httpServer

	return server, nil
}

func (server *Server) setupRouter() *gin.Engine {
	router := gin.Default()

	router.GET("/hello", server.hello)

	return router
}

func (server *Server) Start() error {
	return server.httpServer.ListenAndServe()
}

func (server *Server) Shutdown(ctx context.Context) error {
	return server.httpServer.Shutdown(ctx)
}

func (server *Server) hello(ctx *gin.Context) {
	msg := fmt.Sprintf("Hello World! %s", server.config.Environment)
	ctx.JSON(http.StatusOK, gin.H{
		"message": msg,
	})
}

// func (err error) gin.H {
// 	return gin.H{"error": err.Error()}
// }
