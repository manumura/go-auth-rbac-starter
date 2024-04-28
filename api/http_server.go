package api

import (
	"context"
	"net/http"

	"github.com/gin-gonic/gin"
	"github.com/manumura/go-auth-rbac-starter/config"
	"github.com/manumura/go-auth-rbac-starter/middleware"
)

type HttpServer struct {
	config     config.Config
	httpServer *http.Server
}

func NewHttpServer(config config.Config) (*HttpServer, error) {
	server := &HttpServer{
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

// TODO https://www.franken-ui.dev/
func (server *HttpServer) setupRouter() *gin.Engine {
	router := gin.Default()

	router.Use(
		middleware.ErrorHandlerV2(
			errorToResponseMap,
		))
	// TODO test recovery middleware
	router.Use(gin.CustomRecovery(uncaughtErrorHandler))

	apiV1Router := router.Group("/api/v1")
	apiV1Router.GET("/index", server.index)
	apiV1Router.GET("/test", server.test)

	return router
}

func (server *HttpServer) Start() error {
	return server.httpServer.ListenAndServe()
}

func (server *HttpServer) Shutdown(ctx context.Context) error {
	return server.httpServer.Shutdown(ctx)
}
