package api

import (
	"context"
	"net/http"

	"github.com/gin-gonic/gin"
	"github.com/manumura/go-auth-rbac-starter/config"
	"github.com/manumura/go-auth-rbac-starter/middleware"
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

	// router.Use(middleware.RequestLogger())
	// router.Use(
	// 	middleware.ErrorHandler(
	// 		// middleware.Map(ErrNotFound).ToStatusCode(http.StatusNotFound),
	// 		middleware.Map(ErrNotFound).ToResponse(notFoundErrorHandler),
	// 		middleware.Map(ErrAlreadyExists).ToResponse(badRequestErrorHandler),
	// 		middleware.Map(ErrUnauthorized).ToResponse(unauthorizedErrorHandler),
	// 	))

	errorToResponseMap := middleware.MapErrorsToResponse(
		middleware.ErrorMap{
			Errors:   []error{ErrNotFound},
			Response: notFoundErrorHandler,
		},
		middleware.ErrorMap{
			Errors:   []error{ErrAlreadyExists},
			Response: badRequestErrorHandler,
		},
		middleware.ErrorMap{
			Errors:   []error{ErrUnauthorized},
			Response: unauthorizedErrorHandler,
		},
	)
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

func (server *Server) Start() error {
	return server.httpServer.ListenAndServe()
}

func (server *Server) Shutdown(ctx context.Context) error {
	return server.httpServer.Shutdown(ctx)
}
