package api

import (
	"context"
	"net/http"

	"github.com/gin-gonic/gin"
	"github.com/go-playground/validator/v10"
	"github.com/manumura/go-auth-rbac-starter/authentication"
	"github.com/manumura/go-auth-rbac-starter/config"
	"github.com/manumura/go-auth-rbac-starter/exception"
	"github.com/manumura/go-auth-rbac-starter/middleware"
	"github.com/manumura/go-auth-rbac-starter/user"
)

type HttpServer struct {
	config     config.Config
	httpServer *http.Server
}

func NewHttpServer(config config.Config, validate *validator.Validate) (*HttpServer, error) {
	server := &HttpServer{
		config: config,
	}

	router := server.setupRouter(config, validate)

	httpServer := &http.Server{
		Addr:    config.HTTPServerAddress,
		Handler: router,
	}
	server.httpServer = httpServer

	return server, nil
}

func (server *HttpServer) setupRouter(config config.Config, validate *validator.Validate) *gin.Engine {
	router := gin.Default()

	router.Use(
		middleware.ErrorHandlerV2(
			middleware.ErrorToResponseMap,
		))
	// TODO test recovery middleware
	router.Use(gin.CustomRecovery(exception.UncaughtErrorHandler))

	userService := user.NewUserService()
	userHandler := user.NewUserHandler(&userService, validate)
	authenticationHandler := authentication.NewAuthenticationHandler(&userService, config, validate)

	apiV1Router := router.Group("/api/v1")
	apiV1Router.GET("/index", server.index)
	apiV1Router.POST("/register", userHandler.Register)
	apiV1Router.POST("/login", authenticationHandler.Login)

	// TODO remove test
	apiV1Router.GET("/test", server.test)

	return router
}

func (server *HttpServer) Start() error {
	return server.httpServer.ListenAndServe()
}

func (server *HttpServer) Shutdown(ctx context.Context) error {
	return server.httpServer.Shutdown(ctx)
}
