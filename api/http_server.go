package api

import (
	"context"
	"net/http"

	"github.com/gin-gonic/gin"
	"github.com/go-playground/validator/v10"
	"github.com/manumura/go-auth-rbac-starter/authentication"
	"github.com/manumura/go-auth-rbac-starter/config"
	"github.com/manumura/go-auth-rbac-starter/db"
	"github.com/manumura/go-auth-rbac-starter/exception"
	"github.com/manumura/go-auth-rbac-starter/middleware"
	"github.com/manumura/go-auth-rbac-starter/profile"
	"github.com/manumura/go-auth-rbac-starter/user"
)

type HttpServer struct {
	config     config.Config
	datastore  db.DataStore
	httpServer *http.Server
}

func NewHttpServer(config config.Config, datastore db.DataStore, validate *validator.Validate) (*HttpServer, error) {
	server := &HttpServer{
		config:    config,
		datastore: datastore,
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
	router.Use(gin.CustomRecovery(exception.UncaughtErrorHandler))

	userService := user.NewUserService(server.datastore)
	authenticationService := authentication.NewAuthenticationService(server.datastore)

	userHandler := user.NewUserHandler(userService, validate)
	authenticationHandler := authentication.NewAuthenticationHandler(userService, authenticationService, config, validate)
	profileHandler := profile.NewProfileHandler(userService)

	publicRouter := router.Group("/api/v1")
	publicRouter.GET("/index", server.index)
	publicRouter.POST("/register", userHandler.Register)
	publicRouter.POST("/login", authenticationHandler.Login)

	authRouter := publicRouter.Use(middleware.AuthMiddleware(authenticationService, userService))
	authRouter.GET("/profile", profileHandler.GetProfile)

	// TODO remove test
	publicRouter.GET("/test", server.test)

	return router
}

func (server *HttpServer) Start() error {
	return server.httpServer.ListenAndServe()
}

func (server *HttpServer) Shutdown(ctx context.Context) error {
	return server.httpServer.Shutdown(ctx)
}
