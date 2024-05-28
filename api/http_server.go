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
	"github.com/manumura/go-auth-rbac-starter/role"
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

	roleService := role.NewRoleService(server.datastore)
	roleService.InitRolesMaps(context.Background())

	userService := user.NewUserService(server.datastore)
	userHandler := user.NewUserHandler(userService, validate)
	authenticationHandler := authentication.NewAuthenticationHandler(userService, config, validate)

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
