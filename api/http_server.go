package api

import (
	"context"
	"net/http"

	"github.com/go-playground/validator/v10"
	"github.com/manumura/go-auth-rbac-starter/config"
	"github.com/manumura/go-auth-rbac-starter/db"

	goRedis "github.com/redis/go-redis/v9"
)

type HttpServer struct {
	config      config.Config
	datastore   db.DataStore
	redisClient *goRedis.Client
	httpServer  *http.Server
}

func NewHttpServer(config config.Config, datastore db.DataStore, redisClient *goRedis.Client, validate *validator.Validate) (*HttpServer, error) {
	server := &HttpServer{
		config:      config,
		datastore:   datastore,
		redisClient: redisClient,
	}

	router := server.SetupRouter(config, validate)

	server.httpServer = &http.Server{
		Addr:    config.HTTPServerAddress,
		Handler: router,
	}

	return server, nil
}

func (server *HttpServer) Start() error {
	return server.httpServer.ListenAndServe()
}

func (server *HttpServer) Shutdown(ctx context.Context) error {
	return server.httpServer.Shutdown(ctx)
}
