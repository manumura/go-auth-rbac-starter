package api

import (
	"context"
	"net/http"

	"github.com/go-playground/validator/v10"
	"github.com/manumura/go-auth-rbac-starter/config"
	"github.com/manumura/go-auth-rbac-starter/db"
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

	router := server.SetupRouter(config, validate)

	httpServer := &http.Server{
		Addr:    config.HTTPServerAddress,
		Handler: router,
	}
	server.httpServer = httpServer

	return server, nil
}

func (server *HttpServer) Start() error {
	return server.httpServer.ListenAndServe()
}

func (server *HttpServer) Shutdown(ctx context.Context) error {
	return server.httpServer.Shutdown(ctx)
}
