package main

import (
	"context"
	"errors"
	"io"
	"net/http"
	"os"
	"os/signal"
	"syscall"

	_ "github.com/mattn/go-sqlite3"

	"github.com/go-playground/validator/v10"
	"github.com/manumura/go-auth-rbac-starter/api"
	"github.com/manumura/go-auth-rbac-starter/config"
	"github.com/manumura/go-auth-rbac-starter/db"
	"github.com/rs/zerolog/log"
	"golang.org/x/sync/errgroup"
)

var interruptSignals = []os.Signal{
	os.Interrupt,
	syscall.SIGTERM,
	syscall.SIGINT,
}

// TODO swagger https://github.com/swaggo/gin-swagger https://lemoncode21.medium.com/how-to-add-swagger-in-golang-gin-6932e8076ec0
func main() {
	ctx := context.Background()
	if err := run(ctx, os.Args, os.Stdin, os.Stdout, os.Stderr); err != nil {
		log.Fatal().Err(err).Msg("application stopped with error")
	}
}

// https://grafana.com/blog/2024/02/09/how-i-write-http-services-in-go-after-13-years/
func run(ctx context.Context, args []string, stdin io.Reader, stdout, stderr io.Writer) error {
	ctx, cancel := signal.NotifyContext(context.Background(), interruptSignals...)
	defer cancel()
	waitGroup, ctx := errgroup.WithContext(ctx)

	// use a single instance of Validate, it caches struct info
	validate := validator.New(validator.WithRequiredStructEnabled())

	config, err := config.LoadConfig("config.yaml", validate)
	if err != nil {
		log.Error().Err(err).Msg("cannot load config")
		return err
		// e := fmt.Errorf("environment variable %s is not set", constant.ENVIRONMENT)
		// panic(e)
	}

	log.Info().Msgf("starting main on environment: %s", config.Environment)

	datastore := db.NewDataStore(config)
	err = datastore.Connect()
	if err != nil {
		log.Error().Err(err).Msg("cannot connect to database")
		return err
	}
	defer datastore.Close()

	err = datastore.MigrateUp()
	if err != nil {
		log.Error().Err(err).Msg("cannot migrate up")
		return err
	}

	runHttpServer(ctx, waitGroup, config, datastore, validate)

	err = waitGroup.Wait()
	if err != nil {
		log.Error().Err(err).Msg("error from wait group")
		return err
	}

	return nil
}

func runHttpServer(ctx context.Context,
	waitGroup *errgroup.Group, config config.Config, dataStore db.DataStore,
	validate *validator.Validate) {
	server, err := api.NewHttpServer(config, dataStore, validate)
	if err != nil {
		log.Fatal().Err(err).Msg("cannot create HTTP server")
	}

	waitGroup.Go(func() error {
		log.Info().Msgf("start HTTP server at %s", config.HTTPServerAddress)

		err = server.Start()
		if err != nil {
			if errors.Is(err, http.ErrServerClosed) {
				return nil
			}
			log.Error().Err(err).Msg("cannot start HTTP server")
			return err
		}

		return nil
	})

	waitGroup.Go(func() error {
		<-ctx.Done()
		log.Info().Msg("graceful shutdown HTTP server")

		server.Shutdown(context.Background())
		log.Info().Msg("HTTP server is stopped")

		return nil
	})
}
