package main

import (
	"context"
	"errors"
	"io"
	"net/http"
	"os"
	"os/signal"
	"strconv"
	"syscall"

	"github.com/go-playground/validator/v10"
	"github.com/manumura/go-auth-rbac-starter/api"
	"github.com/manumura/go-auth-rbac-starter/config"
	"github.com/manumura/go-auth-rbac-starter/db"
	"github.com/manumura/go-auth-rbac-starter/redis"
	"github.com/rs/zerolog/log"
	"golang.org/x/sync/errgroup"

	goRedis "github.com/redis/go-redis/v9"
)

var interruptSignals = []os.Signal{
	os.Interrupt,
	syscall.SIGTERM,
	syscall.SIGINT,
}

// https://github.com/swaggo/swag
// @tag.name index
// @tag.description Index handler
// @tag.name authentication
// @tag.description Authentication handler
// @tag.name verify email
// @tag.description Verify email handler
// @tag.name reset password
// @tag.description Reset password handler
// @tag.name recaptcha
// @tag.description Recaptcha handler
// @tag.name profile
// @tag.description Profile handler
// @tag.name user
// @tag.description User handler
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

	redisClient := redis.NewRedisClient(redis.RedisOptions{
		Address:      config.RedisHost + ":" + strconv.Itoa(config.RedisPort),
		Username:     config.RedisUsername,
		Password:     config.RedisPassword,
		UseTLS:       config.RedisUseTLS,
		PoolSize:     10,
		MinIdleConns: 5,
	})
	defer redisClient.Close()

	err = redisClient.Conn().Ping(ctx).Err()
	if err != nil {
		log.Error().Err(err).Msg("cannot ping redis")
		return err
	}

	runHttpServer(ctx, waitGroup, config, datastore, redisClient, validate)

	err = waitGroup.Wait()
	if err != nil {
		log.Error().Err(err).Msg("error from wait group")
		return err
	}

	return nil
}

func runHttpServer(ctx context.Context,
	waitGroup *errgroup.Group,
	config config.Config,
	dataStore db.DataStore,
	redisClient *goRedis.Client,
	validate *validator.Validate) {
	server, err := api.NewHttpServer(config, dataStore, redisClient, validate)
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
