package main

import (
	"context"
	"errors"
	"fmt"
	"net"
	"net/http"
	"os"
	"os/signal"
	"syscall"

	_ "github.com/mattn/go-sqlite3"

	"github.com/go-playground/validator/v10"
	"github.com/manumura/go-auth-rbac-starter/api"
	"github.com/manumura/go-auth-rbac-starter/config"
	"github.com/manumura/go-auth-rbac-starter/db"
	"github.com/manumura/go-auth-rbac-starter/gapi"
	"github.com/manumura/go-auth-rbac-starter/middleware"
	"github.com/manumura/go-auth-rbac-starter/pb"
	"github.com/rs/zerolog"
	"github.com/rs/zerolog/log"
	"golang.org/x/sync/errgroup"
	"google.golang.org/grpc"
	"google.golang.org/grpc/reflection"
)

var interruptSignals = []os.Signal{
	os.Interrupt,
	syscall.SIGTERM,
	syscall.SIGINT,
}

func main() {
	config, err := config.LoadConfig(".env")
	if err != nil {
		log.Fatal().Err(err).Msg("cannot load config")
	}

	if config.Environment == "dev" {
		log.Logger = log.Output(zerolog.ConsoleWriter{Out: os.Stderr})
	}

	log.Info().Msg("starting main")

	// use a single instance of Validate, it caches struct info
	validate := validator.New(validator.WithRequiredStructEnabled())

	database := db.NewDataStore(config)
	err = database.Connect()
	if err != nil {
		log.Fatal().Err(err).Msg("cannot open database")
		return
	}
	defer database.Close()

	u, err := database.GetUserByEmail(context.Background(), "test@test.com")
	if err != nil {
		log.Fatal().Err(err).Msg("cannot get user")
		return
	}
	fmt.Printf("user %v\n", u)

	ctx, stop := signal.NotifyContext(context.Background(), interruptSignals...)
	defer stop()
	waitGroup, ctx := errgroup.WithContext(ctx)

	runGrpcServer(ctx, waitGroup, config)
	runHttpServer(ctx, waitGroup, config, validate)

	err = waitGroup.Wait()
	if err != nil {
		log.Fatal().Err(err).Msg("error from wait group")
	}
}

func runHttpServer(ctx context.Context,
	waitGroup *errgroup.Group, conf config.Config,
	validate *validator.Validate) {
	server, err := api.NewHttpServer(conf, validate)
	if err != nil {
		log.Fatal().Err(err).Msg("cannot create HTTP server")
	}

	waitGroup.Go(func() error {
		log.Info().Msgf("start HTTP server at %s", conf.HTTPServerAddress)

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

func runGrpcServer(
	ctx context.Context,
	waitGroup *errgroup.Group,
	conf config.Config,
) {
	server, err := gapi.NewGrpcServer(conf)
	if err != nil {
		log.Fatal().Err(err).Msg("cannot create server")
	}

	gprcUnaryLogger := grpc.UnaryInterceptor(middleware.GrpcUnaryLogger)
	// gprcStreamLogger := grpc.StreamInterceptor(middleware.GrpcStreamLogger)
	grpcServer := grpc.NewServer(gprcUnaryLogger)
	pb.RegisterUserEventServer(grpcServer, server)
	reflection.Register(grpcServer)

	listener, err := net.Listen("tcp", conf.GRPCServerAddress)
	if err != nil {
		log.Fatal().Err(err).Msg("cannot create listener")
	}

	waitGroup.Go(func() error {
		log.Info().Msgf("start gRPC server at %s", listener.Addr().String())

		err = grpcServer.Serve(listener)
		if err != nil {
			if errors.Is(err, grpc.ErrServerStopped) {
				return nil
			}
			log.Error().Err(err).Msg("gRPC server failed to serve")
			return err
		}

		return nil
	})

	waitGroup.Go(func() error {
		<-ctx.Done()
		log.Info().Msg("graceful shutdown gRPC server")

		grpcServer.GracefulStop()
		log.Info().Msg("gRPC server is stopped")

		return nil
	})
}
