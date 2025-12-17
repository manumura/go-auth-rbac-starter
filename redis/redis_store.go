package redis

import (
	"context"
	"crypto/tls"

	goRedis "github.com/redis/go-redis/v9"
	"github.com/rs/zerolog/log"
)

type RedisOptions struct {
	Address      string
	Username     string
	Password     string
	UseTLS       bool
	PoolSize     int
	MinIdleConns int
}

func NewRedisClient(options RedisOptions) *goRedis.Client {
	rdb := goRedis.NewClient(&goRedis.Options{
		Addr:     options.Address,
		Username: options.Username,
		Password: options.Password,
		OnConnect: func(ctx context.Context, cn *goRedis.Conn) error {
			log.Info().Msg("connected to redis")
			return nil
		},
		PoolSize:     options.PoolSize,
		MinIdleConns: options.MinIdleConns,
	})

	if options.UseTLS {
		rdb.Options().TLSConfig = &tls.Config{
			MinVersion: tls.VersionTLS12,
		}
	}

	return rdb
}
