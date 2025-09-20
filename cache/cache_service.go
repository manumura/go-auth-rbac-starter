package cache

import (
	"context"
	"errors"
	"time"

	goRedis "github.com/redis/go-redis/v9"
)

var ErrCacheMiss = errors.New("cache_miss")

type CacheService interface {
	Set(ctx context.Context, key string, value interface{}, expiration time.Duration) error
	Get(ctx context.Context, key string) (string, error)
	Delete(ctx context.Context, key string) error
}

type CacheServiceImpl struct {
	redisClient *goRedis.Client
}

func NewCacheService(redisClient *goRedis.Client) CacheService {
	return &CacheServiceImpl{
		redisClient: redisClient,
	}
}

func (c *CacheServiceImpl) Set(ctx context.Context, key string, value interface{}, expiration time.Duration) error {
	return c.redisClient.Set(ctx, key, value, expiration).Err()
}

func (c *CacheServiceImpl) Get(ctx context.Context, key string) (string, error) {
	val, err := c.redisClient.Get(ctx, key).Result()
	if err == goRedis.Nil {
		return "", ErrCacheMiss
	}
	return val, err
}

func (c *CacheServiceImpl) Delete(ctx context.Context, key string) error {
	return c.redisClient.Del(ctx, key).Err()
}
