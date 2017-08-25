package storage

import (
	"time"

	"github.com/garyburd/redigo/redis"
)

type RedisConfig struct {
	Address  string `toml:"address"`
	Password string `toml:"password"`
}

type RedisStorage struct {
	pool *redis.Pool
}

func NewRedisStorage(config *RedisConfig) *RedisStorage {
	// Create a Redis connectionpool
	pool := &redis.Pool{
		MaxIdle:     3,
		IdleTimeout: 240 * time.Second,
		// Dial creates a connection and authenticates
		Dial: func() (redis.Conn, error) {
			c, err := redis.Dial("tcp", config.Address)
			if err != nil {
				return nil, err
			}
			if config.Password != "" {
				if _, err := c.Do("AUTH", config.Password); err != nil {
					c.Close()
					return nil, err
				}
			}
			return c, nil
		},
		// Ping a connection to see whether it's still alive
		// TODO: give more thought to semantics
		TestOnBorrow: func(c redis.Conn, t time.Time) error {
			if time.Since(t) < time.Minute {
				return nil
			}
			_, err := c.Do("PING")
			return err
		},
	}

	return &RedisStorage{pool}
}

// Save data in Redis
func (s *RedisStorage) Set(key string, value string, expireIn int) error {
	conn := s.pool.Get()
	defer conn.Close()
	_, err := conn.Do("SET", key, value, "EX", expireIn)
	return err
}

func (s *RedisStorage) Get(key string) (string, error) {
	conn := s.pool.Get()
	defer conn.Close()
	return redis.String(conn.Do("GET", key))
}
