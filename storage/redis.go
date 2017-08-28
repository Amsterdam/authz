package storage

import (
	"log"
	"time"

	"github.com/garyburd/redigo/redis"
)

const (
	DefaultRedisAddress = ":6379"
)

type RedisStorage struct {
	pool *redis.Pool
}

func NewRedisStorage(config interface{}) (*RedisStorage, error) {
	address := DefaultRedisAddress
	password := ""
	if redisConf, ok := config.(map[string]interface{}); ok {
		if addr, ok := redisConf["address"].(string); ok {
			if len(address) > 0 {
				address = addr
			}
		}
		if pwd, ok := redisConf["password"].(string); ok {
			password = pwd
		}
	}
	// Create a Redis connectionpool
	pool := &redis.Pool{
		MaxIdle:     3,
		IdleTimeout: 240 * time.Second,
		// Dial creates a connection and authenticates
		Dial: func() (redis.Conn, error) {
			c, err := redis.Dial("tcp", address)
			if err != nil {
				return nil, err
			}
			if password != "" {
				if _, err := c.Do("AUTH", password); err != nil {
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
	log.Println("Created Redis back-end storage")
	return &RedisStorage{pool}, nil
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
