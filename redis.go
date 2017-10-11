package main

import (
	"errors"
	"time"

	"github.com/garyburd/redigo/redis"
	log "github.com/sirupsen/logrus"
)

type redisStorage struct {
	pool *redis.Pool
}

func newRedisStorage(address string, password string) *redisStorage {
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
	log.Println("INFO: Using Redis as transient storage")
	return &redisStorage{pool}
}

// Save data in Redis
func (s *redisStorage) Persist(key string, value string, timeout time.Duration) error {
	conn := s.pool.Get()
	defer conn.Close()
	_, err := conn.Do("SET", key, value, "EX", int(timeout.Seconds()))
	return err
}

func (s *redisStorage) Restore(key string) (string, error) {
	conn := s.pool.Get()
	defer conn.Close()
	if err := conn.Send("MULTI"); err != nil {
		return "", err
	}
	if err := conn.Send("GET", key); err != nil {
		return "", err
	}
	if err := conn.Send("DEL", key); err != nil {
		return "", err
	}
	if vals, err := redis.Values(conn.Do("EXEC")); err != nil {
		return "", err
	} else if vals[0] == nil {
		return "", errors.New("key doesnt exist")
	} else {
		return redis.String(vals[0], nil)
	}
}
