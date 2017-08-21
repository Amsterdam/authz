package transientstorage

import (
	"bytes"
	"encoding/gob"
	"fmt"
	"time"

	"github.com/garyburd/redigo/redis"
)

type RedisConfig struct {
	Address    string `toml:"address"`
	Password   string `toml:"password"`
	ExpireSecs int    `toml:"expire_secs"`
}

type RedisStorage struct {
	pool   *redis.Pool
	expiry int
}

func NewRedisStorage(config *RedisConfig) *RedisStorage {
	redisStore := &RedisStorage{}
	// Create a Redis connectionpool
	redisStore.pool = &redis.Pool{
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
	// Set the expiry
	redisStore.expiry = config.ExpireSecs

	return redisStore
}

func (r *RedisStorage) SetAuthorizationParams(id string, params *AuthorizationParams) error {
	// Save data in Redis
	var data bytes.Buffer
	enc := gob.NewEncoder(&data)
	err := enc.Encode(params)
	if err != nil {
		return err
	}
	key := fmt.Sprintf("authzreq:%s", id)
	value := data.String()
	conn := r.pool.Get()
	defer conn.Close()
	_, err = conn.Do("SET", key, value, "EX", r.expiry)
	return err
}

func (r *RedisStorage) GetAuthorizationParams(id string) (*AuthorizationParams, error) {
	return nil, nil
}
