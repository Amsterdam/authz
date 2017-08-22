package main

import (
	"io/ioutil"
	"log"

	"github.com/BurntSushi/toml"
	"github.com/DatapuntAmsterdam/goauth2/rfc6749/client"
	"github.com/DatapuntAmsterdam/goauth2/rfc6749/idp"
	"github.com/DatapuntAmsterdam/goauth2/rfc6749/transientstorage"
)

const (
	DefaultBindAddress     = ":8080"
	DefaultURL             = "http://localhost:8080/goauth2"
	DefaultRedisAddress    = ":6379"
	DefaultRedisPassword   = ""
	DefaultRedisExpireSecs = 600
)

// Config represents the configuration format for the server.
type Config struct {
	BindAddress string                            `toml:"bind-address"`
	URL         string                            `toml:"url"`
	IdP         idp.IdPConfig                     `toml:"idp"`
	Clients     client.OAuth20ClientMapFromConfig `toml:"client"`
	Redis       transientstorage.RedisConfig      `toml:"redis"`
}

// LoadConfig returns an instance of Config with reasonable defaults.
func LoadConfig(configPath string) (*Config, error) {
	config := &Config{
		BindAddress: DefaultBindAddress,
		URL:         DefaultURL,
		Redis: transientstorage.RedisConfig{
			DefaultRedisAddress,
			DefaultRedisPassword,
			DefaultRedisExpireSecs,
		},
	}
	if configPath == "" {
		log.Print("No configfile path given, using defaults")
	} else {
		if err := tomlToConfig(configPath, config); err != nil {
			return nil, err
		}
	}
	return config, nil
}

// tomlToConfig merges the toml file with our config.
func tomlToConfig(tomlPath string, config *Config) error {
	bs, err := ioutil.ReadFile(tomlPath)
	if err != nil {
		return err
	}
	_, err = toml.Decode(string(bs), config)
	return err
}
