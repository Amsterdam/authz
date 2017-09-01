package main

import (
	"io/ioutil"
	"log"

	"github.com/BurntSushi/toml"
	"github.com/DatapuntAmsterdam/goauth2/authz"
	"github.com/DatapuntAmsterdam/goauth2/client"
	"github.com/DatapuntAmsterdam/goauth2/idp"
	"github.com/DatapuntAmsterdam/goauth2/storage"
)

const (
	DefaultBindAddress = ":8080"
	DefaultURL         = "http://localhost:8080/goauth2"
)

// Config represents the configuration format for the server.
type Config struct {
	BindAddress  string                            `toml:"bind-address"`
	URL          string                            `toml:"url"`
	IdP          idp.Config                        `toml:"idp"`
	Client       client.OAuth20ClientMapFromConfig `toml:"client"`
	Authz        authz.Config                      `toml:"authorization"`
	Storage      storage.TransientConfig           `toml:"storage"`
	AcccessToken AccessTokenConfig                 `toml:"accesstoken"`
}

// AccessToken configuration
type AccessTokenConfig struct {
	Secret   string `toml:"secret"`
	Lifetime int    `toml:"lifetime"`
}

// LoadConfig returns an instance of Config with reasonable defaults.
func LoadConfig(configPath string) (*Config, error) {
	config := &Config{
		BindAddress: DefaultBindAddress,
		URL:         DefaultURL,
		Storage:     nil,
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
