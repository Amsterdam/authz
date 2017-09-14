package main

import (
	"errors"
	"io/ioutil"
	"log"

	"github.com/BurntSushi/toml"
	"github.com/DatapuntAmsterdam/goauth2/server"
)

const (
	defaultBindHost     = ""
	defaultBindPort     = 8080
	defaultAuthnTimeout = 600
)

// Config represents the configuration format for the server.
type config struct {
	BindHost     string            `toml:"bind-host"`
	BindPort     int               `toml:"bind-port"`
	BaseURL      string            `toml:"base-url"`
	AuthnTimeout int               `toml:"authn-timeout"`
	Authn        authnConfig       `toml:"authentication"`
	Clients      clientMap         `toml:"clients"`
	Authz        authzConfig       `toml:"authorization"`
	Redis        redisConfig       `toml:"redis"`
	Accesstoken  accessTokenConfig `toml:"accesstoken"`
}

// accessToken configuration
type accessTokenConfig struct {
	Secret   string `toml"secret"`
	Lifetime int64  `toml:"lifetime"`
	Issuer   string `toml:"issuer"`
}

// Redis configuration
type redisConfig struct {
	Address  string `toml:"address"`
	Password string `toml:"password"`
}

// Datapunt authorization config
type authzConfig struct {
	BaseURL string `toml:"base-url"`
}

// Datapunt authentication config
type authnConfig struct {
	BaseURL     string `toml:"base-url"`
	AccountsURL string `toml:"accounts-url"`
	Secret      string `toml:"secret"`
}

// Client configuration
type clientConfig struct {
	Redirects []string `toml:"redirects"`
	Secret    string   `toml:"secret"`
	GrantType string   `toml:"granttype"`
}

// Client lookup
type clientMap map[string]clientConfig

// Implements server.ClientMap
func (m clientMap) Get(id string) (*server.Client, error) {
	if c, ok := m[id]; ok {
		return &server.Client{
			Id: id, Redirects: c.Redirects, Secret: c.Secret, GrantType: c.GrantType,
		}, nil
	}
	return nil, errors.New("Unknown client id")
}

// LoadConfig returns an instance of Config with reasonable defaults.
func LoadConfig(configPath string) (*config, error) {
	config := &config{
		BindHost:     defaultBindHost,
		BindPort:     defaultBindPort,
		AuthnTimeout: defaultAuthnTimeout,
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
func tomlToConfig(tomlPath string, config *config) error {
	bs, err := ioutil.ReadFile(tomlPath)
	if err != nil {
		return err
	}
	_, err = toml.Decode(string(bs), config)
	return err
}
