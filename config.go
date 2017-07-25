package main

import (
	"io/ioutil"

	"github.com/BurntSushi/toml"
)

const (
	// DefaultBindAddress is the default address for the HTTP server.
	DefaultBindAddress = "127.0.0.1:8080"
)

// Config represents the configuration format for the server.
type Config struct {
	BindAddress string `toml:"bind-address"`
}

// NewConfig returns an instance of Config with reasonable defaults.
func NewConfig() *Config {
	return &Config{
		BindAddress: DefaultBindAddress,
	}
}

// FromTomlFile loads the config from a TOML file.
func (c *Config) FromTomlFile(fpath string) error {
	bs, err := ioutil.ReadFile(fpath)
	if err != nil {
		return err
	}
	return c.FromToml(string(bs))
}

// FromToml loads the config from TOML.
func (c *Config) FromToml(input string) error {
	_, err := toml.Decode(input, c)
	return err
}
