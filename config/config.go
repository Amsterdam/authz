package config

import (
	"io/ioutil"
	"log"

	"github.com/BurntSushi/toml"
)

const (
	// DefaultBindAddress is the default address for the HTTP server.
	DefaultBindAddress = ":8080"
)

// Config represents the configuration format for the server.
type Config struct {
	BindAddress string                  `toml:"bind-address"`
	IdP         map[string]interface{}  `toml:"idp"`
	Client      map[string]OAuth2Client `toml:"client"`
}

type OAuth2Client struct {
	Redirects []string `toml:"redirects"`
}

// NewConfig returns an instance of Config with reasonable defaults.
func NewConfig(configPath string) (*Config, error) {
	config := &Config{
		BindAddress: DefaultBindAddress,
	}
	if configPath == "" {
		log.Print("No configfile path given, using defaults")
	} else {
		if err := config.fromTomlFile(configPath); err != nil {
			return nil, err
		}
	}
	return config, nil
}

// FromTomlFile loads the config from a TOML file.
func (c *Config) fromTomlFile(fpath string) error {
	bs, err := ioutil.ReadFile(fpath)
	if err != nil {
		return err
	}
	return c.fromToml(string(bs))
}

// FromToml loads the config from TOML.
func (c *Config) fromToml(input string) error {
	_, err := toml.Decode(input, c)
	return err
}
