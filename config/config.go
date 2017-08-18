package config

import (
	"io/ioutil"
	"log"

	"github.com/BurntSushi/toml"
)

const (
	DefaultBindAddress     = ":8080"
	DefaultHost            = "localhost:8080"
	DefaultRedisAddress    = ":6379"
	DefaultRedisPassword   = ""
	DefaultRedisExpireSecs = 600
)

// Config represents the configuration format for the server.
type Config struct {
	BindAddress string                  `toml:"bind-address"`
	Host        string                  `toml:"host"`
	IdP         map[string]interface{}  `toml:"idp"`
	Client      map[string]OAuth2Client `toml:"client"`
	Redis       Redis                   `toml:"redis"`
}

type OAuth2Client struct {
	Redirects []string `toml:"redirects"`
}

type Redis struct {
	Address    string `toml:"address"`
	Password   string `toml:"password"`
	ExpireSecs int    `toml:"expire_secs"`
}

// NewConfig returns an instance of Config with reasonable defaults.
func NewConfig(configPath string) (*Config, error) {
	config := &Config{
		BindAddress: DefaultBindAddress,
		Host:        DefaultHost,
		Redis: Redis{
			DefaultRedisAddress,
			DefaultRedisPassword,
			DefaultRedisExpireSecs,
		},
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
