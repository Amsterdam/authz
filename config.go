package main

import (
	"errors"
	"github.com/BurntSushi/toml"
	"github.com/amsterdam/authz/oauth2"
	"io/ioutil"
	"regexp"
)

const (
	defaultBindHost            = ""
	defaultBindPort            = 8080
	defaultAuthnTimeout        = 600
	defaultAuthzUpdateInterval = 60
)

// Config represents the configuration format for the server.
type config struct {
	BindHost     string            `toml:"bind-host"`
	BindPort     int               `toml:"bind-port"`
	BaseURL      string            `toml:"base-url"`
	PprofEnabled bool              `toml:"pprof-enabled"`
	AuthnTimeout int               `toml:"authn-timeout"`
	TraceHeader  string            `toml:"trace-header-name"`
	LogJSON      bool              `toml:"log-json-output"`
	Roles        rolesConfig       `toml:"roles"`
	DatapuntIDP  datapuntIDPConfig `toml:"idp-datapunt"`
	GoogleIDP    googleIDPConfig   `toml:"idp-google"`
	GripIDP      gripIDPConfig     `toml:"idp-grip"`
	Clients      clientMap         `toml:"clients"`
	Authz        authzConfig       `toml:"authorization"`
	Redis        redisConfig       `toml:"redis"`
	Accesstoken  accessTokenConfig `toml:"accesstoken"`
}

// accessToken configuration
type accessTokenConfig struct {
	JWKS     string `toml:"jwk-set"`
	KID      string `toml:"jwk-id"`
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
	BaseURL        string `toml:"base-url"`
	UpdateInterval int    `toml:"update-interval"`
}

// Datapunt user roles config
type rolesConfig struct {
	AccountsURL string `toml:"accounts-url"`
	APIKey      string `toml:"api-key"`
}

// DatapuntIDPConfig contains DP IdP config
type datapuntIDPConfig struct {
	BaseURL string `toml:"base-url"`
	Secret  string `toml:"secret"`
}

// GoogleIDPConfig contains Google IdP config
type googleIDPConfig struct {
	ClientID     string `toml:"client-id"`
	ClientSecret string `toml:"client-secret"`
}

type gripIDPConfig struct {
	TenantID     string `toml:"tenant-id"`
	ClientID     string `toml:"client-id"`
	ClientSecret string `toml:"client-secret"`
}

// Client configuration
type clientConfig struct {
	Redirects               []string `toml:"redirects"`
	RedirectRegexps         []string `toml:"redirect-regexps"`
	CompiledRedirectRegexps []*regexp.Regexp
	Secret                  string `toml:"secret"`
	GrantType               string `toml:"granttype"`
}

// Client lookup
type clientMap map[string]clientConfig

// Implements oauth2.ClientMap
func (m clientMap) Get(id string) (*oauth2.Client, error) {
	if c, ok := m[id]; ok {
		return &oauth2.Client{
			ID:                      id,
			Redirects:               c.Redirects,
			RedirectRegexps: c.CompiledRedirectRegexps,
			Secret:                  c.Secret,
			GrantType:               c.GrantType,
		}, nil
	}
	return nil, errors.New("Unknown client id")
}

// loadConfig returns an instance of Config with reasonable defaults.
func loadConfig(configPath string) (*config, error) {
	config := &config{
		BindHost:     defaultBindHost,
		BindPort:     defaultBindPort,
		AuthnTimeout: defaultAuthnTimeout,
	}
	if configPath != "" {
		if err := tomlToConfig(configPath, config); err != nil {
			return nil, err
		}
	}
	if config.Authz.UpdateInterval == 0 {
		config.Authz.UpdateInterval = defaultAuthzUpdateInterval
	}
	// Check if all regular expressions are valid:
	for _, c := range config.Clients {
		c.CompiledRedirectRegexps = make([]*regexp.Regexp, len(c.RedirectRegexps))
		for i, r := range c.RedirectRegexps {
			c.CompiledRedirectRegexps[i] = regexp.MustCompile(r)
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
