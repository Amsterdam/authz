// Command goauth2 runs Datapunt Amsterdam's OAuth 2 (RFC 6749) service.
package main

import (
	"flag"
	"log"
	"net/url"
	"os"
	"os/signal"
	"syscall"

	"github.com/DatapuntAmsterdam/goauth2/server"
)

func main() {
	// Load configuration
	conf := conf()
	// Create server options
	options := options(conf)
	// Create server
	srvr, err := server.New(options...)
	if err != nil {
		log.Fatal(err)
	}
	// Create error and signal channels
	errorChan := make(chan error)
	signalChan := make(chan os.Signal, 1)
	// Register signals
	signal.Notify(signalChan, os.Interrupt, syscall.SIGTERM)
	// Start the OAuth 2.0 server
	go srvr.Start(conf.BindAddress, errorChan)
	defer srvr.Close()
	// Block until one of the signals above is received
	log.Printf("INFO: Service started on %s.\n", conf.BindAddress)
	for {
		select {
		case err := <-errorChan:
			log.Print(err)
		case <-signalChan:
			log.Print("INFO: Signal received, shutting down.")
			return
		}
	}
	// Done. Stopping.
	log.Print("INFO: Service stopped")
}

// configuration returns the service configuration
func conf() *config {
	var configPath = flag.String("config", "", "Path to a configuration file.")
	flag.Parse()
	conf, err := LoadConfig(*configPath)
	if err != nil {
		log.Fatal(err)
	}
	return conf
}

func options(conf *config) []server.Option {
	var options []server.Option
	// Check base url
	if conf.BaseURL != "" {
		if u, err := url.Parse(conf.BaseURL); err != nil {
			log.Fatal(err)
		} else {
			options = append(options, server.BaseURL(*u))
		}
	}
	// Check authentication provider
	if (conf.Authn != authnConfig{}) {
		if idp, err := newDatapuntIdP(
			conf.Authn.BaseURL, conf.Authn.AccountsURL, conf.Authn.Secret,
		); err != nil {
			log.Fatal(err)
		} else {
			options = append(options, server.IdP("datapunt", idp))
		}
	}
	// Check authorization provider
	if (conf.Authz != authzConfig{}) {
		if authz, err := newDatapuntAuthz(conf.Authz.BaseURL); err != nil {
			log.Fatal(err)
		} else {
			options = append(options, server.AuthzProvider(authz))
		}
	}
	// Check storage provider
	if (conf.Redis != redisConfig{}) {
		r := newRedisStorage(conf.Redis.Address, conf.Redis.Password)
		options = append(options, server.Storage(r))
	}
	// Add all configured clients
	options = append(options, server.Clients(conf.Clients))
	// Add access token config
	if (conf.Accesstoken != accessTokenConfig{}) {
		a := server.AccessTokenConfig(
			[]byte(conf.Accesstoken.Secret),
			conf.Accesstoken.Lifetime,
			conf.Accesstoken.Issuer,
		)
		options = append(options, a)
	}
	return options
}
