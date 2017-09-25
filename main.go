// Command goauth2 runs Datapunt Amsterdam's OAuth 2 (RFC 6749) service.
package main

import (
	"flag"
	"fmt"
	"log"
	"net"
	"net/http"
	"net/url"
	"os"
	"os/signal"
	"strings"
	"syscall"
	"time"

	"github.com/amsterdam/goauth2/server"
)

func main() {
	// Load configuration
	conf := conf()
	// Get options
	opts := options(conf)
	// Create handler
	handler, err := oauth20.Handler(baseURL(), opts...)
	if err != nil {
		log.Fatal(err)
	}
	// Create listener
	bindAddr := fmt.Sprintf("%s:%d", conf.BindHost, conf.BindPort)
	listener, err := net.Listen("tcp", bindAddr)
	if err != nil {
		log.Fatal(err)
	}
	defer listener.Close()
	// Create error and signal channels
	errorChan := make(chan error)
	signalChan := make(chan os.Signal, 1)
	// Register signals
	signal.Notify(signalChan, os.Interrupt, syscall.SIGTERM)
	// Start the OAuth 2.0 server
	go start(errorChan, listener, handler)
	defer srvr.Close()
	// Block until one of the signals above is received
	log.Printf("INFO: Service started on %s.\n", bindAddr)
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

// Start() runs the server and reports errors. Ignores subsequent calls after
// the first.
func start(errChan chan error, listener net.Listener, handler http.Handler) {
	// Start server
	err := http.Serve(listener, handler)
	if err != nil && !strings.Contains(err.Error(), "closed") {
		errChan <- err
	}
}

func baseURL(conf *config) *url.URL {
	// Check base url
	var bu string
	if conf.BaseURL != "" {
		bu = conf.BaseURL
	} else {
		bu = fmt.Sprintf("%s:%d", conf.BindHost, conf.BindPort)
	}
	if u, err := url.Parse(bu); err != nil {
		log.Fatal(err)
	} else {
		return u
	}
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

	// Check IdP provider
	if (conf.IdP != idpConfig{}) {
		if idp, err := newDatapuntIdP(
			conf.IdP.BaseURL, conf.IdP.AccountsURL, []byte(conf.IdP.Secret), conf.IdP.APIKey,
		); err != nil {
			log.Fatal(err)
		} else {
			options = append(options, server.IdProvider("datapunt", idp))
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
		engine := newRedisStorage(conf.Redis.Address, conf.Redis.Password)
		timeout := time.Duration(conf.AuthnTimeout) * time.Second
		options = append(options, server.StateStorage(engine, timeout))
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
