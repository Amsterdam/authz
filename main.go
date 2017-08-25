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

	"github.com/DatapuntAmsterdam/goauth2/handler"
	"github.com/DatapuntAmsterdam/goauth2/idp"
	"github.com/DatapuntAmsterdam/goauth2/storage"
)

func main() {
	// Load configuration
	config := config()
	// Create error and signal channels
	errorChan := make(chan error)
	signalChan := make(chan os.Signal, 1)
	// Start the OAuth 2.0 server
	go serveOAuth20(config, errorChan)
	// Register signals
	signal.Notify(signalChan, os.Interrupt, syscall.SIGTERM)
	// Block until one of the signals above is received
	log.Print("Service started.")
	for {
		select {
		case err := <-errorChan:
			log.Print(err)
		case <-signalChan:
			log.Print("Signal received, shutting down.")
			return
		}
	}
	// Done. Stopping.
	log.Print("Service stopped")
}

// configuration returns the service configuration
func config() *Config {
	var configPath = flag.String("config", "", "Path to a configuration file.")
	flag.Parse()
	config, err := LoadConfig(*configPath)
	if err != nil {
		log.Fatal(err)
	}
	return config
}

// serveOAuth20 creates a TCP listener and the http.Handler and starts the HTTP server.
func serveOAuth20(config *Config, errCh chan error) {
	handler := oauth20Handler(config)
	listener := listener(config)
	defer listener.Close()
	err := http.Serve(listener, handler)
	if err != nil && !strings.Contains(err.Error(), "closed") {
		errCh <- fmt.Errorf("listener failed: addr=%s, err=%s", listener.Addr(), err)
	}
}

// oauth20Handler creates a http.Handler and registers all resource / method handlers.
func oauth20Handler(config *Config) http.Handler {
	// Parse base URL
	baseURL, err := url.Parse(config.URL)
	if err != nil {
		log.Fatal(err)
	}
	// Create Redis Storage
	redisStore := storage.NewRedisStorage(&config.Redis)
	// Create the IdP map
	idps, err := idp.Load(config.IdP)
	if err != nil {
		log.Fatal(err)
	}
	// Clients
	clients := config.Clients
	// Create OAuth 2.0 resource handlers
	oauth20Handler, err := handler.NewOAuth20Handler(baseURL, clients, idps, redisStore)
	if err != nil {
		log.Fatal(err)
	}
	return oauth20Handler
}

// listener creates a net.Listener.
func listener(config *Config) net.Listener {
	listener, err := net.Listen("tcp", config.BindAddress)
	if err != nil {
		log.Fatal(err)
	}
	log.Printf("Listening on %s", config.BindAddress)
	return listener
}
