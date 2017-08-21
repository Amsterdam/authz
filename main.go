// Command goauth2 runs Datapunt Amsterdam's OAuth 2 (RFC 6749) service.
package main

import (
	"flag"
	"fmt"
	"log"
	"net"
	"net/http"
	"os"
	"os/signal"
	"strings"
	"syscall"

	"github.com/DatapuntAmsterdam/goauth2/config"
	"github.com/bmizerany/pat"
)

func main() {
	var configPath = flag.String("config", "", "Path to a configuration file.")
	flag.Parse()
	config, err := config.NewConfig(*configPath)
	if err != nil {
		log.Fatal(err)
	}
	runService(config)
	log.Print("Service stopped")
}

// runService is starts the service and shuts it down when sigterm or sigint
// is received.
func runService(config *config.Config) {
	// Create error and signal channels
	errorChan := make(chan error)
	signalChan := make(chan os.Signal, 1)
	// Start the OAuth 2.0 server
	go ServeOAuth20(config, errorChan)
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
}

func ServeOAuth20(config *config.Config, errCh chan error) {
	handler := OAuth2Handler(config)
	listener := Listener(config)
	defer listener.Close()
	err := http.Serve(listener, handler)
	if err != nil && !strings.Contains(err.Error(), "closed") {
		errCh <- fmt.Errorf("listener failed: addr=%s, err=%s", listener.Addr(), err)
	}
}

func OAuth2Handler(config *config.Config) http.Handler {
	oauth2, err := NewOAuth2(config)
	if err != nil {
		log.Fatal(err)
	}
	handler := pat.New()
	handler.Add("GET", "/oauth2/authorize", http.HandlerFunc(oauth2.AuthorizationRequest))
	return handler
}

func Listener(config *config.Config) net.Listener {
	listener, err := net.Listen("tcp", config.BindAddress)
	if err != nil {
		log.Fatal(err)
	}
	log.Printf("Listening on %s", config.BindAddress)
	return listener
}
