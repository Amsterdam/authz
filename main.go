// Command goauth2 runs Datapunt Amsterdam's OAuth 2 (RFC 6749) service.
package main

import (
	"flag"
	"log"
	"os"
	"os/signal"
	"syscall"

	"github.com/DatapuntAmsterdam/goauth2/config"
	"github.com/DatapuntAmsterdam/goauth2/service"
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
	oauth2, err := service.NewOAuth2(config)
	if err != nil {
		log.Fatal(err)
	}
	service := service.NewService(config.BindAddress, oauth2.Handler)
	if err := service.Open(); err != nil {
		log.Fatal(err)
	}
	defer service.Close()
	// Create signal channel
	signalChan := make(chan os.Signal, 1)
	signal.Notify(signalChan, os.Interrupt, syscall.SIGTERM)
	// Block until one of the signals above is received
	log.Print("Service started, waiting for signals.")
	for {
		select {
		case err := <-service.Err:
			log.Print(err)
		case <-signalChan:
			log.Print("Signal received, shutting down.")
			return
		}
	}
}
