// Command goauth2 runs Datapunt Amsterdam's OAuth 2 (RFC 6749) service.
package main

import (
	"flag"
	"log"
	"os"
	"os/signal"
	"syscall"

	"github.com/DatapuntAmsterdam/goauth2/service"
)

func main() {
	var bindAddress = flag.String(
		"bind", "127.0.0.1:8080", "Bind the service to this address.")
	flag.Parse()
	runService(bindAddress)
	log.Print("Service stopped")
}

// runService is starts the service and shuts it down when sigterm or sigint
// is received.
func runService(bindAddress *string) {
	oauth2 := service.NewOAuth2()
	service := service.NewService(bindAddress, oauth2.Handler)
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
