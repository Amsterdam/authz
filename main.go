package main

import (
	"flag"
	"log"
	"os"
	"os/signal"
	"syscall"
)

func main() {
	var configPath string
	flag.StringVar(&configPath, "config", "", "Path to the configuration file")
	flag.Parse()
	config := config(configPath)
	runService(config)
	log.Print("Service stopped")
}

func runService(config *Config) {
	service := NewService(config)
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

func config(configPath string) *Config {
	config := NewConfig()
	if configPath == "" {
		log.Print("No config given, using default configuration file")
	} else {
		if err := config.FromTomlFile(configPath); err != nil {
			log.Fatal(err)
		}
	}
	return config
}
