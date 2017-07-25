package main

import (
	"fmt"
	"log"
	"net"
	"net/http"
	"strings"
)

// Service manages the listener and handler for an HTTP endpoint.
type Service struct {
	ln      net.Listener
	addr    string
	Err     chan error
	handler *Handler
}

// NewService returns a new instance of Service.
func NewService(c *Config) *Service {
	s := &Service{
		addr:    c.BindAddress,
		Err:     make(chan error),
		handler: NewHandler(c),
	}
	return s
}

// Open starts the service.
func (s *Service) Open() error {
	log.Print("Starting HTTP service")
	listener, err := net.Listen("tcp", s.addr)
	if err != nil {
		return err
	}
	log.Printf("Listening on HTTP: %s", listener.Addr().String())
	s.ln = listener

	// Begin listening for requests in a separate goroutine.
	go s.serve()
	return nil
}

// Close closes the underlying listener.
func (s *Service) Close() error {
	if s.ln != nil {
		if err := s.ln.Close(); err != nil {
			return err
		}
		log.Print("Listener closed.")
	}
	return nil
}

// serve serves the handler from the listener.
func (s *Service) serve() {
	// The listener was closed so exit
	// See https://github.com/golang/go/issues/4373
	err := http.Serve(s.ln, s.handler)
	if err != nil && !strings.Contains(err.Error(), "closed") {
		s.Err <- fmt.Errorf("listener failed: addr=%s, err=%s", s.ln.Addr(), err)
	}
}
