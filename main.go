// Command goauth2 runs Datapunt Amsterdam's OAuth 2 (RFC 6749) service.
package main

import (
	"flag"
	"fmt"
	"log"
	"net"
	"net/http"
	"net/http/pprof"
	"net/url"
	"os"
	"os/signal"
	"strings"
	"syscall"
	"time"

	"github.com/amsterdam/goauth2/oauth20"
)

func main() {
	// Load configuration
	conf := conf()
	// Get options
	opts := options(conf)
	// Check that base URL is set
	if conf.BaseURL == "" {
		log.Fatal("Must set base-url in config")
	}
	baseURL, err := url.Parse(conf.BaseURL)
	if err != nil {
		log.Fatalf("Invalid base-url: %s", err)
	}
	// Create handler
	oauthHandler, err := oauth20.Handler(baseURL, opts...)
	if err != nil {
		log.Fatal(err)
	}
	handler := &Handler{oauthHandler, conf}
	// Warn if profiler is enabled
	if conf.PprofEnabled {
		log.Println("WARN: Profiling should not be enbaled in production!")
	}
	// Create listener
	bindAddr := fmt.Sprintf("%s:%d", conf.BindHost, conf.BindPort)
	listener, err := net.Listen("tcp", bindAddr)
	if err != nil {
		log.Fatalf("Couldn't bind listener: %s", err)
	}
	defer listener.Close()
	// Create error and signal channels
	errorChan := make(chan error)
	signalChan := make(chan os.Signal, 1)
	// Register signals
	signal.Notify(signalChan, os.Interrupt, syscall.SIGTERM)
	// Start the OAuth 2.0 server
	go start(errorChan, listener, handler)
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

func options(conf *config) []oauth20.Option {
	var options []oauth20.Option

	/////////////////////
	// REQUIRED OPTIONS
	/////////////////////

	// IdP
	if (conf.IdP != idpConfig{}) {
		if idp, err := newDatapuntIdP(
			conf.IdP.BaseURL, conf.IdP.AccountsURL, []byte(conf.IdP.Secret), conf.IdP.APIKey,
		); err != nil {
			log.Fatal(err)
		} else {
			options = append(options, oauth20.IdProvider("datapunt", idp))
		}
	} else {
		log.Fatal("Must configure an IdP")
	}
	// Clients
	if len(conf.Clients) == 0 {
		log.Fatal("Must configure at least one registered client")
	}
	options = append(options, oauth20.Clients(conf.Clients))

	////////////////////////
	// OPTIONAL OPTIONS
	////////////////////////

	// Access token config
	if (conf.Accesstoken != accessTokenConfig{}) {
		a := oauth20.AccessTokenConfig(
			[]byte(conf.Accesstoken.Secret),
			conf.Accesstoken.Lifetime,
			conf.Accesstoken.Issuer,
		)
		options = append(options, a)
	}
	// Authorization provider
	if (conf.Authz != authzConfig{}) {
		if authz, err := newDatapuntAuthz(conf.Authz.BaseURL); err != nil {
			log.Fatal(err)
		} else {
			options = append(options, oauth20.AuthzProvider(authz))
		}
	}
	// Storage provider
	if (conf.Redis != redisConfig{}) {
		engine := newRedisStorage(conf.Redis.Address, conf.Redis.Password)
		timeout := time.Duration(conf.AuthnTimeout) * time.Second
		options = append(options, oauth20.StateStorage(engine, timeout))
	}
	return options
}

type Handler struct {
	http.Handler
	Config *config
}

func (h *Handler) ServeHTTP(w http.ResponseWriter, r *http.Request) {
	if strings.HasPrefix(r.URL.Path, "/debug/pprof") && h.Config.PprofEnabled {
		h.handleProfiles(w, r)
	} else if r.URL.Path == "/ping" {
		h.servePing(w, r)
	} else {
		h.Handler.ServeHTTP(w, r)
	}
}

// handleProfiles determines which profile to return to the requester.
func (h *Handler) handleProfiles(w http.ResponseWriter, r *http.Request) {
	switch r.URL.Path {
	case "/debug/pprof/cmdline":
		pprof.Cmdline(w, r)
	case "/debug/pprof/profile":
		pprof.Profile(w, r)
	case "/debug/pprof/symbol":
		pprof.Symbol(w, r)
	default:
		pprof.Index(w, r)
	}
}

// servePing returns a simple response to let the client know the server is running.
func (h *Handler) servePing(w http.ResponseWriter, r *http.Request) {
	w.WriteHeader(http.StatusNoContent)
}
