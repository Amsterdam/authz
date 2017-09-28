// Command goauth2 runs Datapunt Amsterdam's OAuth 2 (RFC 6749) service.
package main

import (
	"context"
	"flag"
	"fmt"
	"log"
	"net/http"
	"net/http/pprof"
	"os"
	"os/signal"
	"strings"
	"syscall"
	"time"

	"github.com/amsterdam/goauth2/oauth20"
)

func main() {
	// Load and check configuration
	conf := conf()

	// Get options
	opts := options(conf)

	// Create handler
	oauthHandler, err := oauth20.Handler(conf.BaseURL, opts...)
	if err != nil {
		log.Fatal(err)
	}
	// ... wrap in middleware
	handler := &Handler{oauthHandler, conf}

	// Create server
	bindAddr := fmt.Sprintf("%s:%d", conf.BindHost, conf.BindPort)
	server := &http.Server{Addr: bindAddr, Handler: handler}

	// Shut down server if signal is received
	go func() {
		signalChan := make(chan os.Signal, 1)
		signal.Notify(signalChan, os.Interrupt, syscall.SIGTERM)
		<-signalChan
		server.Shutdown(context.Background())
		log.Print("INFO: Signal received, stopping service.")
	}()

	// Start the OAuth 2.0 server
	log.Printf("INFO: Starting service on %s.\n", bindAddr)
	if err := server.ListenAndServe(); err != http.ErrServerClosed {
		log.Printf("WARN: Error shutting down service: %v\n", err)
	} else {
		log.Println("INFO: Server stopped")
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
	// Check that base URL is set
	if conf.BaseURL == "" {
		log.Fatal("Must set base-url in config")
	}
	// Warn if profiler is enabled
	if conf.PprofEnabled {
		log.Println("WARN: Profiling should not be enbaled in production!")
	}
	return conf
}

func options(conf *config) []oauth20.Option {
	var options []oauth20.Option
	// IdP
	if (conf.IdP != idpConfig{}) {
		if idp, err := newDatapuntIdP(
			conf.IdP.BaseURL, conf.IdP.AccountsURL, []byte(conf.IdP.Secret), conf.IdP.APIKey,
		); err != nil {
			log.Fatal(err)
		} else {
			options = append(options, oauth20.IdProvider(idp))
		}
	} else {
		log.Fatal("Must configure an IdP")
	}
	// Clients
	if len(conf.Clients) == 0 {
		log.Fatal("Must configure at least one registered client")
	}
	options = append(options, oauth20.Clients(conf.Clients))
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
