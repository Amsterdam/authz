package server

import (
	"errors"
	"fmt"
	"log"
	"math/rand"
	"net"
	"net/http"
	"net/url"
	"strings"
	"sync"
	"time"
)

func init() {
	rand.Seed(time.Now().UTC().UnixNano())
}

type Server struct {
	baseURL  url.URL
	listener net.Listener
	bindAddr string

	// handler is saved so it can be inspected
	handler http.Handler

	// Components / interfaces
	accessTokenEnc *accessTokenEncoder

	// Lookups / interfaces
	stateStore *stateStorage
	authz      Authz
	authn      map[string]Authn
	clientMap  ClientMap

	// Concurrency control
	clientMutex sync.RWMutex
	once        sync.Once
	initialized bool
}

// Create a new Server.
func New(bindHost string, bindPort int, options ...Option) (*Server, error) {
	s := &Server{authn: make(map[string]Authn)}
	// First we set options
	for _, option := range options {
		if err := option(s); err != nil {
			return nil, err
		}
	}
	// Set default accesstoken config if not set
	if s.accessTokenEnc == nil {
		log.Println("WARN: accesstoken config missing, using random secret.")
		secret := make([]byte, 16)
		rand.Read(secret)
		s.accessTokenEnc = newAccessTokenEncoder(secret, 36000, "goauth2")
	}
	// Set default transient store if none given
	if s.stateStore == nil {
		log.Println("WARN: Using in-memory state storage")
		s.stateStore = newStateStorage(newStateMap(), 60*time.Second)
	}
	// Set default scopeset if no authz provider is given
	if s.authz == nil {
		log.Println("WARN: using empty scope set")
		s.authz = &emptyScopeSet{}
	}
	// Set default clientmap if no ClientMap is given
	if s.clientMap == nil {
		log.Println("WARN: using empty client map")
		s.clientMap = &emptyClientMap{}
	}
	// Set anonymous IdP if none is set
	if len(s.authn) == 0 {
		log.Println("WARN: no IdP registered")
	}
	// Options are done
	s.initialized = true

	// Save bindaddr
	s.bindAddr = fmt.Sprintf("%s:%d", bindHost, bindPort)

	// Set baseURL to http://localhost:[bindPort]/ if it isn't set
	if (s.baseURL == url.URL{}) {
		addr := fmt.Sprintf("http://localhost:%d/", bindPort)
		if u, err := url.Parse(addr); err != nil {
			log.Fatal(err)
		} else {
			s.baseURL = *u
		}
	}
	// Create handler
	if handler, err := s.oauth20handler(); err != nil {
		log.Fatal(err)
	} else {
		s.handler = handler
	}
	return s, nil
}

// Start() runs the server and reports errors. Ignores subsequent calls after
// the first.
func (s *Server) Start(errChan chan error) {
	s.once.Do(func() {
		// Create listener
		if listener, err := net.Listen("tcp", s.bindAddr); err != nil {
			errChan <- err
			return
		} else {
			s.listener = listener
		}
		// Start server
		err := http.Serve(s.listener, s.handler)
		if err != nil && !strings.Contains(err.Error(), "closed") {
			errChan <- err
		}
	})
}

// Handler() returns the server's handler
func (s *Server) Handler() http.Handler {
	return s.handler
}

// Close() closes the listener.
func (s *Server) Close() error {
	return s.listener.Close()
}

// oauth20handler() creates the request handler for the server.
func (s *Server) oauth20handler() (http.Handler, error) {
	mux := http.NewServeMux()
	idps := make(map[string]*idpHandler)
	baseHandler := &oauth20Handler{
		s.clientMap, s.authz, s.stateStore,
	}
	pathTempl := "authorize/%s"
	for idpId, authn := range s.authn {
		relPath := fmt.Sprintf(pathTempl, idpId)
		absPath := fmt.Sprintf("/%s", relPath)
		if u, err := s.baseURL.Parse(relPath); err != nil {
			return nil, err
		} else {
			handler := &idpHandler{baseHandler, authn, u, s.accessTokenEnc}
			mux.Handle(absPath, handler)
			idps[idpId] = handler
		}
	}
	// Create authorization handler
	authzHandler := &authorizationHandler{baseHandler, idps}
	mux.Handle("/authorize", authzHandler)
	return mux, nil
}

// Interface StateKeeper is implemented by storage engines and used to
// store transient state data throughout the server.
type StateKeeper interface {
	Persist(key string, data string, lifetime time.Duration) error
	Restore(key string) (string, error)
}

// Interface User is implemented by identity providers and used by
// authorization providers.
type User struct {
	// UID is the user identifier.
	UID string
	// Roles is a slice of roles associated with this user.
	Roles []string
}

// Interface Authn is implemented by identity providers.
type Authn interface {
	// AuthnRedirect(...) returns an authentication URL and optional serialized
	// state.
	AuthnRedirect(callbackURL *url.URL) (*url.URL, []byte, error)
	// User receives the IdP's callback request and returns a User object or
	// an error.
	User(r *http.Request, state []byte) (*User, error)
}

// The ScopeSet interface is implemented by authorization providers to allow
// membership tests on its total set of scopes.
type ScopeSet interface {
	// ValidScope() returns true if scope is a subset of this scopeset.
	ValidScope(scope ...string) bool
}

// The Authz interface is implemented by authorization providers to extract a
// user's authorized scopeset and the full scopeset supported by the provider.
type Authz interface {
	ScopeSet
	// ScopeSetFor() returns the given user's authorized scopeset.
	ScopeSetFor(u *User) ScopeSet
}

// The Client type contains all data needed for OAuth 2.0 clients.
type Client struct {
	// Client identifier
	Id string
	// list of registered redirects
	Redirects []string
	// client secret
	Secret string
	// Allowed grants (implicit, authz code, client credentials)
	GrantType string
}

// The ClientMap interface is implemented for OAuth 2.0 clients and used to
// authenticate and validate client data provided in all authorization flows.
type ClientMap interface {
	// Returns the client for this identifier or an error
	Get(id string) (*Client, error)
}

// An option is a server option that can be passed to New().
type Option func(*Server) error

// BaseURL() is an option that sets the given URL as the base URL of the
// service. This is useful if the external address of the service is different
// from its bind address (so basically in any environment apart from in
// development).
func BaseURL(u url.URL) Option {
	return func(s *Server) error {
		if s.initialized {
			return errors.New("Given server already initialized")
		}
		s.baseURL = u
		return nil
	}
}

// StateStorage() is an option that sets the transient storage for the server
// instance.
func StateStorage(engine StateKeeper, lifetime time.Duration) Option {
	return func(s *Server) error {
		if s.initialized {
			return errors.New("Given server already initialized")
		}
		s.stateStore = newStateStorage(engine, lifetime)
		return nil
	}
}

// Clients() is an option that sets the given client mapping for the server
// instance.
func Clients(m ClientMap) Option {
	return func(s *Server) error {
		if s.initialized {
			return errors.New("Given server already initialized")
		}
		s.clientMap = m
		return nil
	}
}

// AuthzProvider() is an option that sets the given authorization provider for
// the server instance.
func AuthzProvider(p Authz) Option {
	return func(s *Server) error {
		if s.initialized {
			return errors.New("Given server already initialized")
		}
		s.authz = p
		return nil
	}
}

// AccessTokenConfig() is an option that configures access token JWTs.
func AccessTokenConfig(secret []byte, lifetime int64, issuer string) Option {
	return func(s *Server) error {
		if s.initialized {
			return errors.New("Can only call SetAccessTokenConfig as an option to New(...)")
		}
		s.accessTokenEnc = newAccessTokenEncoder(secret, lifetime, issuer)
		return nil
	}
}

// IdP is an option that adds the given IdP to this server. If the IdP was
// already registered it will be silently overwritten.
func IdP(id string, a Authn) Option {
	return func(s *Server) error {
		if s.initialized {
			return errors.New("Can only call RegisterIdP as an option to New(...)")
		}
		s.authn[id] = a
		return nil
	}
}
