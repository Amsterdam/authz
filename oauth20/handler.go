package oauth20

import (
	"fmt"
	"log"
	"math/rand"
	"net/http"
	"net/http/pprof"
	"net/url"
	"sync"
	"time"
)

func init() {
	rand.Seed(time.Now().UTC().UnixNano())
}

type oauth20Handler struct {
	baseURL url.URL

	// Components / interfaces
	accessTokenEnc *accessTokenEncoder
	stateStore     *stateStorage
	authz          Authz
	idps           map[string]IdP
	clientMap      ClientMap

	// Concurrency control
	clientMutex sync.RWMutex
}

// Handler() returns an http.Handler that handles OAuth 2.0 requests.
func Handler(baseURL *url.URL, options ...Option) (http.Handler, error) {
	s := &oauth20Handler{
		baseURL: *baseURL,
		idps:    make(map[string]IdP),
	}
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
	// Warn if none is set
	if len(s.idps) == 0 {
		log.Println("WARN: no IdP registered")
	}

	return s.handler()
}

// oauth20handler() creates the request handler for the handler.
func (s *oauth20Handler) handler() (http.Handler, error) {
	mux := http.NewServeMux()
	idps := make(map[string]*idpHandler)
	baseHandler := &oauth20Handler{
		s.clientMap, s.authz, s.stateStore,
	}
	pathTempl := "authorize/%s"
	for idpId, idp := range s.idps {
		relPath := fmt.Sprintf(pathTempl, idpId)
		absPath := fmt.Sprintf("/%s", relPath)
		if u, err := s.baseURL.Parse(relPath); err != nil {
			return nil, err
		} else {
			handler := &idpHandler{baseHandler, idp, u, s.accessTokenEnc}
			mux.Handle(absPath, handler)
			idps[idpId] = handler
		}
	}
	// Create authorization handler
	authzHandler := &authorizationHandler{baseHandler, idps}
	mux.Handle("/authorize", authzHandler)
	// Register profile paths
	mux.Handle("/debug/pprof/", http.HandlerFunc(pprof.Index))
	mux.Handle("/debug/pprof/cmdline", http.HandlerFunc(pprof.Cmdline))
	mux.Handle("/debug/pprof/profile", http.HandlerFunc(pprof.Profile))
	mux.Handle("/debug/pprof/symbol", http.HandlerFunc(pprof.Symbol))
	return mux, nil
}

// Interface StateKeeper is implemented by storage engines and used to
// store transient state data throughout the handler.
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

// Interface IdP is implemented by identity providers.
type IdP interface {
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

// An option is a handler option that can be passed to New().
type Option func(*oauth20Handler) error

// StateStorage() is an option that sets the transient storage for the handler
// instance.
func StateStorage(engine StateKeeper, lifetime time.Duration) Option {
	return func(s *oauth20Handler) error {
		s.stateStore = newStateStorage(engine, lifetime)
		return nil
	}
}

// Clients() is an option that sets the given client mapping for the handler
// instance.
func Clients(m ClientMap) Option {
	return func(s *oauth20Handler) error {
		s.clientMap = m
		return nil
	}
}

// AuthzProvider() is an option that sets the given authorization provider for
// the handler instance.
func AuthzProvider(p Authz) Option {
	return func(s *oauth20Handler) error {
		s.authz = p
		return nil
	}
}

// AccessTokenConfig() is an option that configures access token JWTs.
func AccessTokenConfig(secret []byte, lifetime int64, issuer string) Option {
	return func(s *oauth20Handler) error {
		s.accessTokenEnc = newAccessTokenEncoder(secret, lifetime, issuer)
		return nil
	}
}

// IdProvider is an option that adds the given IdP to this handler. If the IdP was
// already registered it will be silently overwritten.
func IdProvider(id string, a IdP) Option {
	return func(s *oauth20Handler) error {
		s.idps[id] = a
		return nil
	}
}
