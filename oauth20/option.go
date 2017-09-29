package oauth20

import (
	"errors"
	"fmt"
	"net/http"
	"net/url"
	"sync"
	"time"
)

// Option is a handler settings that can be passed to Handler().
type Option func(*oauth20Handler) error

// StateStorage is an option that sets the transient storage for the handler
// instance.
func StateStorage(engine StateKeeper, lifetime time.Duration) Option {
	return func(s *oauth20Handler) error {
		s.stateStore = newStateStorage(engine, lifetime)
		return nil
	}
}

// Clients is an option that sets the given client mapping for the handler
// instance.
func Clients(m ClientMap) Option {
	return func(s *oauth20Handler) error {
		s.clientMap = m
		return nil
	}
}

// AuthzProvider is an option that sets the given authorization provider for
// the handler instance.
func AuthzProvider(p Authz) Option {
	return func(s *oauth20Handler) error {
		s.authz = p
		return nil
	}
}

// AccessTokenConfig is an option that configures access token JWTs.
func AccessTokenConfig(secret []byte, lifetime int64, issuer string) Option {
	return func(s *oauth20Handler) error {
		s.accessTokenEnc = newAccessTokenEncoder(secret, lifetime, issuer)
		return nil
	}
}

// IdProvider is an option that adds the given IdP to this handler. If the IdP was
// already registered it will be silently overwritten.
func IDProvider(i IDP) Option {
	return func(s *oauth20Handler) error {
		s.idps[i.ID()] = i
		return nil
	}
}

// StateKeeper defines a storage engine used to store transient state data
// throughout the handler.
type StateKeeper interface {
	Persist(key string, data string, lifetime time.Duration) error
	Restore(key string) (string, error)
}

// User defines a user
type User struct {
	// UID is the user identifier.
	UID string
	// Roles is a slice of roles associated with this user.
	Roles []string
}

// IDP defines an identity provider.
type IDP interface {
	// ID returns the IDP's identifier
	ID() string
	// AuthnRedirect(...) returns an authentication URL and optional serialized
	// state.
	AuthnRedirect(callbackURL *url.URL) (*url.URL, []byte, error)
	// User receives the IDP's callback request and returns a User object or
	// an error.
	User(r *http.Request, state []byte) (*User, error)
}

// ScopeSet defines a set of scopes.
type ScopeSet interface {
	// ValidScope() returns true if scope is a subset of this scopeset.
	ValidScope(scope ...string) bool
}

// Authz contains an authorization provider's scopes and can map a user on scopes.
type Authz interface {
	ScopeSet
	// ScopeSetFor() returns the given user's authorized scopeset.
	ScopeSetFor(u *User) ScopeSet
}

// Client contains all data needed for OAuth 2.0 clients.
type Client struct {
	// Client identifier
	ID string
	// list of registered redirects
	Redirects []string
	// client secret
	Secret string
	// Allowed grants (implicit, authz code, client credentials)
	GrantType string
}

// ClientMap defines OAuth 2.0 clients.
type ClientMap interface {
	// Returns the client for this identifier or an error
	Get(id string) (*Client, error)
}

// stateMap is the default StateKeeper
type stateMap struct {
	values   map[string]string
	expiries map[string]time.Time
	mutex    sync.Mutex
}

func newStateMap() *stateMap {
	return &stateMap{
		values:   make(map[string]string),
		expiries: make(map[string]time.Time),
	}
}

func (s *stateMap) Persist(key string, value string, lifetime time.Duration) error {
	s.mutex.Lock()
	defer s.mutex.Unlock()
	exp := time.Now().Add(lifetime)
	s.values[key] = value
	s.expiries[key] = exp
	return nil
}

func (s *stateMap) Restore(key string) (string, error) {
	s.mutex.Lock()
	defer s.mutex.Unlock()
	val, valOk := s.values[key]
	exp, expOk := s.expiries[key]
	if expOk {
		delete(s.expiries, key)
	}
	if valOk {
		delete(s.values, key)
	}
	if !valOk || !expOk || time.Now().After(exp) {
		return "", fmt.Errorf("key %s not found", key)
	}
	return val, nil
}

// emptyClientMap is the default ClientMap.
type emptyClientMap struct{}

func (m *emptyClientMap) Get(id string) (*Client, error) {
	return nil, errors.New("Unknown client id")
}

// emptyScopeSet is the default ScopeSet.
type emptyScopeSet struct{}

func (p *emptyScopeSet) ScopeSetFor(u *User) ScopeSet {
	return p
}

func (p *emptyScopeSet) ValidScope(scope ...string) bool {
	return false
}
