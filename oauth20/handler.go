package oauth20

import (
	"fmt"
	"log"
	"math/rand"
	"net/http"
	"net/url"
	"strings"
	"time"
)

func init() {
	rand.Seed(time.Now().UTC().UnixNano())
}

type oauth20Handler struct {
	callbackURL url.URL

	// Components / interfaces
	accessTokenEnc *accessTokenEncoder
	stateStore     *stateStorage
	authz          Authz
	idps           map[string]IdP
	clientMap      ClientMap
}

// Handler() returns an http.Handler that handles OAuth 2.0 requests.
func Handler(baseURL string, options ...Option) (http.Handler, error) {
	u, err := url.Parse(baseURL)
	if err != nil {
		return nil, err
	}
	u, err = u.Parse("callback")
	if err != nil {
		return nil, err
	}
	h := &oauth20Handler{
		callbackURL: *u,
		idps:        make(map[string]IdP),
	}
	// First we set options
	for _, option := range options {
		if err := option(h); err != nil {
			return nil, err
		}
	}
	// Set default accesstoken config if not set
	if h.accessTokenEnc == nil {
		log.Println("WARN: accesstoken config missing, using random secret.")
		secret := make([]byte, 16)
		rand.Read(secret)
		h.accessTokenEnc = newAccessTokenEncoder(secret, 36000, "goauth2")
	}
	// Set default transient store if none given
	if h.stateStore == nil {
		log.Println("WARN: Using in-memory state storage")
		h.stateStore = newStateStorage(newStateMap(), 60*time.Second)
	}
	// Set default scopeset if no authz provider is given
	if h.authz == nil {
		log.Println("WARN: using empty scope set")
		h.authz = &emptyScopeSet{}
	}
	// Set default clientmap if no ClientMap is given
	if h.clientMap == nil {
		log.Println("WARN: using empty client map")
		h.clientMap = &emptyClientMap{}
	}
	// Warn if none is set
	if len(h.idps) == 0 {
		log.Println("WARN: no IdP registered")
	}

	return h.handler()
}

// oauth20handler() creates the request handler for the handler.
func (h *oauth20Handler) handler() (http.Handler, error) {
	mux := http.NewServeMux()
	mux.HandleFunc("/authorize", h.serveAuthorizationRequest)
	mux.HandleFunc("/callback", h.serveIdPCallback)
	return mux, nil
}

// oauth20Error
func (h *oauth20Handler) errorResponse(
	w http.ResponseWriter, r *url.URL, code string, desc string) {
	query := r.Query()
	query.Set("error", code)
	query.Set("error_description", desc)
	r.RawQuery = query.Encode()
	headers := w.Header()
	headers.Add("Location", r.String())
	w.WriteHeader(http.StatusSeeOther)
}

func (h *oauth20Handler) implicitResponse(
	w http.ResponseWriter, redirectURI *url.URL, accessToken string,
	tokenType string, lifetime int64, scope []string, state string) {
	v := url.Values{}
	v.Set("access_token", accessToken)
	v.Set("token_type", tokenType)
	v.Set("expires_in", fmt.Sprintf("%d", lifetime))
	v.Set("scope", strings.Join(scope, " "))
	if len(state) > 0 {
		v.Set("state", state)
	}
	fragment := v.Encode()
	redir := fmt.Sprintf("%s#%s", redirectURI.String(), fragment)
	w.Header().Add("Location", redir)
	w.WriteHeader(http.StatusSeeOther)
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
	// ID returns the IdP's identifier
	ID() string
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
