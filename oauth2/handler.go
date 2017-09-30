package oauth2

import (
	"encoding/base64"
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

type handler struct {
	callbackURL url.URL

	// Components / interfaces
	accessTokenEnc *accessTokenEncoder
	stateStore     *stateStorage
	authz          Authz
	idps           map[string]IDP
	clientMap      ClientMap
}

// Handler returns an http.Handler that handles OAuth 2.0 requests.
func Handler(baseURL string, options ...Option) (http.Handler, error) {
	u, err := url.Parse(baseURL)
	if err != nil {
		return nil, err
	}
	u, err = u.Parse("callback")
	if err != nil {
		return nil, err
	}
	h := &handler{
		callbackURL: *u,
		idps:        make(map[string]IDP),
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
		h.accessTokenEnc = newAccessTokenEncoder(secret, 36000, "oauth2")
	}
	// Set default transient store if none given
	if h.stateStore == nil {
		log.Println("WARN: Using in-memory state storage")
		h.stateStore = newStateStorage(newStateMap(), 60*time.Second)
	} else {
		h.checkStateStore()
	}
	// Set default scopeset if no authz provider is given
	if h.authz == nil {
		log.Println("WARN: using empty scope set")
		h.authz = &emptyScopeSet{}
	}
	// Set default clientmap if no ClientMap is given
	if h.clientMap == nil {
		log.Println("WARN: no clientmap given")
		h.clientMap = &emptyClientMap{}
	}
	// Warn if none is set
	if len(h.idps) == 0 {
		log.Println("WARN: no IDP registered")
	}

	// Create and return handler
	mux := http.NewServeMux()
	mux.HandleFunc("/authorize", h.serveAuthorizationRequest)
	mux.HandleFunc("/callback", h.serveIDPCallback)
	return mux, nil
}

// checkStateStore makes sure a key / value pair is only restored once
func (h *handler) checkStateStore() {
	if err := h.stateStore.persist("test", struct{}{}); err != nil {
		log.Fatalf("State storage not working: %v\n", err)
	}
	if err := h.stateStore.restore("test", &struct{}{}); err != nil {
		log.Fatalf("State storage not working: %v\n", err)
	}
	if err := h.stateStore.restore("test", &struct{}{}); err == nil {
		log.Fatal("State storage not working: doesn't remove key on first restore")
	}
}

// serveAuthorizationRequest handles an initial authorization request
func (h *handler) serveAuthorizationRequest(
	w http.ResponseWriter, r *http.Request,
) {
	if r.Method != "GET" {
		http.Error(w, "Invalid method", http.StatusMethodNotAllowed)
		return
	}
	// state of authz request
	authzState := &authorizationState{}
	var (
		query  = r.URL.Query()
		client *Client
		idp    IDP
	)
	// client_id
	if clientID, ok := query["client_id"]; ok {
		authzState.ClientID = clientID[0]
		if c, err := h.clientMap.Get(authzState.ClientID); err == nil {
			client = c
		} else {
			http.Error(w, "invalid client_id", http.StatusBadRequest)
			return
		}
	} else {
		http.Error(w, "missing client_id", http.StatusBadRequest)
		return
	}
	// redirect_uri
	if redir, ok := query["redirect_uri"]; ok {
		for _, r := range client.Redirects {
			if redir[0] == r {
				authzState.RedirectURI = r
				break
			}
		}
	} else if len(client.Redirects) == 1 {
		authzState.RedirectURI = client.Redirects[0]
	}
	if authzState.RedirectURI == "" {
		http.Error(w, "missing or invalid redirect_uri", http.StatusBadRequest)
		return
	}
	redirectURI, err := url.Parse(authzState.RedirectURI)
	if err != nil {
		log.Printf("ERROR: registered redirect is invalid: %s\n", err)
		w.WriteHeader(http.StatusInternalServerError)
		return
	}
	// response_type
	responseType, ok := query["response_type"]
	if !ok {
		h.errorResponse(w, redirectURI, "invalid_request", "response_type missing")
		return
	}
	if responseType[0] != client.GrantType {
		h.errorResponse(
			w, redirectURI, "unsupported_response_type",
			"response_type not supported for client",
		)
		return
	}
	authzState.ResponseType = client.GrantType
	// state
	if s, ok := query["state"]; ok {
		authzState.State = s[0]
	}
	// scope
	scopeMap := make(map[string]struct{})
	if s, ok := query["scope"]; ok {
		for _, scope := range strings.Split(s[0], " ") {
			if !h.authz.ValidScope(scope) {
				h.errorResponse(
					w, redirectURI, "invalid_scope",
					fmt.Sprintf("invalid scope: %s", scope),
				)
				return
			}
			scopeMap[scope] = struct{}{}
		}
	}
	authzState.Scope = make([]string, len(scopeMap))
	i := 0
	for k := range scopeMap {
		authzState.Scope[i] = k
		i++
	}
	// Validate IDP and get idp handler url for this request
	if idpID, ok := query["idp_id"]; ok {
		authzState.IDPID = idpID[0]
		if idp, ok = h.idps[authzState.IDPID]; !ok {
			h.errorResponse(w, redirectURI, "invalid_request", "unknown idp_id")
			return
		}
	} else {
		h.errorResponse(w, redirectURI, "invalid_request", "idp_id missing")
		return
	}
	// Create authn session
	authnRedirect, err := h.authnSession(idp, authzState)
	if err != nil {
		h.errorResponse(w, redirectURI, "server_error", "internal server error")
		return
	}

	w.Header().Set("Location", authnRedirect)
	w.WriteHeader(http.StatusSeeOther)
}

// serveIDPCallback handles IDP callbacks
func (h *handler) serveIDPCallback(w http.ResponseWriter, r *http.Request) {
	q := r.URL.Query()
	token, ok := q["token"]
	if !ok {
		http.Error(w, "token parameter missing", http.StatusBadRequest)
		return
	}
	var state authorizationState
	if err := h.stateStore.restore(token[0], &state); err != nil {
		log.Printf("Error restoring state token: %s\n", err)
		http.Error(w, "invalid state token", http.StatusBadRequest)
		return
	}
	redirectURI, err := url.Parse(state.RedirectURI)
	if err != nil {
		log.Printf("Error reconstructing redirect_uri from unmarshalled state: %s\n", err)
		w.WriteHeader(http.StatusInternalServerError)
		return
	}
	idp, ok := h.idps[state.IDPID]
	if !ok {
		log.Printf("Error finding IDP: %s\n", state.IDPID)
		w.WriteHeader(http.StatusInternalServerError)
		return
	}
	user, err := idp.User(r, state.IDPState)
	if err != nil {
		log.Printf("Error authenticating user: %s\n", err)
		h.errorResponse(w, redirectURI, "access_denied", "couldn't authenticate user")
		return
	}
	grantedScopes := []string{}
	if len(state.Scope) > 0 {
		userScopes, err := h.authz.ScopeSetFor(user)
		if err != nil {
			log.Printf("Error getting scopes for user: %s\n", err)
			w.WriteHeader(http.StatusInternalServerError)
			return
		}
		for _, scope := range state.Scope {
			if userScopes.ValidScope(scope) {
				grantedScopes = append(grantedScopes, scope)
			}
		}
	}
	accessToken, err := h.accessTokenEnc.Encode(user.UID, grantedScopes)
	if err != nil {
		log.Println(err)
		h.errorResponse(w, redirectURI, "server_error", "internal server error")
		return
	}
	h.implicitResponse(
		w, redirectURI, accessToken, "bearer", h.accessTokenEnc.Lifetime(),
		grantedScopes, state.State,
	)
}

// authnSession saves the current state of the authorization request and
// returns a redirect URL for the given idp
func (h *handler) authnSession(idp IDP, state *authorizationState) (string, error) {
	// Create token
	token := make([]byte, 16)
	rand.Read(token)
	b64Token := base64.RawURLEncoding.EncodeToString(token)
	// Add token to callback URL
	query := url.Values{}
	query.Set("token", b64Token)
	callbackURL := h.callbackURL
	callbackURL.RawQuery = query.Encode()
	// Het authentication redirect
	redir, idpState, err := idp.AuthnRedirect(&callbackURL)
	if err != nil {
		return "", err
	}
	state.IDPState = idpState
	if err := h.stateStore.persist(b64Token, state); err != nil {
		return "", err
	}
	return redir.String(), nil
}

// oauth20Error
func (h *handler) errorResponse(
	w http.ResponseWriter, r *url.URL, code string, desc string) {
	query := r.Query()
	query.Set("error", code)
	query.Set("error_description", desc)
	r.RawQuery = query.Encode()
	headers := w.Header()
	headers.Add("Location", r.String())
	w.WriteHeader(http.StatusSeeOther)
}

func (h *handler) implicitResponse(
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
