package main

import (
	"context"
	"fmt"
	"net/http"
	"net/url"
	"os"
	"os/signal"
	"strings"
	"syscall"
	"time"

	"github.com/amsterdam/authz/jose"
	"github.com/google/uuid"
)

func main() {
	keyset, err := jose.LoadJWKSet([]byte(`{
		"keys": [
			{
				"kty": "EC",
				"key_ops": [
					"verify",
					"sign"
				],
				"kid": "2aedafba-8170-4064-b704-ce92b7c89cc6",
				"crv": "P-256",
				"x": "6r8PYwqfZbq_QzoMA4tzJJsYUIIXdeyPA27qTgEJCDw=",
				"y": "Cf2clfAfFuuCB06NMfIat9ultkMyrMQO9Hd2H7O9ZVE=",
				"d": "N1vu0UQUp0vLfaNeM0EDbl4quvvL6m_ltjoAXXzkI3U="
			}
		]
	}`))
	if err != nil {
		panic(err)
	}
	handler := &Handler{
		JWKS:       keyset,
		FileServer: http.FileServer(http.Dir("./static")),
	}
	server := &http.Server{Addr: "0.0.0.0:8686", Handler: handler}

	// Shut down server if signal is received
	go func() {
		signalChan := make(chan os.Signal, 1)
		signal.Notify(signalChan, os.Interrupt, syscall.SIGTERM)
		<-signalChan
		server.Shutdown(context.Background())
	}()

	// Start the OAuth 2.0 server
	if err := server.ListenAndServe(); err != http.ErrServerClosed {
		panic(err)
	}
}

type AccessToken struct {
	Issuer    string   `json:"iss"`
	Subject   string   `json:"sub"`
	IssuedAt  int64    `json:"iat"`
	NotBefore int64    `json:"nbf"`
	ExpiresAt int64    `json:"exp"`
	JWTId     string   `json:"jti"`
	Scopes    []string `json:"scopes"`
}

type Handler struct {
	JWKS       *jose.JWKSet
	FileServer http.Handler
}

func (h *Handler) ServeHTTP(w http.ResponseWriter, r *http.Request) {
	if r.URL.Path == "/oauth2/authorize" {
		h.ServeAuthorizationRequest(w, r)
	} else if r.URL.Path == "/oauth2/jwks" {
		h.ServeVerifierKeys(w, r)
	} else if strings.HasPrefix(r.URL.Path, "/swagger-ui/") {
		h.FileServer.ServeHTTP(w, r)
	} else {
		http.Error(w, "Not Found", http.StatusNotFound)
	}
}

// ServeVerifierKeys handles an authorization request
func (h *Handler) ServeVerifierKeys(w http.ResponseWriter, r *http.Request) {
	fmt.Fprint(w, string(h.JWKS.VerifiersJSON()))
}

// ServeAuthorizationRequest handles an authorization request
func (h *Handler) ServeAuthorizationRequest(w http.ResponseWriter, r *http.Request) {
	if r.Method != "GET" {
		http.Error(w, "Invalid method", http.StatusMethodNotAllowed)
		return
	}
	query := r.URL.Query()
	// client_id
	_, ok := query["client_id"]
	if !ok {
		http.Error(w, "missing client_id", http.StatusBadRequest)
		return
	}
	// redirect_uri
	redir, ok := query["redirect_uri"]
	if !ok {
		http.Error(w, "missing redirect_uri", http.StatusBadRequest)
		return
	}
	// Create response
	redirectURI, err := url.Parse(redir[0])
	if err != nil {
		http.Error(w, "invalid redirect_uri", http.StatusBadRequest)
		return
	}
	response := &oauthResponse{URL: redirectURI, W: w}
	// response_type
	responseType, ok := query["response_type"]
	if !ok {
		response.sendError("invalid_request", "response_type missing")
		return
	}
	if responseType[0] != "token" {
		response.sendError(
			"unsupported_response_type", "response_type not supported for client",
		)
		return
	}
	// state
	var state string
	if s, ok := query["state"]; ok {
		state = s[0]
	}
	// scopes
	var scopes []string
	if s, ok := query["scope"]; ok {
		for _, scope := range strings.Split(s[0], " ") {
			scopes = append(scopes, scope)
		}
	}

	// Accesstoken
	keyid := h.JWKS.KeyIDs()[0]
	now := time.Now().Unix()
	jti, err := uuid.NewRandom()
	if err != nil {
		panic(err)
	}
	nbf := now - 10
	lifetime := int64(60 * 60 * 24)
	token, err := h.JWKS.Encode(keyid, AccessToken{
		Issuer:    "Test",
		Subject:   "test",
		IssuedAt:  nbf,
		NotBefore: nbf,
		ExpiresAt: nbf + lifetime,
		JWTId:     jti.String(),
		Scopes:    scopes,
	})
	if err != nil {
		panic(err)
	}

	// Send response
	response.sendToken(token, "bearer", lifetime, scopes, state)
}

type oauthResponse struct {
	*url.URL
	W http.ResponseWriter
}

func (r *oauthResponse) sendError(code, description string) {
	query := r.Query()
	query.Set("error", code)
	query.Set("error_description", description)
	r.RawQuery = query.Encode()
	headers := r.W.Header()
	headers.Add("Location", r.String())
	r.W.WriteHeader(http.StatusSeeOther)
}

func (r *oauthResponse) sendToken(accessToken string, tokenType string,
	lifetime int64, scope []string, state string) {
	v := url.Values{}
	v.Set("access_token", accessToken)
	v.Set("token_type", tokenType)
	v.Set("expires_in", fmt.Sprintf("%d", lifetime))
	v.Set("scope", strings.Join(scope, " "))
	if len(state) > 0 {
		v.Set("state", state)
	}
	fragment := v.Encode()
	redir := fmt.Sprintf("%s#%s", r.String(), fragment)
	r.W.Header().Add("Location", redir)
	r.W.WriteHeader(http.StatusSeeOther)
}
