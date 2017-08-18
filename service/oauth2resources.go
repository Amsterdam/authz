package service

import (
	"bytes"
	"encoding/gob"
	"errors"
	"fmt"
	"log"
	"math/rand"
	"net/http"
	"net/url"
	"time"

	"github.com/DatapuntAmsterdam/goauth2/config"
	"github.com/DatapuntAmsterdam/goauth2/idp"
	"github.com/garyburd/redigo/redis"
)

// Supported grant types & handlers
var grantHandlers = map[string]func() *AuthorizationResponse{
	"code":  func() *AuthorizationResponse { return nil },
	"token": func() *AuthorizationResponse { return nil },
}

// Error codes
const (
	ERRCODE_INVALID_REQUEST           = "invalid_request"
	ERRCODE_UNAUTHORIZED_CLIENT       = "unauthorized_client"
	ERRCODE_ACCESS_DENIED             = "access_denied"
	ERRCODE_UNSUPPORTED_RESPONSE_TYPE = "unsupported_response_type"
	ERRCODE_INVALID_SCOPE             = "invalid_scope"
	ERRCODE_SERVER_ERROR              = "server_error"
	ERRCODE_TEMPORARILY_UNAVAILABLE   = "temporarily_unavailable"
)

// Characters used for random request identifiers.
const letters = "abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ"

// AuthorizationResponse is an HTTP response that should be returned to the client.
type AuthorizationResponse struct {
	status int
	header map[string][]string
	body   []byte
}

// Write writes the response onto the given ResponseWriter.
func (r *AuthorizationResponse) Write(w http.ResponseWriter) {
	headers := w.Header()
	for header, values := range r.header {
		for _, value := range values {
			headers.Add(header, value)
		}
	}
	w.WriteHeader(r.status)
	w.Write(r.body)
}

// Resource handlers for the OAuth 2.0 service.
type OAuth2 struct {
	Handler *Handler
	idps    map[string]idp.IdP
	clients map[string]config.OAuth2Client
	// ScopesMap ScopeMap
	redisPool       *redis.Pool
	redisExpireSecs int
}

// OAuth 2.0 resources.
//
// NewOAuth2() creates a Handler and registers all its resources.
func NewOAuth2(conf *config.Config) (*OAuth2, error) {
	// Create a Redis connectionpool
	pool := &redis.Pool{
		MaxIdle:     3,
		IdleTimeout: 240 * time.Second,
		// Dial creates a connection and authenticates
		Dial: func() (redis.Conn, error) {
			c, err := redis.Dial("tcp", conf.Redis.Address)
			if err != nil {
				return nil, err
			}
			if conf.Redis.Password != "" {
				if _, err := c.Do("AUTH", conf.Redis.Password); err != nil {
					c.Close()
					return nil, err
				}
			}
			return c, nil
		},
		// Ping a connection to see whether it's still alive
		// TODO: give more thought to semantics
		TestOnBorrow: func(c redis.Conn, t time.Time) error {
			if time.Since(t) < time.Minute {
				return nil
			}
			_, err := c.Do("PING")
			return err
		},
	}
	// Create the IdP map
	idps, err := idp.IdPMap(conf)
	if err != nil {
		return nil, err
	}
	// Create the OAuth 2.0 object
	oauth2 := &OAuth2{
		Handler:         NewHandler(),
		idps:            idps,
		clients:         conf.Client,
		redisPool:       pool,
		redisExpireSecs: conf.Redis.ExpireSecs,
	}
	// Add all resource handlers
	oauth2.Handler.addResources(
		Resource{
			"authorizationrequest", "/authorize",
			methodHandler{
				"GET": oauth2.authorizationRequest,
			},
		},
	)
	return oauth2, nil
}

// authorizationRequest handles an OAuth 2.0 authorization request.
func (h OAuth2) authorizationRequest(w http.ResponseWriter, r *http.Request) {
	// Create an authorization request
	authzReq, err := h.NewAuthorizationRequest(r)
	if err != nil {
		log.Printf("Authz request error: %s -> %s", r.RequestURI, err)
	} else {
		// Save data in Redis
		var data bytes.Buffer
		enc := gob.NewEncoder(&data)
		err := enc.Encode(&authzReq.AuthorizationParams)
		if err != nil {
			authzReq.SetErrorResponse(ERRCODE_SERVER_ERROR, "server error")
			log.Printf("Authz request error (problem encoding data): %s", err)
		} else {
			key := fmt.Sprintf("authzreq:%s", authzReq.Id)
			value := data.String()
			conn := h.redisPool.Get()
			defer conn.Close()
			if _, err := conn.Do("SET", key, value, "EX", h.redisExpireSecs); err != nil {
				authzReq.SetErrorResponse(ERRCODE_SERVER_ERROR, "server error")
				log.Printf("Authz request error (problem saving data in Redis): %s", err)
			}
		}
	}
	authzReq.Response.Write(w)
}

// AuthorizationParams are used throughout the authorization request sequence.
type AuthorizationParams struct {
	// All authorization request params
	ClientId     string
	RedirectURI  string
	ResponseType string
	Scope        []string
	State        string
}

// AuthorizationRequest handles an authorization request.
type AuthorizationRequest struct {
	// An identifier to be used
	Id string
	// Request query and response
	query    url.Values
	Response *AuthorizationResponse
	// Objects and values based on request params
	idProvider   idp.IdP
	oauth2Client *config.OAuth2Client
	redirectURI  *url.URL
	// All params
	AuthorizationParams
}

func (h *OAuth2) NewAuthorizationRequest(r *http.Request) (*AuthorizationRequest, error) {
	// placeholder
	var err error

	q := r.URL.Query()
	authzReq := &AuthorizationRequest{query: q, Response: &AuthorizationResponse{}}

	// Validate and set client_id and oauth2client
	if clientId, ok := q["client_id"]; ok {
		if c, ok := h.clients[clientId[0]]; ok {
			authzReq.oauth2Client = &c
			authzReq.ClientId = clientId[0]
		} else {
			err = errors.New("unknown client_id")
		}
	} else {
		err = errors.New("client_id missing")
	}
	if err != nil {
		authzReq.SetBadRequest(err.Error())
		return authzReq, err
	}

	// Validate and set redirect_uri
	if redirectURI, ok := q["redirect_uri"]; ok {
		for _, registeredRedirectURI := range authzReq.oauth2Client.Redirects {
			if registeredRedirectURI == redirectURI[0] {
				if redir, parseErr := url.Parse(registeredRedirectURI); parseErr == nil {
					authzReq.RedirectURI = registeredRedirectURI
					authzReq.redirectURI = redir
				}
				break
			}
		}
		if authzReq.redirectURI == nil {
			err = errors.New("invalid redirect_uri")
		}
	} else if len(authzReq.oauth2Client.Redirects) == 1 {
		authzReq.RedirectURI = authzReq.oauth2Client.Redirects[0]
	} else {
		err = errors.New("must provide a redirect_uri for this client_id")
	}
	if err != nil {
		authzReq.SetBadRequest(err.Error())
		return authzReq, err
	}

	// Validate and set idProvider property.
	if idpId, ok := q["idp_id"]; ok {
		if i, ok := h.idps[idpId[0]]; ok {
			authzReq.idProvider = i
		} else {
			err = errors.New("unknown idp_id")
		}
	} else {
		err = errors.New("idp_id missing")
	}
	if err != nil {
		authzReq.SetErrorResponse(ERRCODE_INVALID_REQUEST, err.Error())
		return authzReq, err
	}

	// Validate and set response_type
	if responseType, ok := q["response_type"]; ok {
		if _, ok := grantHandlers[responseType[0]]; ok {
			authzReq.ResponseType = responseType[0]
		} else {
			err = errors.New("response_type not supported")
			authzReq.SetErrorResponse(ERRCODE_UNSUPPORTED_RESPONSE_TYPE, err.Error())
			return authzReq, err
		}
	} else {
		err = errors.New("response_type missing")
		authzReq.SetErrorResponse(ERRCODE_INVALID_REQUEST, err.Error())
		return authzReq, err
	}

	// Validate and set state
	if state, ok := q["state"]; ok {
		if len(state[0]) >= 8 {
			authzReq.State = state[0]
		} else {
			err = errors.New("state should be at least 8 characters long")
		}
	} else {
		err = errors.New("state missing")
	}
	if err != nil {
		authzReq.SetErrorResponse(ERRCODE_INVALID_REQUEST, err.Error())
		return authzReq, err
	}

	authzReq.setIdpRedirectResponse()

	return authzReq, err
}

type TestKeyValueStore struct{}

func (kv *TestKeyValueStore) Get(key []byte) ([]byte, error) {
	return []byte(""), nil
}

func (kv *TestKeyValueStore) Set(key []byte, value []byte) error {
	return nil
}

// setIdpRedirectResponse sets a 303 See Other response.
func (r *AuthorizationRequest) setIdpRedirectResponse() {
	// Create an opaque token that can be used to store / fetch request params.
	reqId := make([]byte, 16)
	for i := range reqId {
		reqId[i] = letters[rand.Int63()%int64(len(letters))]
	}
	r.Id = string(reqId)
	// Get the IdP's redirect URI
	cb, _ := url.Parse("http://localhost")
	kv := &TestKeyValueStore{}
	authnRedir, _ := r.idProvider.AuthnRedirect(r.Id, *cb, kv)
	// Create and set the response
	if r.Response.header == nil {
		r.Response.header = make(map[string][]string)
	}
	r.Response.status = http.StatusSeeOther
	r.Response.header["Location"] = []string{authnRedir}
}

// SetBadRequest sets a 404 Bad Request response.
func (r *AuthorizationRequest) SetBadRequest(body string) {
	r.Response.status = http.StatusBadRequest
	r.Response.body = []byte(body)
}

// SetErrorResponse sets a 303 See Other error response with
// error=[errorType]&error_description=[description] query params.
func (r *AuthorizationRequest) SetErrorResponse(errorType string, description string) {
	if r.Response.header == nil {
		r.Response.header = make(map[string][]string)
	}
	query := r.redirectURI.Query()
	query.Set("error", errorType)
	query.Set("error_description", description)
	r.redirectURI.RawQuery = query.Encode()
	r.Response.status = http.StatusSeeOther
	r.Response.header["Location"] = []string{r.redirectURI.String()}
}
