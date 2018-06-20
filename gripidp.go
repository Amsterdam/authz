// An IdP implementation of Grip OIC: https://kb.grip-on-it.com/en/service-onboarding/openidconnect/
package main

import (
	"bytes"
	"encoding/base64"
	"encoding/json"
	"fmt"
	"net/http"
	"net/url"
	"strings"
	"time"

	"github.com/amsterdam/authz/oauth2"
	log "github.com/sirupsen/logrus"
)

var (
	gripAuthURL      = "https://auth.grip-on-it.com/v2/%s/oidc/idp/authorize"
	gripTokenURL     = "https://auth.grip-on-it.com/v2/%s/oidc/idp/token"
	gripUserInfoURL  = "https://auth.grip-on-it.com/v2/%s/oidc/idp/userinfo"
	gripAuthScope    = "openid email"
	gripResponseType = "code"
	gripGrantType    = "authorization_code"
)

type gripAuthzData struct {
	AccessToken string `json:"access_token"`
	TokenType   string `json:"token_type"`
	ExpiresIn   int    `json:"expires_in"`
	IDToken     string `json:"id_token"`

	client *http.Client
}

func (g *gripAuthzData) idToken() (*gripIDToken, error) {

	// split the id token
	parts := strings.Split(g.IDToken, ".")
	if len(parts) != 3 {
		return nil, fmt.Errorf("ID Token is invalid: %s", g.IDToken)
	}
	b64IDToken := parts[1]
	// decode the payload
	rawIDToken, err := base64.RawURLEncoding.DecodeString(b64IDToken)
	if err != nil {
		return nil, err
	}
	var idToken gripIDToken
	if err := json.Unmarshal(rawIDToken, &idToken); err != nil {
		return nil, err
	}
	return &idToken, nil
}

func (g *gripAuthzData) userInfo() (*gripUserInfo, error) {
	// Create UserInfo request
	req, err := http.NewRequest("GET", gripUserInfoURL, nil)
	if err != nil {
		return nil, err
	}
	req.Header.Set("Authorization", fmt.Sprintf("Bearer %s", g.AccessToken))

	// Get userinfo
	resp, err := g.client.Do(req)
	if err != nil {
		return nil, err
	}
	body := new(bytes.Buffer)
	body.ReadFrom(resp.Body)

	// Decode response
	var userInfo gripUserInfo
	if err := json.Unmarshal(body.Bytes(), &userInfo); err != nil {
		return nil, err
	}

	return &userInfo, nil
}

type gripIDToken struct {
	Issuer     string `json:"iss"`
	Subject    string `json:"sub"`
	Audience   string `json:"aud"`
	IssuedAt   int    `json:"iat"`
	ExpiryTime int    `json:"exp"`
}

type gripUserInfo struct {
	Subject           string                     `json:"sub"`
	PreferredUsername string                     `json:"preferred_username"`
	Name              string                     `json:"name"`
	Title             string                     `json:"title"`
	GivenName         string                     `json:"given_name"`
	MiddleName        string                     `json:"middle_name"`
	FamilyName        string                     `json:"family_name"`
	NickName          string                     `json:"nickname"`
	Profile           string                     `json:"profile"`
	Email             string                     `json:"email"`
	EmailAlternate    string                     `json:"email_alternate"`
	Gender            string                     `json:"gender"`
	ZoneInfo          string                     `json:"zoneinfo"`
	Locale            string                     `json:"locale"`
	PhoneNumber       string                     `json:"phone_number"`
	PhoneNumberHome   string                     `json:"phone_number_home"`
	PhoneNumberMobile string                     `json:"phone_number_mobile"`
	Address           gripUserInfoAddress        `json:"address"`
	UpdatedAt         string                     `json:"updated_at"`
	GripUser          gripUserInfoUser           `json:"grip_user"`
	SCIMEnterprise    gripUserInfoSCIMEnterprise `json:"scim_enterprise"`
	GripService       gripUserInfoGripService    `json:"grip_service"`
	GripTenant        gripUserInfoGripTenant     `json:"grip_tenant"`
}

type gripUserInfoAddress struct {
	Street     string `json:"street_address"`
	Locality   string `json:"locality"`
	Region     string `json:"region"`
	PostalCode string `json:"postal_code"`
	Country    string `json:"country"`
}

type gripUserInfoUser struct {
	Type        string                    `json:"user_type"`
	Description string                    `json:"description"`
	Alias       string                    `json:"user_name_alias"`
	Roles       []gripUserInfoStringValue `json:"roles"`
	Custom1     string                    `json:"user_custom_01"`
	Custom2     string                    `json:"user_custom_02"`
	Custom3     string                    `json:"user_custom_03"`
	Custom4     string                    `json:"user_custom_04"`
	Custom5     string                    `json:"user_custom_05"`
}

type gripUserInfoStringValue struct {
	Value string `json:"value"`
}

type gripUserInfoSCIMEnterprise struct {
	EmployeeNumber string                            `json:"employee_number"`
	Division       string                            `json:"division"`
	Department     string                            `json:"department"`
	Manager        gripUserInfoSCIMEnterpriseManager `json:"manager"`
}

type gripUserInfoSCIMEnterpriseManager struct {
	Value string `json:"value"`
	Name  string `json:"name"`
}

type gripUserInfoGripService struct {
	ID          string `json:"service_id"`
	ShortName   string `json:"service_short_name"`
	LongName    string `json:"service_long_name"`
	Description string `json:"description"`
	Custom01    string `json:"service_custom_01"`
	Custom02    string `json:"service_custom_02"`
	Custom03    string `json:"service_custom_03"`
	Custom04    string `json:"service_custom_04"`
	Custom05    string `json:"service_custom_05"`
	Custom06    string `json:"service_custom_06"`
	Custom07    string `json:"service_custom_07"`
	Custom08    string `json:"service_custom_08"`
	Custom09    string `json:"service_custom_09"`
	Custom10    string `json:"service_custom_10"`
}

type gripUserInfoGripTenant struct {
	ID            string                    `json:"tenant_id"`
	KrnID         string                    `json:"krn_id"`
	EnterpriseIDs []gripUserInfoStringValue `json:"enterprise_ids"`
	SNumbers      []gripUserInfoStringValue `json:"s_numbers"`
	ShortName     string                    `json:"tenant_short_name"`
	LongName      string                    `json:"tenant_long_name"`
	Description   string                    `json:"description"`
	Custom1       string                    `json:"tenant_custom_01"`
	Custom2       string                    `json:"tenant_custom_02"`
	Custom3       string                    `json:"tenant_custom_03"`
	Custom4       string                    `json:"tenant_custom_04"`
	Custom5       string                    `json:"tenant_custom_05"`
}

type gripIDP struct {
	clientID     string
	clientSecret string
	oauthBaseURL string
	authURL      string
	tokenURL     string
	userInfoURL  string
	roles        *datapuntRoles
	client       *http.Client
}

// Constructor. Validating its config and creates the instance.
func newGripIDP(tenantID string, clientID string, clientSecret string, oauthBaseURL string, roles *datapuntRoles) *gripIDP {
	authURL := fmt.Sprintf(gripAuthURL, tenantID)
	tokenURL := fmt.Sprintf(gripTokenURL, tenantID)
	userInfoURL := fmt.Sprintf(gripUserInfoURL, tenantID)
	return &gripIDP{
		clientID, clientSecret, oauthBaseURL, authURL, tokenURL, userInfoURL,
		roles, &http.Client{Timeout: 1 * time.Second},
	}
}

// ID returns "grip"
func (g *gripIDP) ID() string {
	return "grip"
}

func (g *gripIDP) oauth2CallbackURL() string {
	return g.oauthBaseURL + "oauth2/callback/" + g.ID()
}

// AuthnRedirect generates the Authentication redirect.
func (g *gripIDP) AuthnRedirect(authzRef string) (*url.URL, error) {
	// Build state
	authURL, err := url.Parse(gripAuthURL)
	if err != nil {
		return nil, err
	}
	authQuery := authURL.Query()
	authQuery.Set("client_id", g.clientID)
	authQuery.Set("response_type", gripResponseType)
	authQuery.Set("scope", gripAuthScope)
	authQuery.Set("redirect_uri", g.oauth2CallbackURL())
	authQuery.Set("state", authzRef)
	authURL.RawQuery = authQuery.Encode()
	return authURL, nil
}

// User returns a User and the original opaque token.
func (g *gripIDP) AuthnCallback(r *http.Request) (string, *oauth2.User, error) {
	q := r.URL.Query()

	// Create context logger
	logFields := log.Fields{
		"type": "authn callback request",
		"idp":  "Grip",
		"uri":  r.RequestURI,
	}
	logger := log.WithFields(logFields)

	// Get the state
	state, ok := q["state"]
	if !ok {
		return "", nil, nil
	}

	// From here on, we always return the authzRef, no matter what the error.
	authzRef := state[0]

	// Get the code
	authzCode, ok := q["code"]
	if !ok {
		logger.Warnln("Missing code parameter")
		return authzRef, nil, nil
	}

	// Get the ID token
	authzData, err := g.authzData(authzCode[0])
	if err != nil {
		logger.Warnf("Error getting authorization data: %v", err)
		return authzRef, nil, nil
	}

	// Get UserInfo
	userInfo, err := authzData.userInfo()
	if err != nil {
		logger.Warnf("Error getting authorization data: %v", err)
		return authzRef, nil, nil
	}

	return authzRef, &oauth2.User{UID: userInfo.Email, Data: []string{"CDE_PLUS"}}, nil

}

func (g *gripIDP) authzData(authzCode string) (*gripAuthzData, error) {
	// Create token request
	data := url.Values{}
	data.Set("code", authzCode)
	data.Set("redirect_uri", g.oauth2CallbackURL())
	data.Set("grant_type", gripGrantType)
	req, err := http.NewRequest(
		"POST", gripTokenURL, strings.NewReader(data.Encode()),
	)
	if err != nil {
		return nil, err
	}
	req.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	req.SetBasicAuth(g.clientID, g.clientSecret)

	// Get token
	resp, err := g.client.Do(req)
	if err != nil {
		return nil, err
	}

	// Read response body
	body := new(bytes.Buffer)
	body.ReadFrom(resp.Body)

	// Handle error response
	if resp.StatusCode != 200 {
		return nil, fmt.Errorf("Error from server while getting a token: %s", body.String())
	}

	// Decode response
	var authzData gripAuthzData
	if err := json.Unmarshal(body.Bytes(), &authzData); err != nil {
		return nil, err
	}

	return &authzData, nil
}
