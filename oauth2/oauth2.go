package oauth2

import (
	"encoding/json"
	"errors"
	"fmt"
	"io/ioutil"
	"mime"
	"net/http"
	"net/url"
	"strconv"
	"strings"

	phttp "github.com/coreos/go-oidc/http"
)

const (
	ResponseTypeCode = "code"
)

const (
	GrantTypeAuthCode    = "authorization_code"
	GrantTypeClientCreds = "client_credentials"
	GrantTypeImplicit    = "implicit"

	AuthMethodClientSecretPost  = "client_secret_post"
	AuthMethodClientSecretBasic = "client_secret_basic"
	AuthMethodClientSecretJWT   = "client_secret_jwt"
	AuthMethodPrivateKeyJWT     = "private_key_jwt"
)

type Config struct {
	Credentials ClientCredentials
	Scope       []string
	RedirectURL string
	AuthURL     string
	TokenURL    string

	// Must be one of the AuthMethodXXX methods above. Right now, only
	// AuthMethodClientSecretPost and AuthMethodClientSecretBasic are supported.
	AuthMethod string
}

type Client struct {
	hc          phttp.Client
	creds       ClientCredentials
	scope       []string
	authURL     *url.URL
	redirectURL *url.URL
	tokenURL    *url.URL
	authMethod  string
}

type ClientCredentials struct {
	ID     string
	Secret string
}

func NewClient(hc phttp.Client, cfg Config) (c *Client, err error) {
	if len(cfg.Credentials.ID) == 0 {
		err = errors.New("missing client id")
		return
	}

	if len(cfg.Credentials.Secret) == 0 {
		err = errors.New("missing client secret")
		return
	}

	if cfg.AuthMethod == "" {
		cfg.AuthMethod = AuthMethodClientSecretBasic
	} else if cfg.AuthMethod != AuthMethodClientSecretPost && cfg.AuthMethod != AuthMethodClientSecretBasic {
		err = fmt.Errorf("auth method %q is not supported", cfg.AuthMethod)
		return
	}

	au, err := url.Parse(cfg.AuthURL)
	if err != nil {
		return
	}

	tu, err := url.Parse(cfg.TokenURL)
	if err != nil {
		return
	}

	ru, err := url.Parse(cfg.RedirectURL)
	if err != nil {
		return
	}

	c = &Client{
		creds:       cfg.Credentials,
		scope:       cfg.Scope,
		redirectURL: ru,
		authURL:     au,
		tokenURL:    tu,
		hc:          hc,
		authMethod:  cfg.AuthMethod,
	}

	return
}

// Generate the url for initial redirect to oauth provider.
func (c *Client) AuthCodeURL(state, accessType, prompt string) string {
	v := c.commonURLValues()
	v.Set("state", state)
	if strings.ToLower(accessType) == "offline" {
		v.Set("access_type", "offline")
	}
	if strings.ToLower(prompt) == "force" {
		v.Set("approval_prompt", "force")
	}
	v.Set("response_type", "code")

	q := v.Encode()
	u := *c.authURL
	if u.RawQuery == "" {
		u.RawQuery = q
	} else {
		u.RawQuery += "&" + q
	}
	return u.String()
}

func (c *Client) commonURLValues() url.Values {
	return url.Values{
		"redirect_uri": {c.redirectURL.String()},
		"scope":        {strings.Join(c.scope, " ")},
		"client_id":    {c.creds.ID},
	}
}

func (c *Client) newAuthenticatedRequest(url string, values url.Values) (*http.Request, error) {
	var req *http.Request
	var err error
	switch c.authMethod {
	case AuthMethodClientSecretPost:
		values.Set("client_secret", c.creds.Secret)
		req, err = http.NewRequest("POST", url, strings.NewReader(values.Encode()))
		if err != nil {
			return nil, err
		}
	case AuthMethodClientSecretBasic:
		req, err = http.NewRequest("POST", url, strings.NewReader(values.Encode()))
		if err != nil {
			return nil, err
		}
		req.SetBasicAuth(c.creds.ID, c.creds.Secret)
	default:
		panic("misconfigured client: auth method not supported")
	}

	req.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	return req, nil

}

// ClientCredsToken posts the client id and secret to obtain a token scoped to the OAuth2 client via the "client_credentials" grant type.
// May not be supported by all OAuth2 servers.
func (c *Client) ClientCredsToken(scope []string) (result TokenResponse, err error) {
	v := url.Values{
		"scope":      {strings.Join(scope, " ")},
		"grant_type": {GrantTypeClientCreds},
	}

	req, err := c.newAuthenticatedRequest(c.tokenURL.String(), v)
	if err != nil {
		return
	}

	resp, err := c.hc.Do(req)
	if err != nil {
		return
	}
	defer resp.Body.Close()

	return parseTokenResponse(resp)
}

// Exchange auth code for series of tokens.
func (c *Client) Exchange(code string) (result TokenResponse, err error) {
	v := c.commonURLValues()

	v.Set("grant_type", GrantTypeAuthCode)
	v.Set("code", code)
	v.Set("client_secret", c.creds.Secret)

	req, err := c.newAuthenticatedRequest(c.tokenURL.String(), v)
	if err != nil {
		return
	}

	resp, err := c.hc.Do(req)
	if err != nil {
		return
	}
	defer resp.Body.Close()

	return parseTokenResponse(resp)
}

func parseTokenResponse(resp *http.Response) (result TokenResponse, err error) {
	body, err := ioutil.ReadAll(resp.Body)
	if err != nil {
		return
	}

	if resp.StatusCode < 200 || resp.StatusCode > 299 {
		err = unmarshalError(body)
		return
	}

	contentType, _, err := mime.ParseMediaType(resp.Header.Get("Content-Type"))
	if err != nil {
		return
	}

	result = TokenResponse{
		RawBody: body,
	}

	if contentType == "application/x-www-form-urlencoded" || contentType == "text/plain" {
		var vals url.Values
		vals, err = url.ParseQuery(string(body))
		if err != nil {
			return
		}
		result.AccessToken = vals.Get("access_token")
		result.TokenType = vals.Get("token_type")
		result.IDToken = vals.Get("id_token")
		e := vals.Get("expires_in")
		if e == "" {
			e = vals.Get("expires")
		}
		result.Expires, err = strconv.Atoi(e)
		if err != nil {
			return
		}
	} else {
		b := make(map[string]interface{})
		if err = json.Unmarshal(body, &b); err != nil {
			return
		}
		result.AccessToken, _ = b["access_token"].(string)
		result.TokenType, _ = b["token_type"].(string)
		result.IDToken, _ = b["id_token"].(string)
		e, ok := b["expires_in"].(int)
		if !ok {
			e, _ = b["expires"].(int)
		}
		result.Expires = e
	}

	return
}

type TokenResponse struct {
	AccessToken string
	TokenType   string
	Expires     int
	IDToken     string
	RawBody     []byte // In case callers need some other non-standard info from the token response
}

type AuthCodeRequest struct {
	ResponseType string
	ClientID     string
	RedirectURL  *url.URL
	Scope        []string
	State        string
}

func ParseAuthCodeRequest(q url.Values) (AuthCodeRequest, error) {
	acr := AuthCodeRequest{
		ResponseType: q.Get("response_type"),
		ClientID:     q.Get("client_id"),
		State:        q.Get("state"),
		Scope:        make([]string, 0),
	}

	qs := strings.TrimSpace(q.Get("scope"))
	if qs != "" {
		acr.Scope = strings.Split(qs, " ")
	}

	err := func() error {
		if acr.ClientID == "" {
			return NewError(ErrorInvalidRequest)
		}

		redirectURL := q.Get("redirect_uri")
		if redirectURL != "" {
			ru, err := url.Parse(redirectURL)
			if err != nil {
				return NewError(ErrorInvalidRequest)
			}
			acr.RedirectURL = ru
		}

		return nil
	}()

	return acr, err
}
