package oidc

import (
	"bytes"
	"context"
	"encoding/json"
	"fmt"
	"io/ioutil"
	"net/http"

	"golang.org/x/oauth2"
)

type (
	// https://openid.net/specs/openid-connect-registration-1_0.html#RegistrationRequest
	ClientRegistration struct {
		Name                    string   `json:"client_name"`
		ResponseTypes           []string `json:"response_types"`
		TokenEndpointAuthMethod string   `json:"token_endpoint_auth_method"`
		InitiateLoginURI        string   `json:"initiate_login_uri"`
		RedirectURIs            []string `json:"redirect_uris"`
		ApplicationType         string   `json:"application_type"`
		FrontchannelLogoutURI   string   `json:"frontchannel_logout_uri"`
	}

	// https://openid.net/specs/openid-connect-registration-1_0.html#RegistrationResponse
	// https://openid.net/specs/openid-connect-registration-1_0.html#RegistrationError
	clientRegistrationResponse struct {
		Error            string `json:"error,omitempty"`
		ErrorDescription string `json:"error_description,omitempty"`

		Client
	}

	Client struct {
		Name                    string   `json:"client_name,omitempty"`
		ID                      string   `json:"client_id"`
		Secret                  string   `json:"client_secret,omitempty"`
		RedirectURIs            []string `json:"redirect_uris,omitempty"`
		ResponseTypes           []string `json:"response_types,omitempty"`
		TokenEndpointAuthMethod string   `json:"token_endpoint_auth_method,omitempty"`
		InitiateLoginURI        string   `json:"initiate_login_uri,omitempty"`
		ApplicationType         string   `json:"application_type,omitempty"`
		FrontchannelLogoutURI   string   `json:"frontchannel_logout_uri,omitempty"`
		IssuedAt                jsonTime `json:"client_id_issued_at,omitempty"`
		SecretExpiresAt         jsonTime `json:"client_secret_expires_at"`
	}
)

// Client registration
//
// See: https://openid.net/specs/openid-connect-registration-1_0.html#ClientRegistration
func (p *Provider) RegisterClient(ctx context.Context, request *ClientRegistration) (*Client, error) {
	if len(p.registrationURL) == 0 {
		return nil, fmt.Errorf("Can not perform client registration without 'registration_endpoint'")
	}

	enc, err := json.Marshal(request)
	if err != nil {
		return nil, fmt.Errorf("unable to encode request: %v", err)
	}

	req, err := http.NewRequest("POST", p.registrationURL, bytes.NewBuffer(enc))
	req.Header.Add("Content-Type", "application/json")
	if err != nil {
		return nil, err
	}
	resp, err := doRequest(ctx, req)
	if err != nil {
		return nil, err
	}
	defer resp.Body.Close()

	body, err := ioutil.ReadAll(resp.Body)
	if err != nil {
		return nil, fmt.Errorf("unable to read response body: %v", err)
	}

	if resp.StatusCode != http.StatusCreated {
		return nil, fmt.Errorf("%s: %s", resp.Status, body)
	}

	var crr clientRegistrationResponse
	err = unmarshalResp(resp, body, &crr)
	if err != nil {
		return nil, fmt.Errorf("oidc: failed to decode client registration response object: %v", err)
	}

	if crr.Error != "" {
		return nil, fmt.Errorf(
			"oidc: client registration failed: [%s] %s",
			crr.Error,
			crr.ErrorDescription)
	}

	return &crr.Client, nil
}

// A little helper to construct oauth2.Config
// struct from provider & client info.
func (p Provider) OAuth2Config(c *Client) (cfg oauth2.Config) {
	cfg = oauth2.Config{
		ClientID:     c.ID,
		ClientSecret: c.Secret,
		Endpoint:     p.Endpoint(),
	}

	if len(c.RedirectURIs) > 0 {
		cfg.RedirectURL = c.RedirectURIs[0]
	}

	return cfg
}
