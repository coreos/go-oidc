package oidc

import (
	"encoding/json"
	"errors"
	"fmt"
	"io/ioutil"
	"net/http"
	"net/url"

	"golang.org/x/net/context"
	"golang.org/x/oauth2"
)

// ScopeOpenID is the mandatory scope for all OpenID Connect OAuth2 requests.
const ScopeOpenID = "openid"

// TokenVerifier uses public keys to verify a JWT.
type TokenVerifier interface {
	// Verify verifies at least one of the signatures of the JWT and returns the
	// payload associated with JSON Web Token.
	Verify(jwt string) (payload []byte, err error)
}

type IDToken struct {
	Issuer   string   `json:"iss"`
	Subject  string   `json:"sub"`
	Audience string   `json:"aud"`
	Exp      int64    `json:"exp"`
	Iat      int64    `json:"iat"`
	AuthTime int64    `json:"auth_time,omitempty"`
	Nonce    string   `json:"string,omitempty"`
	ACR      string   `json:"acr,omitempty"`
	AMR      []string `json:"amr,omitempty"`
	AZP      string   `json:"azp,omitempty"`
}

// ParseIDToken extracts the OpenID Connect ID Token from an OAuth2 token.
// Is uses the provided TokenVerifier to verify that the token has been signed by the
// appropriate source.
func ParseIDToken(v TokenVerifier, t *oauth2.Token) (*IDToken, error) {
	val := t.Extra("id_token")
	if val == nil {
		return nil, errors.New("oidc: no id_token field in token")
	}
	jwt, ok := val.(string)
	if !ok {
		return nil, errors.New("oidc: id_token field not a string")
	}

	payload, err := v.Verify(jwt)
	if err != nil {
		return nil, err
	}
	var tok IDToken
	if err := json.Unmarshal(payload, &tok); err != nil {
		return nil, fmt.Errorf("oidc: failed to unmarshal token payload: %v", err)
	}
	return &tok, nil
}

type Provider struct {
	Issuer      string   `json:"issuer"`
	AuthURL     string   `json:"authorization_endpoint"`
	TokenURL    string   `json:"token_endpoint"`
	JWKSURL     string   `json:"jwks_uri"`
	UserInfoURL string   `json:"userinfo_endpoint"`
	Scopes      []string `json:"scopes_supported"`
}

// NewProvider uses the OpenID Connect disovery mechanism to construct a Provider.
//
// issuer should be a URL with only a scheme, host, and optional port.
func NewProvider(ctx context.Context, issuer string) (*Provider, error) {
	u, err := url.Parse(issuer)
	if err != nil {
		return nil, fmt.Errorf("oidc: failed to parse issuer as URL: %v", err)
	}
	if u.Path != "" {
		return nil, fmt.Errorf("oidc: issuer is expected to be scheme and host without a path")
	}
	u.Path = "/.well-known/openid-configuration"

	cli := contextClient(ctx)
	resp, err := cli.Get(u.String())
	if err != nil {
		return nil, err
	}
	defer resp.Body.Close()
	var p Provider
	if err := json.NewDecoder(resp.Body).Decode(&p); err != nil {
		return nil, fmt.Errorf("oidc: failed to decode provider at well known config: %v", err)
	}
	return &p, nil
}

// Endpoint returns the OAuth2 auth and token endpoints for the given provider.
func (p *Provider) Endpoint() oauth2.Endpoint {
	return oauth2.Endpoint{AuthURL: p.AuthURL, TokenURL: p.TokenURL}
}

// UserInfo represents the OpenID Connect userinfo claims.
type UserInfo struct {
	Subject       string
	Profile       string
	Email         string
	EmailVerified bool

	// Optionally contains extra claims.
	rawClaims map[string]interface{}
}

// Extra returns additional claims returned by the server.
func (u *UserInfo) Extra(key string) interface{} {
	if u.rawClaims != nil {
		return u.rawClaims[key]
	}
	return nil
}

// UserInfo uses the token source to query the provider's userinfo endpoint.
func (p *Provider) UserInfo(ctx context.Context, tokenSource oauth2.TokenSource) (*UserInfo, error) {
	if p.UserInfoURL == "" {
		return nil, errors.New("oidc: provider doid not provide a userinfo endpoint")
	}
	cli := oauth2.NewClient(ctx, tokenSource)
	resp, err := cli.Get(p.UserInfoURL)
	if err != nil {
		return nil, err
	}
	defer resp.Body.Close()
	body, err := ioutil.ReadAll(resp.Body)
	if err != nil {
		return nil, err
	}
	if resp.StatusCode != http.StatusOK {
		return nil, fmt.Errorf("%s: %s", resp.Status, body)
	}

	var userinfo struct {
		Subject       string `json:"sub"`
		Profile       string `json:"profile"`
		Email         string `json:"email"`
		EmailVerified bool   `json:"email_verified"`
	}
	var raw map[string]interface{}

	if err := json.Unmarshal(body, &userinfo); err != nil {
		return nil, fmt.Errorf("oidc: failed to decode userinfo: %v", err)
	}
	if err := json.Unmarshal(body, &raw); err != nil {
		return nil, fmt.Errorf("oidc: failed to decode userinfo: %v", err)
	}
	return &UserInfo{
		Subject:       userinfo.Subject,
		Profile:       userinfo.Profile,
		Email:         userinfo.Email,
		EmailVerified: userinfo.EmailVerified,
		rawClaims:     raw,
	}, nil
}

// Verifier returns a TokenVerifier that uses the provider's key set to verify JWTs.
//
// The verifier queries the provider to update keys when a signature cannot be verified by the
// set of keys cached from the previous request.
func (p *Provider) Verifier(ctx context.Context) TokenVerifier {
	return newRemoteKeySet(ctx, p.JWKSURL)
}

func contextClient(ctx context.Context) *http.Client {
	if ctx != nil {
		if hc, ok := ctx.Value(oauth2.HTTPClient).(*http.Client); ok {
			return hc
		}
	}
	return http.DefaultClient
}
