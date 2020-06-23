package oidc

import (
	"context"
	"fmt"
	"io"
	"net/http"
	"net/http/httptest"
	"reflect"
	"strings"
	"testing"
)

const (
	// at_hash value and access_token returned by Google.
	googleAccessTokenHash = "piwt8oCH-K2D9pXlaS1Y-w"
	googleAccessToken     = "ya29.CjHSA1l5WUn8xZ6HanHFzzdHdbXm-14rxnC7JHch9eFIsZkQEGoWzaYG4o7k5f6BnPLj"
	googleSigningAlg      = RS256
	// following values computed by own algo for regression testing
	computed384TokenHash = "_ILKVQjbEzFKNJjUKC2kz9eReYi0A9Of"
	computed512TokenHash = "Spa_APgwBrarSeQbxI-rbragXho6dqFpH5x9PqaPfUI"
)

type accessTokenTest struct {
	name        string
	tok         *IDToken
	accessToken string
	verifier    func(err error) error
}

func (a accessTokenTest) run(t *testing.T) {
	err := a.tok.VerifyAccessToken(a.accessToken)
	result := a.verifier(err)
	if result != nil {
		t.Error(result)
	}
}

func TestAccessTokenVerification(t *testing.T) {
	newToken := func(alg, atHash string) *IDToken {
		return &IDToken{sigAlgorithm: alg, AccessTokenHash: atHash}
	}
	assertNil := func(err error) error {
		if err != nil {
			return fmt.Errorf("want nil error, got %v", err)
		}
		return nil
	}
	assertMsg := func(msg string) func(err error) error {
		return func(err error) error {
			if err == nil {
				return fmt.Errorf("expected error, got success")
			}
			if err.Error() != msg {
				return fmt.Errorf("bad error message, %q, (want %q)", err.Error(), msg)
			}
			return nil
		}
	}
	tests := []accessTokenTest{
		{
			"goodRS256",
			newToken(googleSigningAlg, googleAccessTokenHash),
			googleAccessToken,
			assertNil,
		},
		{
			"goodES384",
			newToken("ES384", computed384TokenHash),
			googleAccessToken,
			assertNil,
		},
		{
			"goodPS512",
			newToken("PS512", computed512TokenHash),
			googleAccessToken,
			assertNil,
		},
		{
			"badRS256",
			newToken("RS256", computed512TokenHash),
			googleAccessToken,
			assertMsg("access token hash does not match value in ID token"),
		},
		{
			"nohash",
			newToken("RS256", ""),
			googleAccessToken,
			assertMsg("id token did not have an access token hash"),
		},
		{
			"badSignAlgo",
			newToken("none", "xxx"),
			googleAccessToken,
			assertMsg(`oidc: unsupported signing algorithm "none"`),
		},
	}
	for _, test := range tests {
		t.Run(test.name, test.run)
	}
}

func TestNewProvider(t *testing.T) {
	tests := []struct {
		name            string
		data            string
		trailingSlash   bool
		wantAuthURL     string
		wantTokenURL    string
		wantUserInfoURL string
		wantAlgorithms  []string
		wantErr         bool
	}{
		{
			name: "basic_case",
			data: `{
				"issuer": "ISSUER",
				"authorization_endpoint": "https://example.com/auth",
				"token_endpoint": "https://example.com/token",
				"jwks_uri": "https://example.com/keys",
				"id_token_signing_alg_values_supported": ["RS256"]
			}`,
			wantAuthURL:    "https://example.com/auth",
			wantTokenURL:   "https://example.com/token",
			wantAlgorithms: []string{"RS256"},
		},
		{
			name: "additional_algorithms",
			data: `{
				"issuer": "ISSUER",
				"authorization_endpoint": "https://example.com/auth",
				"token_endpoint": "https://example.com/token",
				"jwks_uri": "https://example.com/keys",
				"id_token_signing_alg_values_supported": ["RS256", "RS384", "ES256"]
			}`,
			wantAuthURL:    "https://example.com/auth",
			wantTokenURL:   "https://example.com/token",
			wantAlgorithms: []string{"RS256", "RS384", "ES256"},
		},
		{
			name: "unsupported_algorithms",
			data: `{
				"issuer": "ISSUER",
				"authorization_endpoint": "https://example.com/auth",
				"token_endpoint": "https://example.com/token",
				"jwks_uri": "https://example.com/keys",
				"id_token_signing_alg_values_supported": [
					"RS256", "RS384", "ES256", "HS256", "none"
				]
			}`,
			wantAuthURL:    "https://example.com/auth",
			wantTokenURL:   "https://example.com/token",
			wantAlgorithms: []string{"RS256", "RS384", "ES256"},
		},
		{
			name: "mismatched_issuer",
			data: `{
				"issuer": "https://example.com",
				"authorization_endpoint": "https://example.com/auth",
				"token_endpoint": "https://example.com/token",
				"jwks_uri": "https://example.com/keys",
				"id_token_signing_alg_values_supported": ["RS256"]
			}`,
			wantErr: true,
		},
		{
			name: "issuer_with_trailing_slash",
			data: `{
				"issuer": "ISSUER",
				"authorization_endpoint": "https://example.com/auth",
				"token_endpoint": "https://example.com/token",
				"jwks_uri": "https://example.com/keys",
				"id_token_signing_alg_values_supported": ["RS256"]
			}`,
			trailingSlash:  true,
			wantAuthURL:    "https://example.com/auth",
			wantTokenURL:   "https://example.com/token",
			wantAlgorithms: []string{"RS256"},
		},
		{
			// Test case taken directly from:
			// https://accounts.google.com/.well-known/openid-configuration
			name:            "google",
			wantAuthURL:     "https://accounts.google.com/o/oauth2/v2/auth",
			wantTokenURL:    "https://oauth2.googleapis.com/token",
			wantUserInfoURL: "https://openidconnect.googleapis.com/v1/userinfo",
			wantAlgorithms:  []string{"RS256"},
			data: `{
 "issuer": "ISSUER",
 "authorization_endpoint": "https://accounts.google.com/o/oauth2/v2/auth",
 "device_authorization_endpoint": "https://oauth2.googleapis.com/device/code",
 "token_endpoint": "https://oauth2.googleapis.com/token",
 "userinfo_endpoint": "https://openidconnect.googleapis.com/v1/userinfo",
 "revocation_endpoint": "https://oauth2.googleapis.com/revoke",
 "jwks_uri": "https://www.googleapis.com/oauth2/v3/certs",
 "response_types_supported": [
  "code",
  "token",
  "id_token",
  "code token",
  "code id_token",
  "token id_token",
  "code token id_token",
  "none"
 ],
 "subject_types_supported": [
  "public"
 ],
 "id_token_signing_alg_values_supported": [
  "RS256"
 ],
 "scopes_supported": [
  "openid",
  "email",
  "profile"
 ],
 "token_endpoint_auth_methods_supported": [
  "client_secret_post",
  "client_secret_basic"
 ],
 "claims_supported": [
  "aud",
  "email",
  "email_verified",
  "exp",
  "family_name",
  "given_name",
  "iat",
  "iss",
  "locale",
  "name",
  "picture",
  "sub"
 ],
 "code_challenge_methods_supported": [
  "plain",
  "S256"
 ],
 "grant_types_supported": [
  "authorization_code",
  "refresh_token",
  "urn:ietf:params:oauth:grant-type:device_code",
  "urn:ietf:params:oauth:grant-type:jwt-bearer"
 ]
}`,
		},
	}
	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			ctx, cancel := context.WithCancel(context.Background())
			defer cancel()

			var issuer string
			hf := func(w http.ResponseWriter, r *http.Request) {
				if r.URL.Path != "/.well-known/openid-configuration" {
					http.NotFound(w, r)
					return
				}
				w.Header().Set("Content-Type", "application/json")
				io.WriteString(w, strings.ReplaceAll(test.data, "ISSUER", issuer))
			}
			s := httptest.NewServer(http.HandlerFunc(hf))
			defer s.Close()

			issuer = s.URL
			if test.trailingSlash {
				issuer += "/"
			}

			p, err := NewProvider(ctx, issuer)
			if err != nil {
				if !test.wantErr {
					t.Errorf("NewProvider() failed: %v", err)
				}
				return
			}
			if test.wantErr {
				t.Fatalf("NewProvider(): expected error")
			}

			if p.authURL != test.wantAuthURL {
				t.Errorf("NewProvider() unexpected authURL value, got=%s, want=%s",
					p.authURL, test.wantAuthURL)
			}
			if p.tokenURL != test.wantTokenURL {
				t.Errorf("NewProvider() unexpected tokenURL value, got=%s, want=%s",
					p.tokenURL, test.wantTokenURL)
			}
			if p.userInfoURL != test.wantUserInfoURL {
				t.Errorf("NewProvider() unexpected userInfoURL value, got=%s, want=%s",
					p.userInfoURL, test.wantUserInfoURL)
			}
			if !reflect.DeepEqual(p.algorithms, test.wantAlgorithms) {
				t.Errorf("NewProvider() unexpected algorithms value, got=%s, want=%s",
					p.algorithms, test.wantAlgorithms)
			}
		})
	}
}
