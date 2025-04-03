// Package oidctest implements a test OpenID Connect server.
//
// For convinence, methods in this package panic rather than returning errors.
// This package is NOT suitable for use outside of tests.
//
// This package is primarily intended to be used with the standard library's
// [net/http/httpttest] package. Users should configure a key pair and setup
// a server:
//
//	priv, err := rsa.GenerateKey(rand.Reader, 2048)
//	if err != nil {
//		// ...
//	}
//	s := &oidctest.Server{
//		PublicKeys: []oidctest.PublicKey{
//			{
//				PublicKey: priv.Public(),
//				KeyID:     "my-key-id",
//				Algorithm: oidc.ES256,
//			},
//		},
//	}
//	srv := httptest.NewServer(s)
//	defer srv.Close()
//	s.SetIssuer(srv.URL)
//
// Then sign a token:
//
//	rawClaims := `{
//		"iss": "` + srv.URL + `",
//		"aud": "my-client-id",
//		"sub": "foo",
//		"email": "foo@example.com",
//		"email_verified": true
//	}`
//	token := oidctest.SignIDToken(priv, "my-key-id", oidc.RS256, rawClaims)
//
// And finaly, verify through the oidc package:
//
//	ctx := context.Background()
//	p, err := oidc.NewProvider(ctx, srv.URL)
//	if err != nil {
//		// ...
//	}
//	config := &oidc.Config{
//		ClientID:        "my-client-id",
//		SkipExpiryCheck: true,
//	}
//	v := p.VerifierContext(ctx, config)
//
//	idToken, err := v.Verify(ctx, token)
//	if err != nil {
//		// ...
//	}
package oidctest

import (
	"crypto"
	"encoding/json"
	"fmt"
	"net/http"
	"net/url"

	jose "github.com/go-jose/go-jose/v4"
)

// SignIDToken uses a private key to sign provided claims.
//
// A minimal set of claims may look like:
//
//	rawClaims := `{
//		"iss": "` + srv.URL + `",
//		"aud": "my-client-id",
//		"sub": "foo",
//		"exp": ` + strconv.FormatInt(time.Now().Add(time.Hour).Unix(), 10) + `,
//		"email": "foo@example.com",
//		"email_verified": true
//	}`
//	token := oidctest.SignIDToken(priv, "my-key-id", oidc.RS256, rawClaims)
func SignIDToken(priv crypto.PrivateKey, keyID, alg, claims string) string {
	token, err := newToken(priv, keyID, alg, claims)
	if err != nil {
		panic("oidctest: generating token: " + err.Error())
	}
	return token
}

func newToken(priv crypto.PrivateKey, keyID, alg, claims string) (string, error) {
	key := jose.SigningKey{
		Algorithm: jose.SignatureAlgorithm(alg),
		Key:       priv,
	}
	opts := &jose.SignerOptions{
		ExtraHeaders: map[jose.HeaderKey]interface{}{
			jose.HeaderKey("kid"): keyID,
		},
	}

	signer, err := jose.NewSigner(key, opts)
	if err != nil {
		return "", fmt.Errorf("creating signer: %v", err)
	}
	sig, err := signer.Sign([]byte(claims))
	if err != nil {
		return "", fmt.Errorf("signing payload: %v", err)
	}
	jwt, err := sig.CompactSerialize()
	if err != nil {
		return "", fmt.Errorf("serializing jwt: %v", err)
	}
	return jwt, nil
}

// PublicKey holds a public key as well as additional metadata about that
// key.
type PublicKey struct {
	// Either *rsa.PublicKey or *ecdsa.PublicKey.
	PublicKey crypto.PublicKey
	// The ID of the key. Should match the value passed to [SignIDToken].
	KeyID string
	// Signature algorithm used by the public key, such as "RS256" or "RS256".
	Algorithm string
}

// Server holds configuration for the OpenID Connect test server.
type Server struct {
	// Public keys advertised by the server that can be used to sign tokens.
	PublicKeys []PublicKey
	// The set of signing algorithms used by the server. Defaults to "RS256".
	Algorithms []string

	issuerURL *url.URL
}

// SetIssuer must be called before serving traffic. This is usually the
// [httptest.Server.URL].
func (s *Server) SetIssuer(issuerURL string) {
	u, err := url.Parse(issuerURL)
	if err != nil {
		panic("oidctest: invalid issuer URL: " + err.Error())
	}
	s.issuerURL = u
}

// ServeHTTP is the server's implementation of [http.Handler].
func (s *Server) ServeHTTP(w http.ResponseWriter, r *http.Request) {
	switch r.URL.Path {
	case "/.well-known/openid-configuration":
		if r.Method != http.MethodGet {
			http.Error(w, "Expected GET request for discovery endpoint, got: "+r.Method,
				http.StatusMethodNotAllowed)
			return
		}
		s.serveDiscovery(w, r)
	case "/keys":
		if r.Method != http.MethodGet {
			http.Error(w, "Expected GET request for keys endpoint, got: "+r.Method,
				http.StatusMethodNotAllowed)
			return
		}
		s.serveKeys(w, r)
	default:
		http.Error(w, "Unknown path: "+r.URL.Path, http.StatusNotFound)
	}
}

func (s *Server) serveDiscovery(w http.ResponseWriter, r *http.Request) {
	if s.issuerURL == nil {
		http.Error(w, "oidctest: server called without SetIssuer()", http.StatusInternalServerError)
		return
	}

	algs := s.Algorithms
	if len(algs) == 0 {
		algs = []string{"RS256"}
	}
	disc := struct {
		Issuer        string   `json:"issuer"`
		Auth          string   `json:"authorization_endpoint"`
		Token         string   `json:"token_endpoint"`
		JWKs          string   `json:"jwks_uri"`
		ResponseTypes []string `json:"response_types_supported"`
		SubjectTypes  []string `json:"subject_types_supported"`
		Algs          []string `json:"id_token_signing_alg_values_supported"`
	}{
		Issuer:        s.issuerURL.String(),
		Auth:          s.issuerURL.JoinPath("/auth").String(),
		Token:         s.issuerURL.JoinPath("/token").String(),
		JWKs:          s.issuerURL.JoinPath("/keys").String(),
		ResponseTypes: []string{"code", "id_token", "token id_token"},
		SubjectTypes:  []string{"public"},
		Algs:          algs,
	}

	w.Header().Set("Content-Type", "application/json")
	json.NewEncoder(w).Encode(disc)
}

func (s *Server) serveKeys(w http.ResponseWriter, r *http.Request) {
	set := &jose.JSONWebKeySet{}
	for _, pub := range s.PublicKeys {
		k := jose.JSONWebKey{
			Key:       pub.PublicKey,
			KeyID:     pub.KeyID,
			Algorithm: pub.Algorithm,
			Use:       "sig",
		}
		set.Keys = append(set.Keys, k)
	}

	w.Header().Set("Content-Type", "application/json")
	json.NewEncoder(w).Encode(set)
}
