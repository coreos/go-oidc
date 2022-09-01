package oidctest_test

import (
	"context"
	"crypto/rand"
	"crypto/rsa"
	"net/http/httptest"
	"strconv"
	"testing"
	"time"

	"github.com/coreos/go-oidc/v3/oidc"
	"github.com/coreos/go-oidc/v3/oidc/oidctest"
)

func TestServer(t *testing.T) {
	priv, err := rsa.GenerateKey(rand.Reader, 2048)
	if err != nil {
		t.Fatalf("creating server: %v", err)
	}

	s := &oidctest.Server{
		PublicKeys: []oidctest.PublicKey{
			{
				PublicKey: priv.Public(),
				KeyID:     "my-key-id",
				Algorithm: oidc.RS256,
			},
		},
	}
	srv := httptest.NewServer(s)
	defer srv.Close()
	s.SetIssuer(srv.URL)

	now := time.Now()
	rawClaims := `{
		"iss": "` + srv.URL + `",
		"aud": "my-client-id",
		"sub": "foo",
		"exp": ` + strconv.FormatInt(now.Add(time.Hour).Unix(), 10) + `,
		"email": "foo@example.com",
		"email_verified": true
	}`
	token := oidctest.SignIDToken(priv, "my-key-id", oidc.RS256, rawClaims)

	ctx := context.Background()
	p, err := oidc.NewProvider(ctx, srv.URL)
	if err != nil {
		t.Fatalf("new provider: %v", err)
	}
	config := &oidc.Config{
		ClientID: "my-client-id",
		Now:      func() time.Time { return now },
	}
	v := p.VerifierContext(ctx, config)

	idToken, err := v.Verify(ctx, token)
	if err != nil {
		t.Fatalf("verifying token: %v", err)
	}
	if want := "foo"; idToken.Subject != want {
		t.Errorf("ID token returned unexpected subject, got=%v, want=%v", idToken.Subject, want)
	}

	var claims struct {
		Email         string `json:"email"`
		EmailVerified bool   `json:"email_verified"`
	}
	if err := idToken.Claims(&claims); err != nil {
		t.Fatalf("parsing id token claims: %v", err)
	}
	if want := "foo@example.com"; claims.Email != want {
		t.Errorf("ID token returned unexpected email, got=%v, want=%v", claims.Email, want)
	}
	if want := true; claims.EmailVerified != want {
		t.Errorf("ID token returned unexpected email_verified, got=%v, want=%v", claims.EmailVerified, want)
	}
}
