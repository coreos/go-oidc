package oidc

import (
	"bytes"
	"context"
	"crypto/ecdsa"
	"crypto/ed25519"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/rsa"
	"encoding/json"
	"errors"
	"fmt"
	"net/http"
	"net/http/httptest"
	"strconv"
	"testing"
	"time"

	jose "github.com/go-jose/go-jose/v3"
)

type keyServer struct {
	keys       jose.JSONWebKeySet
	setHeaders func(h http.Header)
}

func (k *keyServer) ServeHTTP(w http.ResponseWriter, r *http.Request) {
	if k.setHeaders != nil {
		k.setHeaders(w.Header())
	}
	if err := json.NewEncoder(w).Encode(k.keys); err != nil {
		panic(err)
	}
}

type signingKey struct {
	keyID string // optional
	priv  interface{}
	pub   interface{}
	alg   jose.SignatureAlgorithm
}

// sign creates a JWS using the private key from the provided payload.
func (s *signingKey) sign(t testing.TB, payload []byte) string {
	privKey := &jose.JSONWebKey{Key: s.priv, Algorithm: string(s.alg), KeyID: s.keyID}

	signer, err := jose.NewSigner(jose.SigningKey{Algorithm: s.alg, Key: privKey}, nil)
	if err != nil {
		t.Fatal(err)
	}
	jws, err := signer.Sign(payload)
	if err != nil {
		t.Fatal(err)
	}

	data, err := jws.CompactSerialize()
	if err != nil {
		t.Fatal(err)
	}
	return data
}

func (s *signingKey) jwk() jose.JSONWebKey {
	return jose.JSONWebKey{Key: s.pub, Use: "sig", Algorithm: string(s.alg), KeyID: s.keyID}
}

func newRSAKey(t testing.TB) *signingKey {
	priv, err := rsa.GenerateKey(rand.Reader, 1028)
	if err != nil {
		t.Fatal(err)
	}
	return &signingKey{"", priv, priv.Public(), jose.RS256}
}

func newECDSAKey(t *testing.T) *signingKey {
	priv, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	return &signingKey{"", priv, priv.Public(), jose.ES256}
}

func newEdDSAKey(t *testing.T) *signingKey {
	publicKey, privateKey, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	return &signingKey{"", privateKey, publicKey, jose.EdDSA}
}

func TestRSAVerify(t *testing.T) {
	good := newRSAKey(t)
	bad := newRSAKey(t)

	testKeyVerify(t, good, bad, good)
}

func TestECDSAVerify(t *testing.T) {
	good := newECDSAKey(t)
	bad := newECDSAKey(t)
	testKeyVerify(t, good, bad, good)
}

func TestEdDSAVerify(t *testing.T) {
	good := newEdDSAKey(t)
	bad := newEdDSAKey(t)
	testKeyVerify(t, good, bad, good)
}

func TestMultipleKeysVerify(t *testing.T) {
	key1 := newRSAKey(t)
	key2 := newRSAKey(t)
	bad := newECDSAKey(t)

	key1.keyID = "key1"
	key2.keyID = "key2"
	bad.keyID = "key3"

	testKeyVerify(t, key2, bad, key1, key2)
}

func TestMismatchedKeyID(t *testing.T) {
	key1 := newRSAKey(t)
	key2 := newRSAKey(t)

	// shallow copy
	bad := new(signingKey)
	*bad = *key1

	// The bad key is a valid key this time, but has a different Key ID.
	// It shouldn't match key1 because of the mismatched ID, even though
	// it would confirm the signature just fine.
	bad.keyID = "key3"

	key1.keyID = "key1"
	key2.keyID = "key2"

	testKeyVerify(t, key2, bad, key1, key2)
}

func TestKeyVerifyContextCanceled(t *testing.T) {
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()

	payload := []byte("a secret")

	good := newECDSAKey(t)
	jws, err := jose.ParseSigned(good.sign(t, payload))
	if err != nil {
		t.Fatal(err)
	}

	ch := make(chan struct{})
	defer close(ch)

	s := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		<-ch
	}))
	defer s.Close()

	rks := newRemoteKeySet(ctx, s.URL, nil)

	cancel()

	// Ensure the token verifies.
	_, err = rks.verify(ctx, jws)
	if err == nil {
		t.Fatal("expected context canceled, got nil error")
	}

	if !errors.Is(err, context.Canceled) {
		t.Errorf("expected error to be %q got %q", context.Canceled, err)
	}
}

func testKeyVerify(t *testing.T, good, bad *signingKey, verification ...*signingKey) {
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()

	keySet := jose.JSONWebKeySet{}
	for _, v := range verification {
		keySet.Keys = append(keySet.Keys, v.jwk())
	}

	payload := []byte("a secret")

	jws, err := jose.ParseSigned(good.sign(t, payload))
	if err != nil {
		t.Fatal(err)
	}
	badJWS, err := jose.ParseSigned(bad.sign(t, payload))
	if err != nil {
		t.Fatal(err)
	}

	s := httptest.NewServer(&keyServer{keys: keySet})
	defer s.Close()

	rks := newRemoteKeySet(ctx, s.URL, nil)

	// Ensure the token verifies.
	gotPayload, err := rks.verify(ctx, jws)
	if err != nil {
		t.Fatal(err)
	}
	if !bytes.Equal(gotPayload, payload) {
		t.Errorf("expected payload %s got %s", payload, gotPayload)
	}

	// Ensure the token verifies from the cache.
	gotPayload, err = rks.verify(ctx, jws)
	if err != nil {
		t.Fatal(err)
	}
	if !bytes.Equal(gotPayload, payload) {
		t.Errorf("expected payload %s got %s", payload, gotPayload)
	}

	// Ensure item signed by wrong token doesn't verify.
	if _, err := rks.verify(context.Background(), badJWS); err == nil {
		t.Errorf("incorrectly verified signature")
	}
}

func TestRotation(t *testing.T) {
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()

	key1 := newRSAKey(t)
	key2 := newRSAKey(t)

	key1.keyID = "key1"
	key2.keyID = "key2"

	payload := []byte("a secret")
	jws1, err := jose.ParseSigned(key1.sign(t, payload))
	if err != nil {
		t.Fatal(err)
	}
	jws2, err := jose.ParseSigned(key2.sign(t, payload))
	if err != nil {
		t.Fatal(err)
	}

	cacheForSeconds := 1200
	now := time.Now()

	server := &keyServer{
		keys: jose.JSONWebKeySet{
			Keys: []jose.JSONWebKey{key1.jwk()},
		},
		setHeaders: func(h http.Header) {
			h.Set("Cache-Control", "max-age="+strconv.Itoa(cacheForSeconds))
		},
	}
	s := httptest.NewServer(server)
	defer s.Close()

	rks := newRemoteKeySet(ctx, s.URL, func() time.Time { return now })

	if _, err := rks.verify(ctx, jws1); err != nil {
		t.Errorf("failed to verify valid signature: %v", err)
	}
	if _, err := rks.verify(ctx, jws2); err == nil {
		t.Errorf("incorrectly verified signature")
	}

	// Add second key to public list.
	server.keys = jose.JSONWebKeySet{
		Keys: []jose.JSONWebKey{key1.jwk(), key2.jwk()},
	}

	if _, err := rks.verify(ctx, jws1); err != nil {
		t.Errorf("failed to verify valid signature: %v", err)
	}
	if _, err := rks.verify(ctx, jws2); err != nil {
		t.Errorf("failed to verify valid signature: %v", err)
	}

	// Kill server. Keys should still be cached.
	s.Close()

	if _, err := rks.verify(ctx, jws1); err != nil {
		t.Errorf("failed to verify valid signature: %v", err)
	}
	if _, err := rks.verify(ctx, jws2); err != nil {
		t.Errorf("failed to verify valid signature: %v", err)
	}
}

func BenchmarkVerify(b *testing.B) {
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()

	key := newRSAKey(b)

	now := time.Date(2022, 1, 29, 0, 0, 0, 0, time.UTC)
	exp := now.Add(time.Hour)
	payload := []byte(fmt.Sprintf(`{
		"iss": "https://example.com",
		"sub": "test_user",
		"aud": "test_client_id",
		"exp": %d
	}`, exp.Unix()))

	idToken := key.sign(b, payload)
	server := &keyServer{
		keys: jose.JSONWebKeySet{
			Keys: []jose.JSONWebKey{key.jwk()},
		},
	}
	s := httptest.NewServer(server)
	defer s.Close()

	rks := NewRemoteKeySet(ctx, s.URL)
	verifier := NewVerifier("https://example.com", rks, &Config{
		ClientID: "test_client_id",
		Now:      func() time.Time { return now },
	})

	// Trigger the remote key set to query the public keys and cache them.
	if _, err := verifier.Verify(ctx, idToken); err != nil {
		b.Fatalf("verifying id token: %v", err)
	}

	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		if _, err := verifier.Verify(ctx, idToken); err != nil {
			b.Fatalf("verifying id token: %v", err)
		}
	}
}
