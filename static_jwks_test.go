package oidc

import (
	"bytes"
	"context"
	"testing"

	jose "gopkg.in/square/go-jose.v2"
)

func TestStaticRSAVerify(t *testing.T) {
	good := newRSAKey(t)
	bad := newRSAKey(t)

	testStaticKeyVerify(t, good, bad, good)
}

func testStaticKeyVerify(t *testing.T, good, bad *signingKey, verification ...*signingKey) {
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

	sks := newStaticKeySet(keySet)

	gotPayload, err := sks.verify(ctx, jws)
	if err != nil {
		t.Fatal(err)
	}
	if !bytes.Equal(gotPayload, payload) {
		t.Errorf("expected payload %s got %s", payload, gotPayload)
	}

	// Ensure item signed by wrong token doesn't verify.
	if _, err := sks.verify(context.Background(), badJWS); err == nil {
		t.Errorf("incorrectly verified signature")
	}
}
