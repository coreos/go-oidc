package oidc

import (
	"context"
	"errors"
	"fmt"

	jose "gopkg.in/square/go-jose.v2"
)

// NewStaticKeySet returns a KeySet that validates JWTs by using a predefined
// jose.JSONWebKeySet (a set of public keys that are trusted).
// This can be useful for testing.
func NewStaticKeySet(keys jose.JSONWebKeySet) KeySet {
	return newStaticKeySet(keys)
}

func newStaticKeySet(keys jose.JSONWebKeySet) *staticKeySet {
	return &staticKeySet{keys: keys}
}

type staticKeySet struct {
	keys jose.JSONWebKeySet
}

// VerifySignature verifies a JWT based on a static JSONWebKeySet
func (l *staticKeySet) VerifySignature(ctx context.Context, jwt string) ([]byte, error) {
	jws, err := jose.ParseSigned(jwt)
	if err != nil {
		return nil, fmt.Errorf("oidc: malformed jwt: %v", err)
	}

	return l.verify(ctx, jws)
}

func (l *staticKeySet) verify(ctx context.Context, jws *jose.JSONWebSignature) ([]byte, error) {

	for _, key := range l.keys.Keys {
		_, _, payload, err := jws.VerifyMulti(key)
		if err != nil {
			return nil, fmt.Errorf("oidc: failed to verify id token signature: %v", err)
		}

		return payload, nil
	}

	return nil, errors.New("failed to verify id token signature")
}
