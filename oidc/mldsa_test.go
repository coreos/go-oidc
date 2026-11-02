//go:build go1.27

package oidc

import (
	"crypto/mldsa"
	"testing"

	jose "github.com/go-jose/go-jose/v4"
)

func newMLDSAKey(t *testing.T, alg jose.SignatureAlgorithm) *signingKey {
	var params mldsa.Parameters
	switch alg {
	case jose.MLDSA44:
		params = mldsa.MLDSA44()
	case jose.MLDSA65:
		params = mldsa.MLDSA65()
	case jose.MLDSA87:
		params = mldsa.MLDSA87()
	default:
		t.Fatalf("unsupported ML-DSA algorithm: %s", alg)
	}
	priv, err := mldsa.GenerateKey(params)
	if err != nil {
		t.Fatal(err)
	}
	return &signingKey{"", priv, priv.PublicKey(), alg}
}

func TestMLDSAVerify(t *testing.T) {
	for _, alg := range []jose.SignatureAlgorithm{jose.MLDSA44, jose.MLDSA65, jose.MLDSA87} {
		t.Run(string(alg), func(t *testing.T) {
			good := newMLDSAKey(t, alg)
			bad := newMLDSAKey(t, alg)
			testKeyVerify(t, good, bad, good)
		})
	}
}

func TestMLDSAVerifyIDToken(t *testing.T) {
	for _, alg := range []string{MLDSA44, MLDSA65, MLDSA87} {
		t.Run(alg, func(t *testing.T) {
			key := newMLDSAKey(t, jose.SignatureAlgorithm(alg))
			otherKey := newMLDSAKey(t, jose.SignatureAlgorithm(alg))

			tests := []verificationTest{
				{
					name:    "good token",
					idToken: `{"iss":"https://foo"}`,
					config: Config{
						SkipClientIDCheck:    true,
						SkipExpiryCheck:      true,
						SupportedSigningAlgs: []string{alg},
					},
					signKey: key,
				},
				{
					name:    "invalid sig",
					idToken: `{"iss":"https://foo"}`,
					config: Config{
						SkipClientIDCheck:    true,
						SkipExpiryCheck:      true,
						SupportedSigningAlgs: []string{alg},
					},
					signKey:         key,
					verificationKey: otherKey,
					wantErr:         true,
				},
				{
					name:    "bad signing alg",
					idToken: `{"iss":"https://foo"}`,
					config: Config{
						SkipClientIDCheck: true,
						SkipExpiryCheck:   true,
					},
					signKey: key,
					wantErr: true,
				},
			}
			for _, test := range tests {
				t.Run(test.name, test.run)
			}
		})
	}
}
