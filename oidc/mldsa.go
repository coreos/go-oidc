//go:build go1.27

package oidc

import (
	"crypto"
	"crypto/mldsa"

	jose "github.com/go-jose/go-jose/v4"
)

func init() {
	for _, alg := range []jose.SignatureAlgorithm{jose.MLDSA44, jose.MLDSA65, jose.MLDSA87} {
		allAlgs = append(allAlgs, alg)
		supportedJOSEAlgs[string(alg)] = true
		supportedAlgorithms[string(alg)] = true
	}
}

func isMLDSAPublicKey(pub crypto.PublicKey) bool {
	_, ok := pub.(*mldsa.PublicKey)
	return ok
}
