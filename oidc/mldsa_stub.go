//go:build !go1.27

package oidc

import "crypto"

func isMLDSAPublicKey(_ crypto.PublicKey) bool {
	return false
}
