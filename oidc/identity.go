package oidc

import (
	"errors"
	"time"

	"github.com/coreos/go-oidc/jose"
)

type Identity struct {
	ID              string
	Name            string
	Email           string
	ExpiresAt       time.Time
	AdditonalClaims jose.Claims
}

func IdentityFromClaims(claims jose.Claims) (*Identity, error) {
	if claims == nil {
		return nil, errors.New("nil claim set")
	}

	var ident Identity
	var err error
	var ok bool

	if ident.ID, ok, err = claims.StringClaim("sub"); err != nil {
		return nil, err
	} else if !ok {
		return nil, errors.New("missing required claim: sub")
	}

	if ident.Email, _, err = claims.StringClaim("email"); err != nil {
		return nil, err
	}

	exp, ok, err := claims.TimeClaim("exp")
	if err != nil {
		return nil, err
	} else if ok {
		ident.ExpiresAt = exp
	}

	return &ident, nil
}

// CopyAdditonalClaims copies all additional claims to claims
func (ident *Identity) CopyAdditonalClaims(claims jose.Claims) {
	if ident.AdditonalClaims == nil {
		return
	}

	for k, v := range ident.AdditonalClaims {
		// TODO: ignore standard claims; related to issue #14
		claims.Add(k, v)
	}
}
