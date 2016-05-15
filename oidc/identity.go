package oidc

import (
	"errors"
	"time"

	"github.com/coreos/go-oidc/jose"
)

type Address struct { // 5.1.1 Address Claim
	Formatted     string // formatted
	StreetAddress string // street_address
	Locality      string // locality
	Region        string // region
	PostalCode    string // postal_code
	Country       string // country
}

type Identity struct { // 5.1. Standard Claims
	ID                  string // sub
	Name                string // name
	GivenName           string // given_name
	FamilyName          string // family_name
	MiddleName          string // middle_name
	Nickname            string // nickname
	PreferredUsername   string // preferred_username
	Profile             string // profile
	Website             string // website
	Email               string // email
	EmailVerified       bool   // email_verified
	Gender              string // gender
	Birthdate           string // birthdate
	Zoneinfo            string // zoneinfo
	Locale              string // locale
	PhoneNumber         string // phone_number
	PhoneNumberVerified bool   // phone_number_verified
	Address             Address
	AdditionalClaims    map[string]string
	ExpiresAt           time.Time
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
