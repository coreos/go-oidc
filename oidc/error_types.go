package oidc

import (
	"fmt"
	"time"
)

// MalformedJWTError is returned when the JWT can't be parsed
type MalformedJWTError struct {
	ParseError error
}

// Error interface
func (e *MalformedJWTError) Error() string {
	return fmt.Sprintf("oidc: malformed jwt: %v", e.ParseError)
}

// MalformedPayloadError is returned when it's impossible to unmarshal the
// JWT payload
type MalformedPayloadError struct {
	UnmarshalError error
}

// Error interface
func (e *MalformedPayloadError) Error() string {
	return fmt.Sprintf("oidc: failed to unmarshal claims: %v", e.UnmarshalError)
}

// InvalidClaimNameError is returned when a claim name returns no claim source
type InvalidClaimNameError struct {
	Name string
}

// Error interface
func (e *InvalidClaimNameError) Error() string {
	return fmt.Sprintf("oidc: failed to obtain source from claim '%s'", e.Name)
}

// InvalidClaimSourceError is returned when a claim name references a
// non existing source
type InvalidClaimSourceError struct {
	Name   string
	Source string
}

// Error interface
func (e *InvalidClaimSourceError) Error() string {
	return fmt.Sprintf("oidc: source '%s', referenced by '%s', does not exist", e.Source, e.Name)
}

// InvalidIssuerError is returned when the JWT issuer in incorrect
type InvalidIssuerError struct {
	Expected string
	Actual   string
}

// Error interface
func (e *InvalidIssuerError) Error() string {
	return fmt.Sprintf("oidc: id token issued by a different provider, expected %q got %q", e.Expected, e.Actual)
}

// InvalidAudienceError is returned when the audience is different from what was
// expected
type InvalidAudienceError struct {
	Expected string
	Actual   []string
}

// Error interface
func (e *InvalidAudienceError) Error() string {
	return fmt.Sprintf("oidc: expected audience %q got %q", e.Expected, e.Actual)
}

// InvalidClientIDConfigurationError is returned if no client_id is specified
// when needed or vice-versa
type InvalidClientIDConfigurationError struct{}

// Error interface
func (e *InvalidClientIDConfigurationError) Error() string {
	return "oidc: invalid configuration, clientID must be provided or SkipClientIDCheck must be set"
}

// ExpiredTokenError is returned when a token is expired
type ExpiredTokenError struct {
	Expiry time.Time
}

// Error interface
func (e *ExpiredTokenError) Error() string {
	return fmt.Sprintf("oidc: token is expired (Token Expiry: %v)", e.Expiry)
}

// TokenNotYetValidError is returned when a token supplies NotBefore but is dated
// after it
type TokenNotYetValidError struct {
	NowTime time.Time
	NbfTime time.Time
}

// Error interface
func (e *TokenNotYetValidError) Error() string {
	return fmt.Sprintf("oidc: current time %v before the nbf (not before) time: %v", e.NowTime, e.NbfTime)
}

// UnsignedTokenError is returned when token lacks signatures
type UnsignedTokenError struct{}

// Error interface
func (e *UnsignedTokenError) Error() string {
	return "oidc: id token not signed"
}

// MultipleSignaturesError is returned when token has more than one sig
type MultipleSignaturesError struct{}

// Error interface
func (e *MultipleSignaturesError) Error() string {
	return "oidc: multiple signatures on id token not supported"
}

// UnsupportedSigningError is returned when token has an unsopported signing
// algorithm
type UnsupportedSigningError struct {
	Supported []string
	Provided  string
}

// Error interface
func (e *UnsupportedSigningError) Error() string {
	return fmt.Sprintf("oidc: id token signed with unsupported algorithm, expected %q got %q", e.Supported, e.Provided)
}

// InvalidSignatureError is returned when the signature cannot be verified
type InvalidSignatureError struct {
	VerificationError error
}

// Error interface
func (e *InvalidSignatureError) Error() string {
	return fmt.Sprintf("failed to verify signature: %v", e.VerificationError)
}

// PayloadMismatchError is returned when there is a mismatch between original
// payload and verified payload
type PayloadMismatchError struct{}

// Error interface
func (e *PayloadMismatchError) Error() string {
	return "oidc: internal error, payload parsed did not match previous payload"
}
