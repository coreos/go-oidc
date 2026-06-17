package oidc

import (
	"fmt"
	"time"
)

// TokenExpiredError indicates that Verify failed because the token was expired. This
// error does NOT indicate that the token is not also invalid for other reasons. Other
// checks might have failed if the expiration check had not failed.
type TokenExpiredError struct {
	// Expiry is the time when the token expired.
	Expiry time.Time
}

func (e *TokenExpiredError) Error() string {
	return fmt.Sprintf("oidc: token is expired (Token Expiry: %v)", e.Expiry)
}

// InvalidIssuerError indicates that Verify failed because the token was issued
// by an unexpected issuer. This error does NOT indicate that the token is not
// also invalid for other reasons. Other checks might have failed if the issuer
// check had not failed.
type InvalidIssuerError struct {
	Expected, Actual string
}

func (e *InvalidIssuerError) Error() string {
	return fmt.Sprintf("oidc: id token issued by a different provider, expected %q got %q", e.Expected, e.Actual)
}

// InvalidAudienceError indicates that Verify failed because the token was
// intended for a different audience. This error does NOT indicate that the
// token is not also invalid for other reasons. Other checks might have failed
// if the audience check had not failed.
type InvalidAudienceError struct {
	Expected string
	Actual   []string
}

func (e *InvalidAudienceError) Error() string {
	return fmt.Sprintf("oidc: expected audience %q got %q", e.Expected, e.Actual)
}
