package oidc

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"gopkg.in/square/go-jose.v2"
	"time"
)

// This adds the ability to verify Logout Tokens as specified in https://openid.net/specs/openid-connect-backchannel-1_0.html

type logoutEvent struct {
	Event *struct{} `json:"http://schemas.openid.net/event/backchannel-logout"`
}

// logoutToken
type logoutToken struct {
	Issuer   string      `json:"iss"`
	Subject  string      `json:"sub"`
	Audience audience    `json:"aud"`
	IssuedAt jsonTime    `json:"iat"`
	JwtID    string      `json:"jti"`
	Events   logoutEvent `json:"events"`
	Sid      string      `json:"sid"`
}

// Logout Token
type LogoutToken struct {
	// The URL of the server which issued this token. OpenID Connect
	// requires this value always be identical to the URL used for
	// initial discovery.
	//
	// Note: Because of a known issue with Google Accounts' implementation
	// this value may differ when using Google.
	//
	// See: https://developers.google.com/identity/protocols/OpenIDConnect#obtainuserinfo
	Issuer string

	// A unique string which identifies the end user.
	Subject string

	// The client ID, or set of client IDs, that this token is issued for. For
	// common uses, this is the client that initialized the auth flow.
	//
	// This package ensures the audience contains an expected value.
	Audience []string

	// When the token was issued by the provider.
	IssuedAt time.Time

	// The Session Id
	SessionId string

	// Jwt Id
	JwtID string
}

// LogoutTokenVerifier provides verification for Logout Tokens.
type LogoutTokenVerifier struct {
	keySet KeySet
	config *Config
	issuer string
}

func NewLogoutVerifier(issuerURL string, keySet KeySet, config *Config) *LogoutTokenVerifier {
	return &LogoutTokenVerifier{keySet: keySet, config: config, issuer: issuerURL}
}

// Verifier returns an LogoutTokenVerifier that uses the provider's key set to verify JWTs.
//
// The returned LogoutTokenVerifier is tied to the Provider's context and its behavior is
// undefined once the Provider's context is canceled.
func (p *Provider) LogoutVerifier(config *Config) *LogoutTokenVerifier {
	if len(config.SupportedSigningAlgs) == 0 && len(p.algorithms) > 0 {
		// Make a copy so we don't modify the config values.
		cp := &Config{}
		*cp = *config
		cp.SupportedSigningAlgs = p.algorithms
		config = cp
	}
	return NewLogoutVerifier(p.issuer, p.remoteKeySet, config)
}

//Upon receiving a logout request at the back-channel logout URI, the RP MUST validate the Logout Token as follows:
//
//1. If the Logout Token is encrypted, decrypt it using the keys and algorithms that the Client specified during Registration that the OP was to use to encrypt ID Tokens. If ID Token encryption was negotiated with the OP at Registration time and the Logout Token is not encrypted, the RP SHOULD reject it.
//2. Validate the Logout Token signature in the same way that an ID Token signature is validated, with the following refinements.
//3. Validate the iss, aud, and iat Claims in the same way they are validated in ID Tokens.
//4. Verify that the Logout Token contains a sub Claim, a sid Claim, or both.
//5. Verify that the Logout Token contains an events Claim whose value is JSON object containing the member name http://schemas.openid.net/event/backchannel-logout.
//6. Verify that the Logout Token does not contain a nonce Claim.
//7. Optionally verify that another Logout Token with the same jti value has not been recently received.
//If any of the validation steps fails, reject the Logout Token and return an HTTP 400 Bad Request error. Otherwise, proceed to perform the logout actions.

// Verify verifies a Logout token according to Specs
func (v *LogoutTokenVerifier) Verify(ctx context.Context, rawIDToken string) (*LogoutToken, error) {
	jws, err := jose.ParseSigned(rawIDToken)
	if err != nil {
		return nil, err
	}
	// Throw out tokens with invalid claims before trying to verify the token. This lets
	// us do cheap checks before possibly re-syncing keys.
	payload, err := parseJWT(rawIDToken)
	if err != nil {
		return nil, fmt.Errorf("oidc: malformed jwt: %v", err)
	}
	var token logoutToken
	if err := json.Unmarshal(payload, &token); err != nil {
		return nil, fmt.Errorf("oidc: failed to unmarshal claims: %v", err)
	}

	//4. Verify that the Logout Token contains a sub Claim, a sid Claim, or both.
	if token.Subject == "" && token.Sid == "" {
		return nil, fmt.Errorf("oidc: logout token must contain either sub or sid and MAY contain both")
	}
	//5. Verify that the Logout Token contains an events Claim whose value is JSON object containing the member name http://schemas.openid.net/event/backchannel-logout.
	if token.Events.Event == nil {
		return nil, fmt.Errorf("oidc: logout token must contain logout event")
	}
	//6. Verify that the Logout Token does not contain a nonce Claim.
	type nonce struct {
		Nonce *string `json:"nonce"`
	}
	var n nonce
	json.Unmarshal(payload, &n)
	if n.Nonce != nil {
		return nil, fmt.Errorf("oidc: nonce on logout token MUST NOT be present")
	}
	// Check issuer.
	if !v.config.SkipIssuerCheck && token.Issuer != v.issuer {
		// Google sometimes returns "accounts.google.com" as the issuer claim instead of
		// the required "https://accounts.google.com". Detect this case and allow it only
		// for Google.
		//
		// We will not add hooks to let other providers go off spec like this.
		if !(v.issuer == issuerGoogleAccounts && token.Issuer == issuerGoogleAccountsNoScheme) {
			return nil, fmt.Errorf("oidc: id token issued by a different provider, expected %q got %q", v.issuer, token.Issuer)
		}
	}

	// If a client ID has been provided, make sure it's part of the audience. SkipClientIDCheck must be true if ClientID is empty.
	//
	// This check DOES NOT ensure that the ClientID is the party to which the ID Token was issued (i.e. Authorized party).
	if !v.config.SkipClientIDCheck {
		if v.config.ClientID != "" {
			if !contains(token.Audience, v.config.ClientID) {
				return nil, fmt.Errorf("oidc: expected audience %q got %q", v.config.ClientID, token.Audience)
			}
		} else {
			return nil, fmt.Errorf("oidc: invalid configuration, clientID must be provided or SkipClientIDCheck must be set")
		}
	}

	switch len(jws.Signatures) {
	case 0:
		return nil, fmt.Errorf("oidc: id token not signed")
	case 1:
	default:
		return nil, fmt.Errorf("oidc: multiple signatures on id token not supported")
	}

	sig := jws.Signatures[0]
	supportedSigAlgs := v.config.SupportedSigningAlgs
	if len(supportedSigAlgs) == 0 {
		supportedSigAlgs = []string{RS256}
	}

	if !contains(supportedSigAlgs, sig.Header.Algorithm) {
		return nil, fmt.Errorf("oidc: id token signed with unsupported algorithm, expected %q got %q", supportedSigAlgs, sig.Header.Algorithm)
	}

	gotPayload, err := v.keySet.VerifySignature(ctx, rawIDToken)
	if err != nil {
		return nil, fmt.Errorf("failed to verify signature: %v", err)
	}

	// Ensure that the payload returned by the square actually matches the payload parsed earlier.
	if !bytes.Equal(gotPayload, payload) {
		return nil, errors.New("oidc: internal error, payload parsed did not match previous payload")
	}

	t := &LogoutToken{
		Issuer:    token.Issuer,
		Subject:   token.Subject,
		Audience:  token.Audience,
		IssuedAt:  time.Time(token.IssuedAt),
		SessionId: token.Sid,
		JwtID:     token.JwtID,
	}

	return t, nil
}
