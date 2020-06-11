package oidc

import (
	"context"
	"testing"
)

func TestLogoutVerify(t *testing.T) {
	tests := []logoutVerificationTest{
		{
			name: "good token",
			logoutToken: ` {
							   "iss": "https://foo",
							   "sub": "248289761001",
							   "aud": "s6BhdRkqt3",
							   "iat": 1471566154,
							   "jti": "bWJq",
							   "sid": "08a5019c-17e1-4977-8f42-65a12843ea02",
							   "events": {
								 "http://schemas.openid.net/event/backchannel-logout": {}
								 }
							  }`,
			config: Config{
				SkipClientIDCheck: true,
			},
			signKey: newRSAKey(t),
		},
		{
			name:        "invalid issuer",
			issuer:      "https://bar",
			logoutToken: `{"iss":"https://foo"}`,
			config: Config{
				SkipClientIDCheck: true,
				SkipExpiryCheck:   true,
			},
			signKey: newRSAKey(t),
			wantErr: true,
		},
		{
			name:    "invalid sig",
			logoutToken: `{
							   "iss": "https://foo",
							   "sub": "248289761001",
							   "aud": "s6BhdRkqt3",
							   "iat": 1471566154,
							   "jti": "bWJq",
							   "sid": "08a5019c-17e1-4977-8f42-65a12843ea02",
							   "events": {
								 "http://schemas.openid.net/event/backchannel-logout": {}
								 }
							  }`,
			config: Config{
				SkipClientIDCheck: true,
				SkipExpiryCheck:   true,
			},
			signKey:         newRSAKey(t),
			verificationKey: newRSAKey(t),
			wantErr:         true,
		},
		{
			name: "no sid and no sub",
			logoutToken: ` {
								"iss": "https://foo",
							   "aud": "s6BhdRkqt3",
							   "iat": 1471566154,
							   "jti": "bWJq",
							   "events": {
								 "http://schemas.openid.net/event/backchannel-logout": {}
								 }
							  }`,
			config: Config{
				SkipClientIDCheck: true,
			},
			signKey: newRSAKey(t),
			wantErr: true,
		},
		{
			name: "Prohibited nonce present",
			logoutToken: ` {
							   	"iss": "https://foo",
								"sub": "248289761001",
							   	"aud": "s6BhdRkqt3",
							   	"iat": 1471566154,
							   	"jti": "bWJq",
								"nonce" : "prohibited",
							   	"events": {
								 "http://schemas.openid.net/event/backchannel-logout": {}
								 }
							  }`,
			config: Config{
				SkipClientIDCheck: true,
			},
			signKey: newRSAKey(t),
			wantErr: true,
		},
		{
			name: "Wrong Event string",
			logoutToken: ` {
							   "iss": "https://foo",
							   "sub": "248289761001",
							   "aud": "s6BhdRkqt3",
							   "iat": 1471566154,
							   "jti": "bWJq",
							   "sid": "08a5019c-17e1-4977-8f42-65a12843ea02",
							   "events": {
								 "not a logout event": {}
								 }
							  }`,
			config: Config{
				SkipClientIDCheck: true,
			},
			signKey: newRSAKey(t),
			wantErr: true,
		},
		{
			name: "No Event string",
			logoutToken: ` {
							   "iss": "https://foo",
							   "sub": "248289761001",
							   "aud": "s6BhdRkqt3",
							   "iat": 1471566154,
							   "jti": "bWJq",
							   "sid": "08a5019c-17e1-4977-8f42-65a12843ea02",
							  }`,
			config: Config{
				SkipClientIDCheck: true,
			},
			signKey: newRSAKey(t),
			wantErr: true,
		},
	}
	for _, test := range tests {
		t.Run(test.name, test.run)
	}
}

func TestVerifyAudienceLogout(t *testing.T) {
	tests := []logoutVerificationTest{
		{
			name:    "good audience",
			logoutToken: `{"iss":"https://foo","aud":"client1","sub":"subject","events": {
								 "http://schemas.openid.net/event/backchannel-logout": {}
								 }
							}`,
			config: Config{
				ClientID:        "client1",
				SkipExpiryCheck: true,
			},
			signKey: newRSAKey(t),
		},
		{
			name:    "mismatched audience",
			logoutToken: `{"iss":"https://foo","aud":"client2","sub":"subject","events": {
								 "http://schemas.openid.net/event/backchannel-logout": {}
								 }}`,
			config: Config{
				ClientID:        "client1",
				SkipExpiryCheck: true,
			},
			signKey: newRSAKey(t),
			wantErr: true,
		},
		{
			name:    "multiple audiences, one matches",
			logoutToken: `{"iss":"https://foo","aud":["client1","client2"],"sub":"subject","events": {
								 "http://schemas.openid.net/event/backchannel-logout": {}
								 }}`,
			config: Config{
				ClientID:        "client2",
				SkipExpiryCheck: true,
			},
			signKey: newRSAKey(t),
		},
	}
	for _, test := range tests {
		t.Run(test.name, test.run)
	}
}

type logoutVerificationTest struct {
	// Name of the subtest.
	name string

	// If not provided defaults to "https://foo"
	issuer string

	// JWT payload (just the claims).
	logoutToken string

	// Key to sign the ID Token with.
	signKey *signingKey
	// If not provided defaults to signKey. Only useful when
	// testing invalid signatures.
	verificationKey *signingKey

	config  Config
	wantErr bool
}

func (v logoutVerificationTest) runGetToken(t *testing.T) (*LogoutToken, error) {
	token := v.signKey.sign(t, []byte(v.logoutToken))

	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()

	issuer := "https://foo"
	if v.issuer != "" {
		issuer = v.issuer
	}
	var ks KeySet
	if v.verificationKey == nil {
		ks = &testVerifier{v.signKey.jwk()}
	} else {
		ks = &testVerifier{v.verificationKey.jwk()}
	}
	verifier := NewLogoutVerifier(issuer, ks, &v.config)

	return verifier.Verify(ctx, token)
}

func (l logoutVerificationTest) run(t *testing.T) {
	_, err := l.runGetToken(t)
	if err != nil && !l.wantErr {
		t.Errorf("%v", err)
	}
	if err == nil && l.wantErr {
		t.Errorf("expected error")
	}
}
