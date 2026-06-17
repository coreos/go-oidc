package oidc

import (
	"crypto"
	"encoding/json"
	"reflect"
	"testing"
	"time"

	jose "github.com/go-jose/go-jose/v4"
)

const auth0JWTs = `{
  "keys": [
    {
      "kty": "RSA",
      "use": "sig",
      "n": "uv7NSwCelgZ7nAOxKM27fUHKJrIIL-UreZ0wz5MRvfoQQXcaOnjpcSoBX1FwTXH01MPKhPJMJkMFpDfdT7IxMgdq_SLBGz73FRabahOXbItyEvOPf6oXmJJB3vh3at-G7dWRGOa3YC8gXw_2V7OgAh2X4UyqB40hjlvM8bjtbK8QBZGGbw2h-7Hp8GTa5iZXjqd_o6e9zhqzVCOSj-DOQYp8EqlW0gBQu-4-WDgnK0VwBCuaFGqznKg0HjM4FS4qCVYmLIFX3k2ibpwHncEvTPTJ3LMN7WBElM5jIpW5mVKFrgiM2dgfGbfE1uTSwep8507SBj3d0PAmHomFoCzGDQ",
      "e": "AQAB",
      "kid": "MJEenCzYAP_m5TgvpAPya",
      "x5t": "e5j-NuV3qV9pTuGiO619QS0E04Q",
      "x5c": [
        "MIIDHTCCAgWgAwIBAgIJXRuvBG90F7xrMA0GCSqGSIb3DQEBCwUAMCwxKjAoBgNVBAMTIWRldi0xenp2ZTQxcDFjZWM3eDFqLnVzLmF1dGgwLmNvbTAeFw0yNjA2MTcxNzM4MTNaFw00MDAyMjQxNzM4MTNaMCwxKjAoBgNVBAMTIWRldi0xenp2ZTQxcDFjZWM3eDFqLnVzLmF1dGgwLmNvbTCCASIwDQYJKoZIhvcNAQEBBQADggEPADCCAQoCggEBALr+zUsAnpYGe5wDsSjNu31ByiayCC/lK3mdMM+TEb36EEF3Gjp46XEqAV9RcE1x9NTDyoTyTCZDBaQ33U+yMTIHav0iwRs+9xUWm2oTl2yLchLzj3+qF5iSQd74d2rfhu3VkRjmt2AvIF8P9lezoAIdl+FMqgeNIY5bzPG47WyvEAWRhm8Nofux6fBk2uYmV46nf6Onvc4as1Qjko/gzkGKfBKpVtIAULvuPlg4JytFcAQrmhRqs5yoNB4zOBUuKglWJiyBV95Nom6cB53BL0z0ydyzDe1gRJTOYyKVuZlSha4IjNnYHxm3xNbk0sHqfOdO0gY93dDwJh6JhaAsxg0CAwEAAaNCMEAwDwYDVR0TAQH/BAUwAwEB/zAdBgNVHQ4EFgQUxIt/DkLyNhKm86E5OO9racAMyb4wDgYDVR0PAQH/BAQDAgKEMA0GCSqGSIb3DQEBCwUAA4IBAQC0gbuBuECbkfqsfls0I+Nni1kodTJSRK9LgDPkk/dN68j6fqDoiXr/qnLAYjv3vdvVTHn+bJ01iv9F23uW0umHQ4QXB0nd6lZqy33RVLVaFCRX0n1sJEf7Uwz+MROqxE1nlZSxPwiLUYsXuCut2q5NDybNlw6FSlO8BDohTQvpmVu2RDnFfG9as5LC80nmnfdWjiHfM+r9P7sjqkZvuulTQcgmHe29CqOKI2PZWV6CZlqleY3c9Ub7qJQ4mwmkpaJvyA7j81H7R2DAx61hR6glXHnvF6s/7Qt6TAVW1SNbR4+8bBDRBzJcyOmaaLw/rCglOVWW70ZoE28a9iVy5owO"
      ],
      "alg": "RS256"
    },
    {
      "kty": "RSA",
      "use": "sig",
      "n": "1MPL8fuaTURFBZSwPGDVs8sxOkHs0rUX0s82GttwXNtC0WpU4HeNqha5LCW5Rot0rx2JOPGzgzLbiw7z1TfqNuG3w9nV16U7-CQM65d78vgw6qZ2-MEzc_6eOundchXlHu67DWEkaf61NPJ-zfE2I2wb_VWhhoxuJSxX6b2X9arMzNfc9-0vcwgVQsNTVU6G-OrHVoZu2O-d95nf_3XDlHxH_GOA2Wplf9LmiFwyQBKAHgAs7GWZ1Jmp4Br8dp8ZiRb_FMAYZLN0jRxEPjITsopEuStq819qg7Mf0QF4Ba6cIaleQ6CO54CHcNKXtw9j3Vc1mkUJ3ERInT-705g_fw",
      "e": "AQAB",
      "kid": "at8QtR6iDf7Cct4M75uyQ",
      "x5t": "0RZ_EexHYMHWQOeDs0Pw_aAH4Eg",
      "x5c": [
        "MIIDHTCCAgWgAwIBAgIJFCeir1tXEr02MA0GCSqGSIb3DQEBCwUAMCwxKjAoBgNVBAMTIWRldi0xenp2ZTQxcDFjZWM3eDFqLnVzLmF1dGgwLmNvbTAeFw0yNjA2MTcxNzM4MTNaFw00MDAyMjQxNzM4MTNaMCwxKjAoBgNVBAMTIWRldi0xenp2ZTQxcDFjZWM3eDFqLnVzLmF1dGgwLmNvbTCCASIwDQYJKoZIhvcNAQEBBQADggEPADCCAQoCggEBANTDy/H7mk1ERQWUsDxg1bPLMTpB7NK1F9LPNhrbcFzbQtFqVOB3jaoWuSwluUaLdK8diTjxs4My24sO89U36jbht8PZ1delO/gkDOuXe/L4MOqmdvjBM3P+njrp3XIV5R7uuw1hJGn+tTTyfs3xNiNsG/1VoYaMbiUsV+m9l/WqzMzX3PftL3MIFULDU1VOhvjqx1aGbtjvnfeZ3/91w5R8R/xjgNlqZX/S5ohcMkASgB4ALOxlmdSZqeAa/HafGYkW/xTAGGSzdI0cRD4yE7KKRLkravNfaoOzH9EBeAWunCGpXkOgjueAh3DSl7cPY91XNZpFCdxESJ0/u9OYP38CAwEAAaNCMEAwDwYDVR0TAQH/BAUwAwEB/zAdBgNVHQ4EFgQUOpacqHH7kmg51Sp5DpYPiVKed9gwDgYDVR0PAQH/BAQDAgKEMA0GCSqGSIb3DQEBCwUAA4IBAQB8M9poQXm6AHgZZjJmDJ3fbPT+aM8cuih0wAzjo92JFBc81xO3gU9z1i9gEqySzZ0RTlwKGUoM8J55sTB0v+FEu4XV94xD6ttlYarr0JMi+0C3uH2C/KURpmAmZeWaP+fe3t6QSlpz9d4tl+OHJqVpmqCJSu8x3Jc+dATq4EkEBj1d/keF/bg2nkBt4NOh0bz6UMUCOhGcCUJNeZR6wa7DwjVMorvED6GAHipot5aNC4/8SR5ubC7p12ZYLDusr1sOxSfqjk0K4I+LeyrKMprw7gkOvjLEvmyWkCdO4yHq2ibYBSLTiyhEO2xn9VQuogtUXh13DKXp6vEMeMcL378/"
      ],
      "alg": "RS256"
    }
  ]
}`

// Token received from an Auth0 logout POST.
const auth0LogoutToken = "eyJhbGciOiJSUzI1NiIsInR5cCI6IkpXVCIsImtpZCI6Ik1KRWVuQ3pZQVBfbTVUZ3ZwQVB5YSJ9.eyJpc3MiOiJodHRwczovL2Rldi0xenp2ZTQxcDFjZWM3eDFqLnVzLmF1dGgwLmNvbS8iLCJzdWIiOiJnb29nbGUtb2F1dGgyfDExMjkxODk2MDE1NTk4NzMyMzM2MSIsImF1ZCI6IlpIVFpyZm50ZlBqWVpESmlJTUIxa2ViMEhIQTlBS0V2IiwiaWF0IjoxNzgxNzI0ODk3LCJleHAiOjE3ODE3MjUwMTcsImp0aSI6ImMzMWIzYTE0LTkzOTctNDRjNC04NTZhLTllYTE4ODAwOTM0NSIsImV2ZW50cyI6eyJodHRwOi8vc2NoZW1hcy5vcGVuaWQubmV0L2V2ZW50L2JhY2tjaGFubmVsLWxvZ291dCI6e319LCJ0cmFjZV9pZCI6ImEwZDQ3ZTlhYzg1YTE1YTQiLCJzaWQiOiJIRENlMENILXI2RGoyaXloVG5qc0ZwczlhX0lOckVfYyJ9.GWzDL6fKUIx_41MIkX-lRLiU9KJy7JHgV7i96PqRT5RK_8PkDMJzeKqpzbwgQat_jNbd3b3PiT-lhPDumPxurQJSKaBv09Rpuui96wp95y1S1heUDTR5YVc5HFnaVlQTOQExJMsi-yfsQiIYqgwavhOerps5Rfl37GakxzN7nYGc7-lznjdJCkaTV-goh81xIdYskKcnfxBJcPOXQmmqelQDUKusjQk_deaUQHyUGU8LONpbgxP4DGBIS6EZp5WbPKRSeimGJpd1Phycf6n4eojojnJihBBfxPaCZRTHTwrfh1-WuROVXhoRtE51FYcycWMLxM4E9JX85I9k2C0AAg"

// The time this token was issued.
const auth0IAT = 1781724897

func TestAuth0Logout(t *testing.T) {
	now := time.Unix(auth0IAT, 0)
	clientID := "ZHTZrfntfPjYZDJiIMB1keb0HHA9AKEv"
	issuerURL := "https://dev-1zzve41p1cec7x1j.us.auth0.com/"
	var jwks struct {
		Keys []*jose.JSONWebKey `json:"keys"`
	}
	if err := json.Unmarshal([]byte(auth0JWTs), &jwks); err != nil {
		t.Fatalf("Parsing JWKs: %v", err)
	}
	var pubKeys []crypto.PublicKey
	for _, k := range jwks.Keys {
		pubKeys = append(pubKeys, k.Public().Key)
	}

	config := &Config{
		ClientID: clientID,
		Now:      func() time.Time { return now },
	}
	keySet := &StaticKeySet{PublicKeys: pubKeys}
	v := NewVerifier(issuerURL, keySet, config)
	got, err := v.VerifyLogout(t.Context(), auth0LogoutToken)
	if err != nil {
		t.Fatalf("Verifying logout token: %v", err)
	}

	var claims struct {
		TraceID string `json:"trace_id"`
	}
	if err := got.Claims(&claims); err != nil {
		t.Fatalf("Parsing claims: %v", err)
	}
	wantTraceID := "a0d47e9ac85a15a4"
	if claims.TraceID != wantTraceID {
		t.Errorf("Parsing claims returned unexpected trace_id, got=%s, want=%s", claims.TraceID, wantTraceID)
	}

	got.claims = nil
	want := &LogoutToken{
		Issuer:    "https://dev-1zzve41p1cec7x1j.us.auth0.com/",
		Subject:   "google-oauth2|112918960155987323361",
		Audience:  []string{"ZHTZrfntfPjYZDJiIMB1keb0HHA9AKEv"},
		IssuedAt:  time.Unix(1781724897, 0),
		Expiry:    time.Unix(1781725017, 0),
		TokenID:   "c31b3a14-9397-44c4-856a-9ea188009345",
		SessionID: "HDCe0CH-r6Dj2iyhTnjsFps9a_INrE_c",
	}
	if !reflect.DeepEqual(got, want) {
		t.Errorf("Auth0 Logout token returned unexpected results, got=%#v, want=%#v", got, want)
	}
}

const (
	testLogoutIssuer   = "https://login.example.com"
	testLogoutClientID = "test-client-id"
	// The "iat" and "exp" used in the payloads below, along with the time
	// returned by the test verifier's Now function (set to testLogoutIAT).
	testLogoutIAT = 1781724897
	testLogoutExp = 1781725017
)

func TestLogoutToken(t *testing.T) {
	// A key used to sign tokens that is NOT in the verifier's key set, used to
	// exercise signature validation failures.
	unknownKey := newRSAKey(t)

	tests := []struct {
		name string
		// The key used to sign the payload.
		signKey *signingKey
		// The keys the verifier trusts. If empty, defaults to signKey so that
		// signatures verify by default.
		verificationKeys []*signingKey
		config           Config
		payload          string

		wantErr bool
		want    *LogoutToken
	}{
		{
			name:    "valid",
			signKey: newRSAKey(t),
			config:  Config{ClientID: testLogoutClientID},
			payload: `{
				"iss": "https://login.example.com",
				"sub": "user-1",
				"aud": "test-client-id",
				"iat": 1781724897,
				"exp": 1781725017,
				"jti": "jti-1",
				"sid": "sid-1",
				"events": {"http://schemas.openid.net/event/backchannel-logout": {}}
			}`,
			want: &LogoutToken{
				Issuer:    testLogoutIssuer,
				Subject:   "user-1",
				Audience:  []string{testLogoutClientID},
				IssuedAt:  time.Unix(testLogoutIAT, 0),
				Expiry:    time.Unix(testLogoutExp, 0),
				TokenID:   "jti-1",
				SessionID: "sid-1",
			},
		},
		{
			name:    "no session id",
			signKey: newRSAKey(t),
			config:  Config{ClientID: testLogoutClientID},
			payload: `{
				"iss": "https://login.example.com",
				"sub": "user-1",
				"aud": "test-client-id",
				"iat": 1781724897,
				"exp": 1781725017,
				"jti": "jti-1",
				"events": {"http://schemas.openid.net/event/backchannel-logout": {}}
			}`,
			want: &LogoutToken{
				Issuer:   testLogoutIssuer,
				Subject:  "user-1",
				Audience: []string{testLogoutClientID},
				IssuedAt: time.Unix(testLogoutIAT, 0),
				Expiry:   time.Unix(testLogoutExp, 0),
				TokenID:  "jti-1",
			},
		},
		{
			name:    "multiple audiences",
			signKey: newRSAKey(t),
			config:  Config{ClientID: testLogoutClientID},
			payload: `{
				"iss": "https://login.example.com",
				"sub": "user-1",
				"aud": ["test-client-id", "test-client-id-2"],
				"iat": 1781724897,
				"exp": 1781725017,
				"jti": "jti-1",
				"sid": "sid-1",
				"events": {"http://schemas.openid.net/event/backchannel-logout": {}}
			}`,
			want: &LogoutToken{
				Issuer:    testLogoutIssuer,
				Subject:   "user-1",
				Audience:  []string{testLogoutClientID, "test-client-id-2"},
				IssuedAt:  time.Unix(testLogoutIAT, 0),
				Expiry:    time.Unix(testLogoutExp, 0),
				TokenID:   "jti-1",
				SessionID: "sid-1",
			},
		},
		{
			name:    "signed with EdDSA key",
			signKey: newEdDSAKey(t),
			config: Config{
				ClientID:             testLogoutClientID,
				SupportedSigningAlgs: []string{EdDSA},
			},
			payload: `{
				"iss": "https://login.example.com",
				"sub": "user-1",
				"aud": "test-client-id",
				"iat": 1781724897,
				"exp": 1781725017,
				"jti": "jti-1",
				"sid": "sid-1",
				"events": {"http://schemas.openid.net/event/backchannel-logout": {}}
			}`,
			want: &LogoutToken{
				Issuer:    testLogoutIssuer,
				Subject:   "user-1",
				Audience:  []string{testLogoutClientID},
				IssuedAt:  time.Unix(testLogoutIAT, 0),
				Expiry:    time.Unix(testLogoutExp, 0),
				TokenID:   "jti-1",
				SessionID: "sid-1",
			},
		},
		{
			name:    "missing backchannel-logout event",
			signKey: newRSAKey(t),
			config:  Config{ClientID: testLogoutClientID},
			payload: `{
				"iss": "https://login.example.com",
				"sub": "user-1",
				"aud": "test-client-id",
				"iat": 1781724897,
				"exp": 1781725017,
				"jti": "jti-1",
				"sid": "sid-1",
				"events": {}
			}`,
			wantErr: true,
		},
		{
			name:    "missing jti",
			signKey: newRSAKey(t),
			config:  Config{ClientID: testLogoutClientID},
			payload: `{
				"iss": "https://login.example.com",
				"sub": "user-1",
				"aud": "test-client-id",
				"iat": 1781724897,
				"exp": 1781725017,
				"sid": "sid-1",
				"events": {"http://schemas.openid.net/event/backchannel-logout": {}}
			}`,
			wantErr: true,
		},
		{
			name:    "issuer mismatch",
			signKey: newRSAKey(t),
			config:  Config{ClientID: testLogoutClientID},
			payload: `{
				"iss": "https://evil.example.com",
				"sub": "user-1",
				"aud": "test-client-id",
				"iat": 1781724897,
				"exp": 1781725017,
				"jti": "jti-1",
				"sid": "sid-1",
				"events": {"http://schemas.openid.net/event/backchannel-logout": {}}
			}`,
			wantErr: true,
		},
		{
			name:    "skip issuer check",
			signKey: newRSAKey(t),
			config: Config{
				ClientID:        testLogoutClientID,
				SkipIssuerCheck: true,
			},
			payload: `{
				"iss": "https://other.example.com",
				"sub": "user-1",
				"aud": "test-client-id",
				"iat": 1781724897,
				"exp": 1781725017,
				"jti": "jti-1",
				"sid": "sid-1",
				"events": {"http://schemas.openid.net/event/backchannel-logout": {}}
			}`,
			want: &LogoutToken{
				Issuer:    "https://other.example.com",
				Subject:   "user-1",
				Audience:  []string{testLogoutClientID},
				IssuedAt:  time.Unix(testLogoutIAT, 0),
				Expiry:    time.Unix(testLogoutExp, 0),
				TokenID:   "jti-1",
				SessionID: "sid-1",
			},
		},
		{
			name:    "audience mismatch",
			signKey: newRSAKey(t),
			config:  Config{ClientID: testLogoutClientID},
			payload: `{
				"iss": "https://login.example.com",
				"sub": "user-1",
				"aud": "some-other-client",
				"iat": 1781724897,
				"exp": 1781725017,
				"jti": "jti-1",
				"sid": "sid-1",
				"events": {"http://schemas.openid.net/event/backchannel-logout": {}}
			}`,
			wantErr: true,
		},
		{
			name:    "missing client id config",
			signKey: newRSAKey(t),
			config:  Config{},
			payload: `{
				"iss": "https://login.example.com",
				"sub": "user-1",
				"aud": "test-client-id",
				"iat": 1781724897,
				"exp": 1781725017,
				"jti": "jti-1",
				"sid": "sid-1",
				"events": {"http://schemas.openid.net/event/backchannel-logout": {}}
			}`,
			wantErr: true,
		},
		{
			name:    "skip client id check",
			signKey: newRSAKey(t),
			config:  Config{SkipClientIDCheck: true},
			payload: `{
				"iss": "https://login.example.com",
				"sub": "user-1",
				"aud": "some-other-client",
				"iat": 1781724897,
				"exp": 1781725017,
				"jti": "jti-1",
				"sid": "sid-1",
				"events": {"http://schemas.openid.net/event/backchannel-logout": {}}
			}`,
			want: &LogoutToken{
				Issuer:    testLogoutIssuer,
				Subject:   "user-1",
				Audience:  []string{"some-other-client"},
				IssuedAt:  time.Unix(testLogoutIAT, 0),
				Expiry:    time.Unix(testLogoutExp, 0),
				TokenID:   "jti-1",
				SessionID: "sid-1",
			},
		},
		{
			name:    "expired token",
			signKey: newRSAKey(t),
			config:  Config{ClientID: testLogoutClientID},
			// Expiry well before testLogoutIAT, the verifier's notion of "now".
			payload: `{
				"iss": "https://login.example.com",
				"sub": "user-1",
				"aud": "test-client-id",
				"iat": 1781724657,
				"exp": 1781724777,
				"jti": "jti-1",
				"sid": "sid-1",
				"events": {"http://schemas.openid.net/event/backchannel-logout": {}}
			}`,
			wantErr: true,
		},
		{
			name:    "skip expiry check",
			signKey: newRSAKey(t),
			config: Config{
				ClientID:        testLogoutClientID,
				SkipExpiryCheck: true,
			},
			payload: `{
				"iss": "https://login.example.com",
				"sub": "user-1",
				"aud": "test-client-id",
				"iat": 1781724657,
				"exp": 1781724777,
				"jti": "jti-1",
				"sid": "sid-1",
				"events": {"http://schemas.openid.net/event/backchannel-logout": {}}
			}`,
			want: &LogoutToken{
				Issuer:    testLogoutIssuer,
				Subject:   "user-1",
				Audience:  []string{testLogoutClientID},
				IssuedAt:  time.Unix(1781724657, 0),
				Expiry:    time.Unix(1781724777, 0),
				TokenID:   "jti-1",
				SessionID: "sid-1",
			},
		},
		{
			name:    "missing exp",
			signKey: newRSAKey(t),
			config:  Config{ClientID: testLogoutClientID},
			// A logout token must contain an "exp" claim.
			payload: `{
				"iss": "https://login.example.com",
				"sub": "user-1",
				"aud": "test-client-id",
				"iat": 1781724897,
				"jti": "jti-1",
				"sid": "sid-1",
				"events": {"http://schemas.openid.net/event/backchannel-logout": {}}
			}`,
			wantErr: true,
		},
		{
			name:             "signed by untrusted key",
			signKey:          unknownKey,
			verificationKeys: []*signingKey{newRSAKey(t)},
			config:           Config{ClientID: testLogoutClientID},
			payload: `{
				"iss": "https://login.example.com",
				"sub": "user-1",
				"aud": "test-client-id",
				"iat": 1781724897,
				"exp": 1781725017,
				"jti": "jti-1",
				"sid": "sid-1",
				"events": {"http://schemas.openid.net/event/backchannel-logout": {}}
			}`,
			wantErr: true,
		},
		{
			name:    "no subject",
			signKey: newRSAKey(t),
			config:  Config{ClientID: testLogoutClientID},
			// A logout token may identify the session via "sid" without a "sub".
			payload: `{
				"iss": "https://login.example.com",
				"aud": "test-client-id",
				"iat": 1781724897,
				"exp": 1781725017,
				"jti": "jti-1",
				"sid": "sid-1",
				"events": {"http://schemas.openid.net/event/backchannel-logout": {}}
			}`,
			want: &LogoutToken{
				Issuer:    testLogoutIssuer,
				Audience:  []string{testLogoutClientID},
				IssuedAt:  time.Unix(testLogoutIAT, 0),
				Expiry:    time.Unix(testLogoutExp, 0),
				TokenID:   "jti-1",
				SessionID: "sid-1",
			},
		},
		{
			name:    "missing subject and session id",
			signKey: newRSAKey(t),
			config:  Config{ClientID: testLogoutClientID},
			// A logout token must contain a "sub" claim, a "sid" claim, or both.
			payload: `{
				"iss": "https://login.example.com",
				"aud": "test-client-id",
				"iat": 1781724897,
				"exp": 1781725017,
				"jti": "jti-1",
				"events": {"http://schemas.openid.net/event/backchannel-logout": {}}
			}`,
			wantErr: true,
		},
		{
			name:    "contains nonce",
			signKey: newRSAKey(t),
			config:  Config{ClientID: testLogoutClientID},
			// A logout token must not contain a "nonce" claim.
			payload: `{
				"iss": "https://login.example.com",
				"sub": "user-1",
				"aud": "test-client-id",
				"iat": 1781724897,
				"exp": 1781725017,
				"jti": "jti-1",
				"sid": "sid-1",
				"nonce": "n-0S6_WzA2Mj",
				"events": {"http://schemas.openid.net/event/backchannel-logout": {}}
			}`,
			wantErr: true,
		},
		{
			name:    "malformed payload",
			signKey: newRSAKey(t),
			config:  Config{ClientID: testLogoutClientID},
			payload: `{"iss": "https://login.example.com", not valid json`,
			wantErr: true,
		},
	}

	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			verificationKeys := tc.verificationKeys
			if len(verificationKeys) == 0 {
				verificationKeys = []*signingKey{tc.signKey}
			}
			var pubKeys []crypto.PublicKey
			for _, k := range verificationKeys {
				pubKeys = append(pubKeys, k.pub)
			}

			config := tc.config
			if config.Now == nil {
				config.Now = func() time.Time { return time.Unix(testLogoutIAT, 0) }
			}

			token := tc.signKey.sign(t, []byte(tc.payload))
			keySet := &StaticKeySet{PublicKeys: pubKeys}
			v := NewVerifier(testLogoutIssuer, keySet, &config)

			got, err := v.VerifyLogout(t.Context(), token)
			if err != nil {
				if !tc.wantErr {
					t.Fatalf("VerifyLogout() returned unexpected error: %v", err)
				}
				return
			}
			if tc.wantErr {
				t.Fatalf("VerifyLogout() expected an error, got token: %#v", got)
			}

			// claims holds the raw payload, which isn't compared directly.
			got.claims = nil
			if !reflect.DeepEqual(got, tc.want) {
				t.Errorf("VerifyLogout() returned unexpected token\n got=%#v\nwant=%#v", got, tc.want)
			}
		})
	}
}
