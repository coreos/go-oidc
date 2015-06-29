package oidc

import (
	"net/http"
	"reflect"
	"testing"
	"time"

	"github.com/coreos/go-oidc/jose"
)

func TestParseTokenFromRequestValid(t *testing.T) {
	tests := []string{"", "x", "Bearer", "xxxxxxx", "Bearer NotARealToken"}

	for i, tt := range tests {
		r, _ := http.NewRequest("", "", nil)
		r.Header.Add("Authorization", tt)
		_, err := ParseTokenFromRequest(r)
		if err == nil {
			t.Errorf("case %d: want: invalid Authorization header, got: valid Authorization header.", i)
		}
	}
}

func TestParseTokenFromRequestInvalid(t *testing.T) {
	tests := []string{
		"Bearer eyJ0eXAiOiJKV1QiLA0KICJhbGciOiJIUzI1NiJ9.eyJpc3MiOiJqb2UiLA0KICJleHAiOjEzMDA4MTkzODAsDQogImh0dHA6Ly9leGFtcGxlLmNvbS9pc19yb290Ijp0cnVlfQ.dBjftJeZ4CVP-mB92K27uhbUJU1p1r_wW1gFWFOEjXk",
	}

	for i, tt := range tests {
		r, _ := http.NewRequest("", "", nil)
		r.Header.Add("Authorization", tt)
		_, err := ParseTokenFromRequest(r)
		if err != nil {
			t.Errorf("case %d: want: valid Authorization header, got: invalid Authorization header: %v.", i, err)
		}
	}
}

func TestNewClaims(t *testing.T) {
	issAt := time.Date(2, time.January, 1, 0, 0, 0, 0, time.UTC)
	expAt := time.Date(2, time.January, 1, 1, 0, 0, 0, time.UTC)

	want := jose.Claims{
		"iss": "https://example.com",
		"sub": "user-123",
		"aud": "client-abc",
		"iat": float64(issAt.Unix()),
		"exp": float64(expAt.Unix()),
	}

	got := NewClaims("https://example.com", "user-123", "client-abc", issAt, expAt)

	if !reflect.DeepEqual(want, got) {
		t.Fatalf("want=%#v got=%#v", want, got)
	}
}
