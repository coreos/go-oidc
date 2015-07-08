package oidc

import (
	"crypto/rand"
	"encoding/base64"
	"errors"
	"fmt"
	"net"
	"net/http"
	"net/url"
	"strings"
	"time"

	"github.com/coreos/go-oidc/jose"
)

func ParseTokenFromRequest(r *http.Request) (token jose.JWT, err error) {
	ah := r.Header.Get("Authorization")
	if ah == "" {
		err = errors.New("missing Authorization header")
		return
	}

	if len(ah) <= 6 || strings.ToUpper(ah[0:6]) != "BEARER" {
		err = errors.New("should be a bearer token")
		return
	}

	return jose.ParseJWT(ah[7:])
}

func NewClaims(iss, sub, aud string, iat, exp time.Time) jose.Claims {
	return jose.Claims{
		// required
		"iss": iss,
		"sub": sub,
		"aud": aud,
		"iat": float64(iat.Unix()),
		"exp": float64(exp.Unix()),
	}
}

func GenClientID(hostport string) (string, error) {
	b, err := randBytes(32)
	if err != nil {
		return "", err
	}

	var host string
	if strings.Contains(hostport, ":") {
		host, _, err = net.SplitHostPort(hostport)
		if err != nil {
			return "", err
		}
	} else {
		host = hostport
	}

	return fmt.Sprintf("%s@%s", base64.URLEncoding.EncodeToString(b), host), nil
}

func randBytes(n int) ([]byte, error) {
	b := make([]byte, n)
	got, err := rand.Read(b)
	if err != nil {
		return nil, err
	} else if n != got {
		return nil, errors.New("unable to generate enough random data")
	}
	return b, nil
}

// urlEqual checks two urls for equality using only the host and path portions.
func urlEqual(url1, url2 string) bool {
	u1, err := url.Parse(url1)
	if err != nil {
		return false
	}
	u2, err := url.Parse(url2)
	if err != nil {
		return false
	}

	return strings.ToLower(u1.Host+u1.Path) == strings.ToLower(u2.Host+u2.Path)
}
