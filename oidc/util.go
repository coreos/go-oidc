package oidc

import (
	"encoding/base64"
	"errors"
	"fmt"
	"net"
	"net/http"
	"strings"
	"time"

	"github.com/coreos/go-oidc/jose"
	pcrypto "github.com/coreos/go-oidc/pkg/crypto"
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
	b, err := pcrypto.RandBytes(32)
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
