package oidc

import (
	"encoding/json"
	"errors"
	"net/http"
	"time"

	phttp "github.com/coreos/go-oidc/http"
	"github.com/coreos/go-oidc/jose"
	"github.com/coreos/go-oidc/key"
)

func NewRemotePublicKeyRepo(hc phttp.Client, ep string, exp time.Duration) *remotePublicKeyRepo {
	return &remotePublicKeyRepo{hc: hc, ep: ep, exp: exp}
}

type remotePublicKeyRepo struct {
	hc  phttp.Client
	ep  string
	exp time.Duration
}

func (r *remotePublicKeyRepo) Get() (key.KeySet, error) {
	req, err := http.NewRequest("GET", r.ep, nil)
	if err != nil {
		return nil, err
	}

	resp, err := r.hc.Do(req)
	if err != nil {
		return nil, err
	}
	defer resp.Body.Close()

	var d struct {
		Keys []jose.JWK `json:"keys"`
	}
	if err := json.NewDecoder(resp.Body).Decode(&d); err != nil {
		return nil, err
	}

	if len(d.Keys) == 0 {
		return nil, errors.New("zero keys in response")
	}

	ttl, ok, err := phttp.Cacheable(resp.Header)
	if err != nil {
		return nil, err
	}
	var exp time.Time
	if !ok {
		if r.exp < 0 {
			return nil, errors.New("HTTP cache headers not set")
		}
		exp = time.Now().UTC().Add(r.exp)
	} else {
		exp = time.Now().UTC().Add(ttl)
	}
	ks := key.NewPublicKeySet(d.Keys, exp)
	return ks, nil
}
