package oidc

import (
	"encoding/json"
	"errors"
	"fmt"
	"net/http"

	"github.com/square/go-jose"
	"golang.org/x/net/context"
)

type keyRequest struct {
	jws    *jose.JsonWebSignature
	respCh chan keyResponse
}

type keyResponse struct {
	key interface{}
	err error
}

type remoteKeySet struct {
	ctx     context.Context
	hc      *http.Client
	jwksURL string

	requestCh chan keyRequest
}

func newRemoteKeySet(ctx context.Context, jwksURL string) *remoteKeySet {
	r := &remoteKeySet{
		ctx:       ctx,
		hc:        contextClient(ctx),
		jwksURL:   jwksURL,
		requestCh: make(chan keyRequest),
	}
	go r.start() // begin the main loop in a goroutine.
	return r
}

func (r *remoteKeySet) Verify(jwt string) (payload []byte, err error) {
	jws, err := jose.ParseSigned(jwt)
	if err != nil {
		return nil, fmt.Errorf("parsing jwt: %v", err)
	}
	// Construct a key requests.
	keyReq := keyRequest{jws, make(chan keyResponse, 1)}

	select {
	case r.requestCh <- keyReq: // Send the request on the requests channel.
	case <-r.ctx.Done():
		return nil, r.ctx.Err()
	}

	select {
	case resp := <-keyReq.respCh: // Wait for a response on the response channel.
		if resp.err != nil {
			return nil, resp.err
		}
		return jws.Verify(resp.key)
	case <-r.ctx.Done():
		return nil, r.ctx.Err()
	}
}

// updateKeys queries the provider for the current set of keys.
func (r *remoteKeySet) updateKeys() (jose.JsonWebKeySet, error) {
	resp, err := r.hc.Get(r.jwksURL)
	if err != nil {
		return jose.JsonWebKeySet{}, err
	}
	defer resp.Body.Close()

	var set jose.JsonWebKeySet
	if err := json.NewDecoder(resp.Body).Decode(&set); err != nil {
		return jose.JsonWebKeySet{}, fmt.Errorf("failed to decode key set: %v", err)
	}
	return set, nil
}

func keyForSet(keys map[string]interface{}, jws *jose.JsonWebSignature) (interface{}, bool) {
	for _, sig := range jws.Signatures {
		if key, ok := keys[sig.Header.KeyID]; ok {
			return key, true
		}
	}
	return nil, false
}

type keySetResponse struct {
	keyset jose.JsonWebKeySet
	err    error
}

// start beings the main loop.
func (r *remoteKeySet) start() {
	remoteResponseCh := make(chan keySetResponse, 1) // Channel to wait for a remote response on.
	var waitingReqs []keyRequest                     // Request that are waiting for a remote response.
	keys := make(map[string]interface{})             // Keys currently cached by the key set.

	for {
		select {
		case req := <-r.requestCh: // Got a request for a key from a goroutine.
			if key, ok := keyForSet(keys, req.jws); ok {
				// A key is cached that can verify the JWS.
				req.respCh <- keyResponse{key, nil}
				break
			}

			if len(waitingReqs) == 0 {
				// No current inflight request, make a request.
				go func() {
					set, err := r.updateKeys()
					remoteResponseCh <- keySetResponse{set, err}
				}()
			}
			// Add request to the wait queue.
			waitingReqs = append(waitingReqs, req)

		case resp := <-remoteResponseCh:
			// A request to the provider came back with new keys.
			// Respond to all queued requests.

			if resp.err != nil {
				for _, req := range waitingReqs {
					req.respCh <- keyResponse{nil, resp.err}
				}
			} else {
				// reset the keys
				keys = make(map[string]interface{})
				for _, key := range resp.keyset.Keys {
					keys[key.KeyID] = key.Key
				}

				// for each waiting request, respond.
				for _, req := range waitingReqs {
					var keyResp keyResponse
					if key, ok := keyForSet(keys, req.jws); ok {
						keyResp.key = key
					} else {
						keyResp.err = errors.New("key not found")
					}
					req.respCh <- keyResp
				}
			}

			waitingReqs = nil // Clear wait queue.

		case <-r.ctx.Done():
			return
		}
	}
}
