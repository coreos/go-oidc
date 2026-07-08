/*
This is an example application to demonstrate parsing an ID Token.
*/
package main

import (
	"context"
	"crypto/rand"
	"encoding/base64"
	"encoding/json"
	"flag"
	"fmt"
	"html/template"
	"io"
	"log"
	"net/http"
	"net/url"
	"os"
	"strconv"
	"time"

	"github.com/coreos/go-oidc/v3/oidc"
	"golang.org/x/oauth2"
)

var (
	clientID     = os.Getenv("CLIENT_ID")
	clientSecret = os.Getenv("CLIENT_SECRET")
)

func randString(nByte int) (string, error) {
	b := make([]byte, nByte)
	if _, err := io.ReadFull(rand.Reader, b); err != nil {
		return "", err
	}
	return base64.RawURLEncoding.EncodeToString(b), nil
}

func setCallbackCookie(w http.ResponseWriter, r *http.Request, name, value string) {
	c := &http.Cookie{
		Name:     name,
		Value:    value,
		MaxAge:   int(time.Hour.Seconds()),
		Secure:   r.TLS != nil,
		HttpOnly: true,
	}
	http.SetCookie(w, c)
}

func main() {
	var (
		baseURL   string
		issuerURL string
		port      uint64
	)
	flag.StringVar(&baseURL, "base-url", "",
		"Base URL that the server is running on such as 'https://example.com'")
	flag.Uint64Var(&port, "port", 3000,
		"Port to serve locally.")
	flag.StringVar(&issuerURL, "issuer-url", "",
		"OpenID Connect Issuer URL to listen for")
	flag.Parse()
	if baseURL == "" {
		log.Fatalf("No --base-url provided")
	}
	if issuerURL == "" {
		log.Fatalf("No --issuer-url provided")
	}
	if clientID == "" {
		log.Fatalf("No CLIENT_ID environment variable set")
	}
	if clientSecret == "" {
		log.Fatalf("No CLIENT_SECRET environment variable set")
	}

	ctx := context.Background()

	callbackURL, err := url.JoinPath(baseURL, "/callback")
	if err != nil {
		log.Fatalf("Generating callback URL: %v", err)
	}

	provider, err := oidc.NewProvider(ctx, issuerURL)
	if err != nil {
		log.Fatal(err)
	}
	var metadata struct {
		EndSessionEndpoint string `json:"end_session_endpoint"`
	}
	if err := provider.Claims(&metadata); err != nil {
		log.Fatalf("Parsing metadata: %v", err)
	}
	if metadata.EndSessionEndpoint == "" {
		log.Fatalf("Provider doesn't have end_session_endpoint")
	}

	oidcConfig := &oidc.Config{
		ClientID: clientID,
	}
	verifier := provider.Verifier(oidcConfig)

	config := oauth2.Config{
		ClientID:     clientID,
		ClientSecret: clientSecret,
		Endpoint:     provider.Endpoint(),
		RedirectURL:  callbackURL,
		Scopes:       []string{oidc.ScopeOpenID, oidc.ScopeProfile, oidc.ScopeEmail},
	}

	http.HandleFunc("/", func(w http.ResponseWriter, r *http.Request) {
		state, err := randString(16)
		if err != nil {
			http.Error(w, "Internal error", http.StatusInternalServerError)
			return
		}
		nonce, err := randString(16)
		if err != nil {
			http.Error(w, "Internal error", http.StatusInternalServerError)
			return
		}
		setCallbackCookie(w, r, "state", state)
		setCallbackCookie(w, r, "nonce", nonce)

		http.Redirect(w, r, config.AuthCodeURL(state, oidc.Nonce(nonce)), http.StatusFound)
	})

	http.HandleFunc("POST /logout", func(w http.ResponseWriter, r *http.Request) {
		token := r.PostFormValue("logout_token")
		if token == "" {
			log.Println("No logout_token")
			http.Error(w, "No logout token", http.StatusBadRequest)
			return
		}
		logoutToken, err := verifier.VerifyLogout(r.Context(), token)
		if err != nil {
			log.Printf("Failed to validate logout token: %v", err)
			http.Error(w, "Invalid logout token", http.StatusBadRequest)
			return
		}
		data, _ := json.MarshalIndent(logoutToken, "", "  ")
		log.Printf("Logout token: %s", data)
		w.WriteHeader(http.StatusNoContent)
	})

	http.HandleFunc("GET /callback", func(w http.ResponseWriter, r *http.Request) {
		state, err := r.Cookie("state")
		if err != nil {
			http.Error(w, "state not found", http.StatusBadRequest)
			return
		}
		if r.URL.Query().Get("state") != state.Value {
			http.Error(w, "state did not match", http.StatusBadRequest)
			return
		}

		oauth2Token, err := config.Exchange(ctx, r.URL.Query().Get("code"))
		if err != nil {
			http.Error(w, "Failed to exchange token: "+err.Error(), http.StatusInternalServerError)
			return
		}
		rawIDToken, ok := oauth2Token.Extra("id_token").(string)
		if !ok {
			http.Error(w, "No id_token field in oauth2 token.", http.StatusInternalServerError)
			return
		}
		idToken, err := verifier.Verify(ctx, rawIDToken)
		if err != nil {
			http.Error(w, "Failed to verify ID Token: "+err.Error(), http.StatusInternalServerError)
			return
		}

		nonce, err := r.Cookie("nonce")
		if err != nil {
			http.Error(w, "nonce not found", http.StatusBadRequest)
			return
		}
		if idToken.Nonce != nonce.Value {
			http.Error(w, "nonce did not match", http.StatusBadRequest)
			return
		}

		oauth2Token.AccessToken = "*REDACTED*"

		resp := struct {
			OAuth2Token   *oauth2.Token
			IDTokenClaims *json.RawMessage // ID Token payload is just JSON.
		}{oauth2Token, new(json.RawMessage)}

		if err := idToken.Claims(&resp.IDTokenClaims); err != nil {
			http.Error(w, err.Error(), http.StatusInternalServerError)
			return
		}
		data, err := json.MarshalIndent(resp, "", "    ")
		if err != nil {
			http.Error(w, err.Error(), http.StatusInternalServerError)
			return
		}
		endSessionEndpoint, err := url.Parse(metadata.EndSessionEndpoint)
		if err != nil {
			http.Error(w, fmt.Sprintf("Failed to parse end session endpoint :%v", err), http.StatusInternalServerError)
			return
		}
		v := endSessionEndpoint.Query()
		v.Add("id_token_hint", rawIDToken)
		endSessionEndpoint.RawQuery = v.Encode()
		d := tmplData{
			Payload:   string(data),
			LoginURL:  baseURL,
			LogoutURL: endSessionEndpoint.String(),
		}
		tmpl.Execute(w, d)
	})

	log.Printf("listening on http://[::]:%d", port)
	log.Fatal(http.ListenAndServe(":"+strconv.FormatUint(port, 10), nil))
}

type tmplData struct {
	Payload   string
	LoginURL  string
	LogoutURL string
}

var tmpl = template.Must(template.New("").Parse(`<!DOCTYPE html>
<html lang="en">
<head>
    <meta charset="UTF-8">
    <title>go-oidc</title>
</head>
<body>
	<pre>
    	<code>{{.Payload}}</code>
	</pre>
	<a href="{{.LoginURL}}">Reauth</a>
	<a href="{{.LogoutURL}}">Logout</a>
</body>
</html>`))
