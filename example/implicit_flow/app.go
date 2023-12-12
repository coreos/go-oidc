/*
This is an example application to test the implicit flow.
*/
package main

import (
	"context"
	// "encoding/json"
	"fmt"
	"net/http"
	"time"

	oidc "github.com/coreos/go-oidc/v3/oidc"
	// "github.com/google/uuid"
)

var (
	issuerURL = "http://localhost:9090"
	jwksURL   = "http://localhost:9090/keysets"
	clientID  = "client4321"
	// state should be cookie? and is a JWT?:
	myState = "987654321state"
)

// would need to be in main:

// ctx := context.Background()

// // Create a key set from the JWKS URL
// keySet := oidc.NewRemoteKeySet(ctx, jwksURL)

// // Create an ID token verifier manually
// verifier := oidc.NewVerifier(issuerURL, keySet, &oidc.Config{
// 	ClientID: clientID,
// })

var (
	ctx = context.Background()
	// Create a key set from the JWKS URL
	keySet = oidc.NewRemoteKeySet(ctx, jwksURL)
	// Create an ID token verifier manually
	verifier = oidc.NewVerifier(issuerURL, keySet, &oidc.Config{
		ClientID: clientID,
	})
)

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

func generateNonce() string {
	// return uuid.New().String()
	return "9999-efbc-5434-3cde-acde"
}

var nonce = generateNonce()

func handleLaunch(w http.ResponseWriter, r *http.Request) {
	// if r.FormValue("state") == myState {
	// 	fmt.Println("Got state back!!! 👍")
	// } else {
	// 	fmt.Println("where'd my state go?????")
	// }

	state, err := r.Cookie("state")
	if err != nil {
		http.Error(w, "state not found", http.StatusBadRequest)
		return
	}

	if state.Value == myState {
		fmt.Println("Got state back!!! 👍")
	} else {
		fmt.Println("where'd my state go?????")
	}

	nonce, err := r.Cookie("nonce")
	if err != nil {
		http.Error(w, "nonce not found", http.StatusBadRequest)
		return
	}

	if nonce.Value == myState {
		fmt.Println("Got nonce back!!! 🎉")
	} else {
		fmt.Println("where'd my NONCE go?????")
	}

	// Extract the JWT from the request
	// rawIDToken := r.FormValue("id_token")
	rawIDToken := r.URL.Query().Get("id_token")

	fmt.Println("RAW ID TOKEN! - ", rawIDToken)

	// Parse and verify the ID token
	idToken, err := verifier.Verify(ctx, rawIDToken)
	if err != nil {
		fmt.Println("Invalid token:", err)
		return
	}

	fmt.Println("\n🎉\nid token unpacked and verified!!!\n")

	// resp := struct {
	// 	// OAuth2Token   *oauth2.Token
	// 	IDTokenClaims *json.RawMessage // ID Token payload is just JSON.
	// }{new(json.RawMessage)}

	resp := map[string]interface{}{}

	// if err := idToken.Claims(&resp.IDTokenClaims); err != nil {
	if err := idToken.Claims(&resp); err != nil {
		// http.Error(w, err.Error(), http.StatusInternalServerError)
		fmt.Println("cannot pull out claims ")
		return
	}

	// fmt.Println(resp.IDTokenClaims)

	fmt.Println(resp)
	fmt.Println(resp["name"])

	// fmt.Println("token name: ", claimedName)

	// Token is valid, continue with your application logic
	// ...

	// fmt.Fprintf(w, "LTI Launch successful!")

	// data, err := json.MarshalIndent(resp, "", "    ")
	// if err != nil {
	// 	http.Error(w, err.Error(), http.StatusInternalServerError)
	// 	return
	// }
	// fmt.Println(string(data))
	claimedName := resp["name"]
	// w.Write(data)
	// claimedName := "make-me-real"
	http.Redirect(w, r, "/content?name="+fmt.Sprintf("%v", claimedName), http.StatusFound)
}

func handleLoginInit(w http.ResponseWriter, r *http.Request) {
	// Extract necessary parameters like iss, login_hint, target_link_uri, etc.
	// ...

	// Construct the OIDC Authentication request URL
	// Redirect to LMS's OIDC authorization endpoint with required parameters
	// ...
	loginHint := r.FormValue("login_hint")
	ltiMessageHint := r.FormValue("lti_message_hint")
	ltiDeploymentID := r.FormValue("lti_deployment_id")
	// some kind of deployment id check... --> DB
	iss := r.FormValue("iss")
	if iss != "Platform" {
		fmt.Println("Incorrect issuer")
		return
	}
	targetLinkUri := r.FormValue("target_link_uri")
	clientID := r.FormValue("client_id")

	// platform2 server auth endpoint:
	redirURL := "http://localhost:9090/authlogin?" +
		"client_id=" + clientID + "&target_link_uri=" + targetLinkUri +
		"&login_hint=" + loginHint + "&response_type=id_token" +
		// "&state=" + myState +
		"&redirect_uri=http://localhost:8881/ltiLaunch" +
		"&lti_message_hint=" + ltiMessageHint + "&lti_deployment_id=" + ltiDeploymentID

	setCallbackCookie(w, r, "state", myState)
	setCallbackCookie(w, r, "nonce", nonce)

	// fmt.Fprintf(w, "Redirecting to LMS authorization endpoint...")
	fmt.Println("URL redirect - to the Plat side: " + redirURL)
	http.Redirect(w, r, redirURL, http.StatusFound)
}

func handleContent(w http.ResponseWriter, r *http.Request) {
	w.Write([]byte("These are the droids you are looking for " + r.FormValue("name") + " 🎉"))
}

func main() {
	// LTI Login Initialization Endpoint
	http.HandleFunc("/ltiLogin", handleLoginInit)

	// LTI Launch Endpoint
	http.HandleFunc("/ltiLaunch", handleLaunch)

	http.HandleFunc("/content", handleContent)

	// Start the server
	fmt.Println("Starting server on :8881...")
	http.ListenAndServe(":8881", nil)
}
