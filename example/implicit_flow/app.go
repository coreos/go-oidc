/*
This is an example application to test the implicit flow.
*/
package main

import (
	"context"
	// "encoding/json"
	"fmt"
	"net/http"
	"strings"
	"time"

	oidc "github.com/coreos/go-oidc/v3/oidc"
	// "github.com/google/uuid"
)

var (
	// issuerURL = "http://localhost:9090"
	issuerURL = "https://canvas.instructure.com"
	// jwksURL   = "http://localhost:9090/keysets"
	jwksURL = "https://canvas.instructure.com/api/lti/security/jwks"
	// clientID  = "client4321"
	clientID = "249610000000000102"
	// deploymentId = "141:33178d8e980cf91cec8f153c868ec5216d001806"
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

	// state, err := r.Cookie("state")
	// if err != nil {
	// 	http.Error(w, "state not found", http.StatusBadRequest)
	// 	return
	// }

	// if state.Value == myState {
	// 	fmt.Println("Got state back!!! 👍")
	// } else {
	// 	fmt.Println("where'd my state go?????")
	// }

	// nonce, err := r.Cookie("nonce")
	// if err != nil {
	// 	http.Error(w, "nonce not found", http.StatusBadRequest)
	// 	return
	// }

	// if nonce.Value == myState {
	// 	fmt.Println("Got nonce back!!! 🎉")
	// } else {
	// 	fmt.Println("where'd my NONCE go?????")
	// }

	// Extract the JWT from the request
	rawIDToken := r.FormValue("id_token")
	// rawIDToken := r.URL.Query().Get("id_token")

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
	fmt.Println(resp["https://purl.imsglobal.org/spec/lti/claim/roles"])
	fmt.Println(resp["https://purl.imsglobal.org/spec/lti/claim/lti1p1"])

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
	lti11claims := resp["https://purl.imsglobal.org/spec/lti/claim/lti1p1"]
	claimedUserID := strings.Split(fmt.Sprintf("%v", lti11claims), " ")[1]
	// claimedUserID := resp["user_id"]
	// claimedUserID := lti11claims["user_id"]
	// w.Write(data)
	// claimedName := "make-me-real"
	http.Redirect(w, r, "/content?user_id="+fmt.Sprintf("%v", claimedUserID), http.StatusFound)
}

// formatRequest generates ascii representation of a request
func formatRequest(r *http.Request) string {
	// Create return string
	var request []string
	// Add the request string
	url := fmt.Sprintf("%v %v %v", r.Method, r.URL, r.Proto)
	request = append(request, url)
	// Add the host
	request = append(request, fmt.Sprintf("Host: %v", r.Host))
	// Loop through headers
	for name, headers := range r.Header {
		name = strings.ToLower(name)
		for _, h := range headers {
			request = append(request, fmt.Sprintf("%v: %v", name, h))
		}
	}

	// If this is a POST, add post data
	if r.Method == "POST" {
		r.ParseForm()
		request = append(request, "\n")
		request = append(request, r.Form.Encode())
	}
	// Return the request as a string
	return strings.Join(request, "\n")
}

func handleLoginInit(w http.ResponseWriter, r *http.Request) {
	fmt.Println(formatRequest(r))
	// Extract necessary parameters like iss, login_hint, target_link_uri, etc.
	// ...

	// Construct the OIDC Authentication request URL
	// Redirect to LMS's OIDC authorization endpoint with required parameters
	// ...
	loginHint := r.FormValue("login_hint")
	ltiMessageHint := r.FormValue("lti_message_hint")
	ltiDeploymentID := r.FormValue("lti_deployment_id")
	// some kind of deployment id check... --> DB
	// iss := r.FormValue("iss")
	// if iss != "Platform" {
	// 	fmt.Println("Incorrect issuer")
	// 	return
	// }
	targetLinkUri := r.FormValue("target_link_uri")
	clientID := r.FormValue("client_id")

	// For Canvas issuer, per https://canvas.instructure.com/doc/api/file.lti_dev_key_config.html
	// https://sso.canvaslms.com/api/lti/authorize_redirect (if launched from a production environment)
	// https://sso.beta.canvaslms.com/api/lti/authorize_redirect (if launched from a beta environment)
	// https://sso.test.canvaslms.com/api/lti/authorize_redirect (if launched from a test environment)

	// platform2 server auth endpoint:
	// redirURL := "http://localhost:9090/authlogin?" +
	redirURL := "https://sso.canvaslms.com/api/lti/authorize_redirect?" +
		"client_id=" + clientID + "&target_link_uri=" + targetLinkUri +
		"&login_hint=" + loginHint + "&response_type=id_token" +
		// "&state=" + myState +
		"&scope=openid" +
		"&redirect_uri=http://localhost:8881/ltiLaunch" +
		"&lti_message_hint=" + ltiMessageHint + "&lti_deployment_id=" + ltiDeploymentID +
		"&nonce=" + nonce + "&prompt=welcome-to-kiddom" +
		"&response_mode=form_post"

	setCallbackCookie(w, r, "state", myState)
	// setCallbackCookie(w, r, "nonce", nonce)

	// fmt.Fprintf(w, "Redirecting to LMS authorization endpoint...")
	fmt.Println("URL redirect - to the Plat side: " + redirURL)
	http.Redirect(w, r, redirURL, http.StatusFound)
}

func handleContent(w http.ResponseWriter, r *http.Request) {
	contentHtml := `<div style="color: blue"><h1>Welcome to kiddom</h1><img src="https://www.kiddom.co/wp-content/uploads/2021/12/kiddom-logo-nav.svg"><h3>These are the droids you are looking for!</h3>` +
		"<p>Welcome to " + r.FormValue("user_id") + "  🎉<p>"
	w.Write([]byte(contentHtml))
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
