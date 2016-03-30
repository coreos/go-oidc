/*
Package oidc implements OpenID Connect client logic for the golang.org/x/oauth2 package.

	provider, err := oidc.NewProvider(ctx, "https://accounts.exmaple.com")
	if err != nil {
		return err
	}

	// Configure an OpenID Connect aware OAuth2 client.
	config := oauth2.Config{
		ClientID:     clientID,
		ClientSecret: clientSecret,
		RedirectURL:  redirectURL,
		Endpoint:     provider.Endpoint(),
		Scopes:       []string{oidc.ScopeOpenID, "profile", "email"},
	}

	// A verifier for JWTs.
	verifier := provider.Verifier(ctx)

OAuth2 redirects are unchanged.

	func handleRedirect(w http.ResponseWriter, r *http.Request) {
		http.Redirect(w, r, config.AuthCodeURL(state), http.StatusFound)
	})

For callbacks the oidc package can be used to extract ID Tokens and UserInfo data.

	func handleOAuth2Callback(w http.ResponseWriter, r *http.Request) {
		// Verify state...

		oauth2Token, err := config.Exchange(ctx, r.URL.Query().Get("code"))
		if err != nil {
			http.Error(w, "Failed to exchange token: "+err.Error(), http.StatusInternalServerError)
			return
		}

		idToken, err := oidc.ParseIDToken(verifier, oauth2Token)
		if err != nil {
			http.Error(w, "Failed to get token: "+err.Error(), http.StatusInternalServerError)
			return
		}

		userinfo, err := provider.UserInfo(ctx, oauth2.StaticTokenSource(oauth2Token))
		if err != nil {
			http.Error(w, "Failed to get userinfo: "+err.Error(), http.StatusInternalServerError)
			return
		}

		// ...
	})

This package uses contexts to derive HTTP clients in the same way as the oauth2 package. To configure
a custom client, use the oauth2 packages HTTPClient context key when constructing the context.

	myClient := &http.Client{}

	myCtx := context.WithValue(parentCtx, oauth2.HTTPClient, myClient)

	// NewProvider will use myClient to make the request.
	provider, err := oidc.NewProvider(myCtx, "https://accounts.example.com")
*/
package oidc
