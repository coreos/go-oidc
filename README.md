# go-oidc

[![Go Reference](https://pkg.go.dev/badge/github.com/coreos/go-oidc/v3/oidc.svg)](https://pkg.go.dev/github.com/coreos/go-oidc/v3/oidc)

OpenID Connect is a specification on top of OAuth 2.0 that adds a
provider-agnostic API for user attributes. End users perform the regular OAuth 2.0 flow
and the response includes a JWT signed by the identity provider with [standard
claims][oidc-claims] for a stable identifier, email, display name, and other
attributes.

```json
{
  "sub": "12345abcd",
  "email": "janedoe@example.com",
  "email_verified": true,
  "name": "Jane Doe"
}
```

[oidc-claims]: https://openid.net/specs/openid-connect-core-1_0.html#StandardClaims

This package can be used to identify users (and even [workload identities][github-workload])
across a large number of identity providers:

- Consumer
  - [Google](https://developers.google.com/identity/openid-connect/openid-connect)
  - [Apple (Sign in with Apple)](https://developer.apple.com/sign-in-with-apple/)
  - [Microsoft](https://learn.microsoft.com/en-us/entra/identity-platform/v2-protocols-oidc)
  - [Facebook Login](https://developers.facebook.com/docs/facebook-login/)
  - [LinkedIn](https://learn.microsoft.com/en-us/linkedin/consumer/integrations/self-serve/sign-in-with-linkedin-v2)
- Enterprise
  - [Microsoft Entra ID](https://learn.microsoft.com/en-us/entra/identity-platform/v2-protocols-oidc)
  - [Okta](https://developer.okta.com/docs/concepts/oauth-openid/)
  - [Auth0](https://auth0.com/docs/authenticate/protocols/openid-connect-protocol)
  - [Amazon Cognito](https://docs.aws.amazon.com/cognito/latest/developerguide/cognito-user-pools-oidc-idp.html)
  - [OneLogin](https://developers.onelogin.com/openid-connect)
- Workload
  - [GitHub Actions](https://docs.github.com/en/actions/concepts/security/openid-connect)
  - [GitLab CI/CD (ID tokens)](https://docs.gitlab.com/ci/cloud_services/)
  - [Google Cloud Workload Identity Federation](https://cloud.google.com/iam/docs/workload-identity-federation)
  - [AWS (IAM OIDC identity providers)](https://docs.aws.amazon.com/IAM/latest/UserGuide/id_roles_providers_create_oidc.html)
  - [Kubernetes (service account / OIDC tokens)](https://kubernetes.io/docs/reference/access-authn-authz/authentication/#openid-connect-tokens)
  - [HashiCorp HCP Terraform](https://developer.hashicorp.com/terraform/cloud-docs/workspaces/dynamic-provider-credentials/workload-identity-tokens)

[github-workload]: https://oblique.security/blog/github-actions-identity/

go-oidc is a mature OpenID Connect client, and is imported by [over 1000][go-oidc-imports]
open source projects.

[go-oidc-imports]: https://pkg.go.dev/github.com/coreos/go-oidc/v3/oidc?tab=importedby

## OpenID Connect support for Go

This package enables OpenID Connect support for the [golang.org/x/oauth2][go-oauth2-doc] package.
The client can be initialized through OpenID Connect discovery with the issuer
URL and a few additional scopes on the `oauth2.Config`.

[go-oauth2-doc]: https://pkg.go.dev/golang.org/x/oauth2

```go
provider, err := oidc.NewProvider(ctx, "https://accounts.google.com")
if err != nil {
    // handle error
}

// Configure an OpenID Connect aware OAuth2 client.
oauth2Config := oauth2.Config{
    ClientID:     clientID,
    ClientSecret: clientSecret,
    RedirectURL:  redirectURL,

    // Discovery returns the OAuth2 endpoints.
    Endpoint: provider.Endpoint(),

    // "openid" is a required scope for OpenID Connect flows.
    Scopes: []string{oidc.ScopeOpenID, oidc.ScopeProfile, oidc.ScopeEmail},
}

// Create an ID Token verifier.
idTokenVerifier := provider.Verifier(&oidc.Config{ClientID: clientID})
```

OAuth2 redirects are unchanged, except for PKCE ([RFC 7636][pkce]). The [OAuth 2.0
Security Best Current Practice][oauth2-bcp] requires PKCE for public clients and
recommends it for confidential ones, and some providers reject an authorization
code exchange that omits it. `golang.org/x/oauth2` implements it: generate a
verifier per authorization request, send its challenge on the redirect, and hold
the verifier until the callback.

```go
func handleRedirect(w http.ResponseWriter, r *http.Request) {
    // A fresh verifier is required for each authorization request. Store it the
    // same way the state is stored, so the callback can replay it.
    codeVerifier := oauth2.GenerateVerifier()

    http.Redirect(w, r, oauth2Config.AuthCodeURL(state,
        oauth2.S256ChallengeOption(codeVerifier)), http.StatusFound)
}
```

[pkce]: https://datatracker.ietf.org/doc/html/rfc7636
[oauth2-bcp]: https://datatracker.ietf.org/doc/html/rfc9700#section-2.1.1

Then, on the response, the ID Token verifier can be used to verify ID Tokens.

```go
func handleOAuth2Callback(w http.ResponseWriter, r *http.Request) {
    // Verify state and errors.

    // Replay the verifier held since the redirect.
    oauth2Token, err := oauth2Config.Exchange(ctx, r.URL.Query().Get("code"),
        oauth2.VerifierOption(codeVerifier))
    if err != nil {
        // handle error
    }

    // Extract the ID Token from OAuth2 token.
    rawIDToken, ok := oauth2Token.Extra("id_token").(string)
    if !ok {
        // handle missing token
    }

    // Parse and verify ID Token payload.
    idToken, err := idTokenVerifier.Verify(ctx, rawIDToken)
    if err != nil {
        // handle error
    }

    // Extract custom claims
    var claims struct {
        Email         string `json:"email"`
        EmailVerified bool   `json:"email_verified"`
        Name          string `json:"name"`
        Picture       string `json:"picture"`
    }
    if err := idToken.Claims(&claims); err != nil {
        // handle error
    }
}
```

## Examples

The [example](example) directory holds runnable programs for the flows above,
each performing the full authorization code exchange with PKCE:

- [example/idtoken](example/idtoken) parses and verifies an ID Token.
- [example/userinfo](example/userinfo) queries the UserInfo endpoint.
- [example/logout](example/logout) verifies back-channel logout tokens.
