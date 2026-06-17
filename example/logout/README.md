# Logout example app

This logout example app demonstrates use of the logout endpoint. As opposed to
the other example apps, it runs against Auth0 rather than Google. This works
best with:

- An Auth0 [developer instance][auth0-dev].
- A [Tailscale funnel][tailscale-funnel] or [Cloudflare Tunnel][cloudflare-tunnel]
  to advertise a local logout endpoint on the internet.

[auth0-dev]: https://developer.auth0.com/
[cloudflare-tunnel]: https://developers.cloudflare.com/cloudflare-one/networks/connectors/cloudflare-tunnel/
[tailscale-funnel]: https://tailscale.com/docs/features/tailscale-funnel

Using Tailscale, the tunnel will advertise on a DNS name like:

```
BASE_URL="https://${MY_HOST}.ts.net"
```

Within the Auth0 application, configure "Allowed Callback URLs" with the
following value:

```
${BASE_URL}/callback
```

And "Back-Channel Logout URI" with:

```
${BASE_URL}/logout
```

Then run the logout app with:

```
export CLIENT_ID="{AUTH0_CLIENT_ID}"
export CLIENT_SECRET="{AUTH0_CLIENT_SECRET}"
go run ./example/logout/app.go \
    --base-url="${BASE_URL}" \
    --issuer-url="${AUTH0_ISSUER_URL}"
```

After logging into the app, there will be a "Logout" link at the bottom of the
page that performs RP-Initiated Logout. Clicking on that link, you will logout
through Auth0, and trigger a POST to the logout endpoint.

Once the app receives the logout token, it will validate it and log a message:

```
2026/06/17 13:06:39 Logout token: {
  "Issuer": "${AUTH0_ISSUER_URL}",
  "Subject": "1234",
  "Audience": [
    "${CLIENT_ID}"
  ],
  "IssuedAt": "2026-06-17T13:06:39-07:00",
  "Expiry": "2026-06-17T13:08:39-07:00",
  "SessionID": "Kaeo_qJ9zFDcWI9g_fNVa24rv7uu1gpV"
}
```
