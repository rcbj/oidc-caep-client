# oidc-caep-client

An in-browser OpenID Connect client library, plus a demo single-page app. The library runs as a **public client** and implements the OAuth 2.0 / OIDC security best practices: PKCE, a hardened `state`, nonce, RFC 9207, PAR, DPoP with a non-extractable key, strict ID token validation, and TLS enforcement. It also subscribes to **CAEP** events over the Shared Signals Framework, with one handler per event.

| Path | What it is |
|---|---|
| [`packages/oidc-caep-client`](packages/oidc-caep-client) | **The library**: Web APIs only, so it runs in browsers and in Node.js. See its [README](packages/oidc-caep-client/README.md) for the security features and the API. |
| [`demo`](demo) | A single-page app, served by a small static server in one container. The OIDC client runs in the browser and is configured from the front page against your own OIDC provider. |

## Run the demo

```sh
docker compose up --build
```

Open **http://localhost:3000** and configure the identity provider on the front page:

1. **Metadata:** type the issuer (or its `/.well-known/openid-configuration` URL) and click **Fetch**, or paste the JSON document. The page fetches it from your browser, so the IdP must allow CORS from this origin. The summary shows what the IdP offers (PAR, DPoP, RFC 9207) and warns if it doesn't accept public clients.
2. **Client:** register a **public** client (`token_endpoint_auth_method: none`) with the redirect URIs shown under **Register these with your IdP**, and enter its `client_id`. If the IdP allows Dynamic Client Registration, you can choose **Register a new client** instead. That also fixes the ID token signing algorithm, and can carry a software statement or initial access token.
3. **Security:** these are on by default:
   - **DPoP**, with the key kept non-extractable in IndexedDB;
   - **PAR** whenever the IdP offers it;
   - tokens kept in **memory only**. You can switch to `sessionStorage` so a reload keeps you signed in; with DPoP on, stored tokens are useless without the key.
4. **CAEP:** the transmitter issuer defaults to the OIDC issuer. The stream is created with the signed-in user's access token, carrying a DPoP proof when bound, and polled from the browser (RFC 8936). By default the user is added as the stream's only subject.

Then click **Sign in**. The page shows:

- the **protections in effect**;
- the token cache, with auto-refresh;
- the raw and decoded **tokens**;
- the CAEP stream;
- a live **event log**.

It reacts to events about the signed-in user: `session-revoked` signs them out, `token-claims-change` refreshes their tokens, an assurance drop requires step-up, and so on.

Everything you type is remembered in `localStorage`, except the DCR initial access token. There is no client secret anywhere.

### What the server does

`demo/server.js` only serves static files: the SPA (also at `/callback`), the library as ES modules, and `jose`'s browser build, with no bundler. It holds no tokens and no configuration. It sets the headers a browser-based OAuth client needs:

- **CSP:** scripts only from this origin, with the one inline import map allowed by its SHA-256 hash; no `eval`; no framing.
- **`Referrer-Policy: no-referrer`:** the authorization code arrives in the URL and must not leak.
- **`X-Frame-Options: DENY`**, `nosniff`, and a cross-origin opener policy.
- **`no-store`** on the page and the callback.

| Variable | Default | Purpose |
|---|---|---|
| `PUBLIC_URL` | `http://localhost:3000` | The URL browsers use. The redirect URI is `${PUBLIC_URL}/callback`. With Compose, change it together with `HOST_PORT`. |

## Tests

```sh
npm install
npm test
```

There are 37 tests. They run against a strict in-memory OP stub that enforces public clients, PKCE, PAR and DPoP (proof signature, `htm`/`htu`/`ath`, key binding and nonces), injected through the library's `fetch` option. They cover:

- **State:** single use, expiry, issuer binding, missing and tampered values.
- **Front channel:** injected tokens, repeated parameters, RFC 9207 `iss`, error ordering.
- **Setup checks:** PKCE downgrade, TLS enforcement, public-client-only.
- **ID token:** token-confusion `typ`, stale `iat`, forged signature, `acr`.
- **DPoP:** code and token binding, nonce retry at the token endpoint and resource servers, refresh.
- **Other flows:** PAR, resource indicators, the logout `state`, dynamic registration of a public client.
- **Token cache:** refresh behaviour.
- **SSF:** poll delivery with a DPoP-bound user token, and SET validation (signature, audience, `typ`, age, replay).
- **Browser safety:** a check that the library imports no Node.js built-ins.

## License

MIT © 2026 Iya CyberSecurity Solutions, LLC. See [LICENSE](LICENSE).
