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
   - every signed-in account's tokens cached in **IndexedDB**, shared by the browser's tabs. Only the tab's active account's tokens are used. With DPoP on, cached tokens are useless without the key.
4. **CAEP:** the transmitter issuer defaults to the OIDC issuer. The stream is created with the signed-in user's access token, carrying a DPoP proof when bound, and polled from the browser (RFC 8936). By default the user is added as the stream's only subject.

Then click **Sign in**. The page shows:

- the **protections in effect**;
- the token cache, with auto-refresh;
- the raw and decoded **tokens**;
- the CAEP stream;
- a live **event log**.

It reacts to events about the signed-in user: `session-revoked` signs them out, `token-claims-change` refreshes their tokens, an assurance drop requires step-up, and so on.

### Several accounts

You can be signed in with several accounts at once, as iya-sts allows with `authn.multipleAccounts` (its docs/multiple-accounts.md). The library caches every signed-in account's tokens for the whole browser, shared by its tabs. Each tab has **one active account**: only its tokens are used and refreshed, and only its CAEP stream is polled. The other accounts are **dormant**.

- **Switch account**, in the menu under your name or in the **Accounts** card, makes another cached account active in this tab, with no password. Before the switch completes, the account's stream catches up on the signals queued while it was dormant. If one of them ended its session, the account shows as ended and its tokens are never used. The log marks such signals *(caught up on activation)*.
- **Several tabs** can have different active accounts. A new tab lists the accounts already signed in, and any of them can become its active account without signing in again.
- **Sign in with another account** is a fresh sign-in (`prompt=login`) that adds an account. **Choose at the identity provider** opens the IdP's account picker (`prompt=select_account`).
- In the **event log**, **This account** shows the active account's signals and **All accounts** shows the signals every tab has received, each marked with its account. A badge counts the signals for another account that this tab hasn't seen yet.
- A signal that ends a session ends **that account only**, and offers **Sign in again**. That sign-in names the account (`login_hint`/`id_token_hint`) and refuses a sign-in as anybody else. A `session-revoked` naming another of the person's sessions (`sid`) is ignored.
- **Sign out** on an account sends a logout naming its ID token, so the IdP ends that session and keeps the others. It also deletes the account's stream, and the other tabs see the account as signed out.

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

There are 52 tests. They run against a strict in-memory OP stub that enforces public clients, PKCE, PAR and DPoP (proof signature, `htm`/`htu`/`ath`, key binding and nonces), injected through the library's `fetch` option. They cover:

- **State:** single use, expiry, issuer binding, missing and tampered values.
- **Front channel:** injected tokens, repeated parameters, RFC 9207 `iss`, error ordering.
- **Setup checks:** PKCE downgrade, TLS enforcement, public-client-only.
- **ID token:** token-confusion `typ`, stale `iat`, forged signature, `acr`.
- **DPoP:** code and token binding, nonce retry at the token endpoint and resource servers, refresh.
- **Other flows:** PAR, resource indicators, the logout `state`, dynamic registration of a public client.
- **Token cache:** refresh behaviour.
- **Several accounts:**
  - only the active account's tokens are reachable and refreshed;
  - a dormant account is refreshed when it is activated;
  - `onActivate` runs before activation, and a signal handled there can end the account;
  - tabs share the cache, each with its own active account, with no duplicate refresh;
  - a sign-out reaches the other tabs;
  - the IdP's picker, silent resume, refusing a sign-in as another person, and `prompt=none` errors tied to their account;
  - sign-out of one account by its ID token, routing events by subject and session, reloads, and `maxAccounts`.
- **SSF catch-up:** `start({ catchUp: true })` acts on queued SETs before it resolves.
- **SSF:** poll delivery with a DPoP-bound user token, and SET validation (signature, audience, `typ`, age, replay).
- **Browser safety:** a check that the library imports no Node.js built-ins.

## License

MIT © 2026 Iya CyberSecurity Solutions, LLC. See [LICENSE](LICENSE).
