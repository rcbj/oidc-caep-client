# oidc-caep-client

An in-browser OpenID Connect client library, plus a demo single-page app. The library runs as a **public client** and implements the OAuth 2.0 / OIDC security best practices: PKCE, a hardened `state`, nonce, RFC 9207, PAR, DPoP with a non-extractable key, strict ID token validation, and TLS enforcement. It also subscribes to **CAEP** events over the Shared Signals Framework, with one handler per event.

| Path | What it is |
|---|---|
| [`packages/oidc-caep-client`](packages/oidc-caep-client) | **The library**: Web APIs only, so it runs in browsers and in Node.js. See its [README](packages/oidc-caep-client/README.md) for the security features and the API. |
| [`demo`](demo) | A single-page app, served by a small static server in one container. The OIDC client runs in the browser and reads `demo/public/oidc.json`. |

## Run the demo

```sh
docker compose up --build
```

Open **http://localhost:3000**. The page loads [`demo/public/oidc.json`](demo/public/oidc.json) (served at `/oidc.json`): an OIDC metadata URL, a public `client_id`, and scopes. There is no configuration form. It fetches that metadata document from the browser, so the identity provider must allow CORS from this origin and the browser must trust the provider's certificate.

The default file points at an iya-sts instance on `https://localhost:8081`, client `oidc-caep-demo`. Register that client in the default realm first:

```sh
ADMIN_API_CLIENT_SECRET=… npm run register-iya-sts
```

`scripts/register-iya-sts-client.mjs` mints a management API token the way `iya-sts/tests/tools/admin-api-token.js` does (`sts-management-api`, client credentials, audience `<issuer>/admin-api`) and creates the public client (`token_endpoint_auth_method: none`) with this page's redirect URIs, the file's scopes, and this origin allowed for CORS. The secret is `ADMIN_API_CLIENT_SECRET` or `STS_ADMIN_API_CLIENT_SECRET`. Pass `--public-url` when the demo is not on `http://localhost:3000`.

These stay on without a setting in the file:

- **DPoP**, with the key kept in this tab's session storage;
- **PAR** whenever the IdP offers it;
- every signed-in account's tokens cached in this tab's **session storage**. Only the tab's active account's tokens are used. Closing the tab clears the cache. The configuration, stream ids and event log stay in local storage.
- **CAEP:** the transmitter issuer is the OIDC issuer. The stream is created with the signed-in user's access token, carrying a DPoP proof when bound, and polled from the browser (RFC 8936). When that token includes `ssf.manage`, the user is added as the stream's only subject. `ssf.read` only polls.

Then click **Sign in**. The page has two tabs, and every pane on the selected tab stays visible.

**Identity** shows sign-in, the protections in effect, the session, the token cache, and the raw and decoded tokens.

**CAEP events** shows the stream and the live event log.

It reacts to events about the signed-in user: `session-revoked` signs them out, `token-claims-change` refreshes their tokens, an assurance drop requires step-up, and so on.

### Several accounts

You can be signed in with several accounts at once, as iya-sts allows with `authn.multipleAccounts` (its docs/multiple-accounts.md). This page keeps every signed-in account's tokens in the tab's session storage. Each tab has **one active account**: only its tokens are used and refreshed, and only its CAEP stream is polled. The other accounts are **dormant**.

- **Switch account**, in the menu under your name, makes another cached account active in this tab, with no password. Before the switch completes, the account's stream catches up on the signals queued while it was dormant. If one of them ended its session, the account shows as ended and its tokens are never used. The log marks such signals *(caught up on activation)*.
- **Each tab has its own cache.** A new tab starts signed out. Closing the tab clears its tokens and its DPoP key.
- **Sign in with another account** is a fresh sign-in (`prompt=login`) that adds an account. **Choose at the identity provider** opens the IdP's account picker (`prompt=select_account`).
- In the **event log**, **This account** shows the active account's signals and **All accounts** shows the signals every tab has received, each marked with its account. A badge counts the signals for another account that this tab hasn't seen yet.
- A signal that ends a session ends **that account only**, and offers **Sign in again**. That sign-in names the account (`login_hint`/`id_token_hint`) and refuses a sign-in as anybody else. A `session-revoked` naming another of the person's sessions (`sid`) is ignored.
- **Sign out** on an account sends a logout naming its ID token, so the IdP ends that session and keeps the others. It also deletes the account's stream, and the other tabs see the account as signed out.

### What the server does

`demo/server.js` only serves static files: the SPA (also at `/callback`), `/oidc.json`, the library as ES modules, and `jose`'s browser build, with no bundler. It holds no tokens. The OIDC settings live in the configuration file. It sets the headers a browser-based OAuth client needs:

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

There are 53 tests. They run against a strict in-memory OP stub that enforces public clients, PKCE, PAR and DPoP (proof signature, `htm`/`htu`/`ath`, key binding and nonces), injected through the library's `fetch` option. They cover:

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
