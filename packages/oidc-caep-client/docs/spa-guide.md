# Building a browser single-page app with oidc-caep-client

This guide shows how to build a browser single-page app (SPA) on `oidc-caep-client`. By the end, your app signs people in with OpenID Connect, keeps their tokens fresh, calls your APIs with sender-constrained tokens, and reacts within seconds when the identity provider reports a change about a signed-in user through CAEP.

Everything runs in the browser. Your web server only serves files and security headers; it holds no tokens and no secrets. The library is a **public client**: it never has a client secret, so anyone can read your page's code without gaining anything.

The [README](../README.md) is the API reference: every option, method and event. This guide is the walkthrough. It explains which pieces to use, in what order, and why. The demo in this repository ([`demo/`](../../../demo)) is a working app built this way.

**Who this is for.** Apps whose code runs in a web page: React, Vue, Svelte, or plain ES modules. It isn't for native mobile apps, and it isn't for server-rendered apps that can keep a secret. Those should use a confidential client on the server.

## Contents

1. [How the pieces fit together](#1-how-the-pieces-fit-together)
2. [Set up the identity provider](#2-set-up-the-identity-provider)
3. [Serve the app](#3-serve-the-app)
4. [Create the client](#4-create-the-client)
5. [Choose where tokens and keys live](#5-choose-where-tokens-and-keys-live)
6. [Sign in](#6-sign-in)
7. [Call your APIs](#7-call-your-apis)
8. [Several accounts in one browser](#8-several-accounts-in-one-browser)
9. [Receive CAEP events](#9-receive-caep-events)
10. [Sign out](#10-sign-out)
11. [Errors](#11-errors)
12. [Security checklist](#12-security-checklist)
13. [Troubleshooting](#13-troubleshooting)

## 1. How the pieces fit together

| Piece | What it does |
|---|---|
| `OIDCClient` | Sign-in (Authorization Code + PKCE, PAR, DPoP), ID token validation, refresh, UserInfo, sign-out. |
| `TokenManager` | Caches one person's tokens and refreshes them before they expire. |
| `AccountManager` | Several people signed in to one browser, one active account per tab. Use it instead of `TokenManager` when you need that. |
| `SSFReceiver` | Subscribes to the identity provider's Shared Signals stream, polls it, validates each event and hands it to your handlers. |
| Stores | Where tokens, the DPoP key and the in-flight sign-in live: memory, `sessionStorage` or IndexedDB. |

```
 Browser (your SPA)                                     Identity provider
 ───────────────────                                    ─────────────────
 OIDCClient ──── authorize (PAR), token, UserInfo ────▶ OpenID Connect endpoints
 TokenManager / AccountManager (refresh, DPoP proofs)
 SSFReceiver ──── create / read stream, poll ─────────▶ SSF transmitter (/ssf/...)
      ▲                                                       │
      └──────────── signed security events (SETs) ◀───────────┘
 your handlers: end the session, refresh tokens, ask for step-up, ...
 your APIs ◀──── fetchResource(): access token + DPoP proof
```

The identity provider is usually both the OpenID provider and the SSF transmitter. The receiver authenticates to the transmitter with the **signed-in person's own access token**, so it can only see that person's stream. A browser can't receive pushed events, so delivery is always **poll** (RFC 8936).

## 2. Set up the identity provider

Register your app as a **public client**:

| Setting | Value |
|---|---|
| Client type | public, `token_endpoint_auth_method: none` |
| Grant types | `authorization_code`, `refresh_token` |
| Response type | `code` |
| Redirect URI | your callback page, e.g. `https://app.example.com/callback` |
| Post-logout redirect URI | e.g. `https://app.example.com/` |
| Allowed scopes | `openid profile email`, `offline_access` for refresh tokens, and the CAEP scopes below |
| CORS origin | your app's origin, e.g. `https://app.example.com` |

**CORS is required.** The browser calls the identity provider directly from your origin: discovery, the PAR and token endpoints, UserInfo, revocation, and every SSF endpoint. If the provider doesn't allow your origin, these calls fail with a network error.

**TLS.** Every provider endpoint, and your redirect URIs, must be `https`. Loopback `http` (`localhost`, `127.0.0.1`) is allowed for development. The browser must also trust the provider's certificate. With a self-signed development certificate, open the provider's URL once and accept it, or install a local CA such as mkcert.

**CAEP scopes.** These are the CAEP Interoperability Profile's names:

| Scope | Lets the receiver |
|---|---|
| `ssf.read` | read its stream and its status, and poll for events |
| `ssf.manage` | everything `ssf.read` does, plus create, change or delete a stream, add or remove subjects, change the stream's status and request a verification event |

An app that only consumes a stream someone else created needs `ssf.read`. An app that creates its own stream, chooses its event types or adds the user as the stream's subject needs `ssf.manage`.

### iya-sts

With iya-sts, both scopes are gated by role. A person is issued `ssf.read` only while two things are true: they are in the group `ssf-read`, and your application is an **application member** of the native role `SSF_READ`. `ssf.manage` works the same way through the group `ssf-manage` and the role `SSF_MANAGE`, which does not authorize `ssf.read`, so ask for both. Every realm has these roles and groups by default. Applications have to be added to the roles; nothing adds them for you.

[`scripts/register-iya-sts-client.mjs`](../../../scripts/register-iya-sts-client.mjs) does all of this for the demo:

- registers the public client;
- adds it to `SSF_READ` and `SSF_MANAGE`;
- creates a test user in `ssf-read` and `ssf-manage`.

Read it as an example of the management API calls involved.

Two settings look similar but **don't** grant a scope:

- An application's **required roles** (`appRequiredRole`) decide who may sign in to it.
- A role's **conferring clients** lend the role to people who sign in through them. The SSF roles ignore conferral.

## 3. Serve the app

### Install the library

```sh
npm install oidc-caep-client
```

That adds `"oidc-caep-client": "^0.1.0"` to the `dependencies` in your `package.json`, and installs its one dependency, [`jose`](https://github.com/panva/jose). Versions are `M.N.O`, with `O` the UTC build time, so `^0.1.0` takes every later 0.1 build. Pin one version instead for reproducible builds. `npm install oidc-caep-client@next` gets the latest build from `develop`, ahead of a release. The README's [Installing](../README.md#installing) section has the details.

### Load the library

The library is plain ES modules. With a bundler, `import { OIDCClient } from 'oidc-caep-client'` just works. Without one, serve both packages from `node_modules` and add an import map, as the demo does:

```html
<script type="importmap">{"imports":{"jose":"/vendor/jose/index.js","oidc-caep-client":"/lib/index.js"}}</script>
<script type="module" src="/app.js"></script>
```

Serve `node_modules/oidc-caep-client/src/` at `/lib/`, and `jose`'s browser build (`node_modules/jose/dist/webapi/`) at `/vendor/jose/`.

### Serve the page at the callback path too

The provider sends the browser back to your redirect URI (`/callback`) with `code` and `state` in the query string. Serve your app's page there as well, so the same code completes the sign-in.

### Send these headers

The authorization code arrives in the page's URL, and the page holds live tokens. Lock it down:

```http
Content-Security-Policy: default-src 'none'; script-src 'self' 'sha256-<hash of the import map>'; style-src 'self'; img-src 'self' data:; connect-src 'self' https:; base-uri 'none'; form-action 'self'; frame-ancestors 'none'; object-src 'none'
Referrer-Policy: no-referrer
X-Content-Type-Options: nosniff
X-Frame-Options: DENY
Cross-Origin-Opener-Policy: same-origin
Cache-Control: no-store            (on the HTML page)
```

- **No inline script.** An injected script can use your tokens while the page is open. CSP is what keeps it out.
- **`Referrer-Policy: no-referrer`** keeps the code and state in the callback URL out of `Referer` headers (RFC 9700 §4.2.4).
- **`frame-ancestors 'none'`** stops another site from framing your sign-in button (RFC 9700 §4.16).
- Narrow `connect-src` to your provider's and your APIs' origins once you know them.

[`demo/server.js`](../../../demo/server.js) is a complete example, including how it computes the import map's hash.

## 4. Create the client

```js
import { OIDCClient } from 'oidc-caep-client';

const client = await OIDCClient.discover({
  issuer: 'https://idp.example.com',             // reads /.well-known/openid-configuration
  clientId: 'my-spa',
  redirectUri: `${location.origin}/callback`,
  postLogoutRedirectUri: `${location.origin}/`,
  scope: 'openid profile email offline_access ssf.read ssf.manage',
  dpop: true,                                    // see section 5 for where the key lives
});
```

If you already have the metadata document, use `OIDCClient.fromMetadata(metadata, { ... })` instead. The client checks the metadata before using it:

- **PKCE:** the provider must offer `S256`, otherwise the client refuses it.
- **Public clients:** the provider must accept `none` as a token endpoint authentication method.
- **TLS:** every endpoint must be `https`, apart from loopback addresses.

**PAR** is used whenever the provider offers it (`par: 'auto'`). `client.securityFeatures` lists the protections in effect, which is useful to show on a diagnostics page.

## 5. Choose where tokens and keys live

Anything in browser storage can be read by script running in your page. Two things limit what that script can do with stolen tokens:

- **DPoP** binds each token to a key pair. A token is useless without a proof signed by the private key.
- A **non-extractable** WebCrypto key can sign while the page is open, but can't be read out. So a stolen token can't be used anywhere else.

Pick one row:

| Setup | Tokens | DPoP key | Survives | Trade-off |
|---|---|---|---|---|
| **Memory** (default) | `MemoryTokenStore` | `MemoryKeyStore` | nothing; a reload signs the person in again (often silently) | Smallest exposure; most sign-in round trips. |
| **Per tab** | `WebStorageTokenStore` (sessionStorage) | `WebStorageKeyStore` (sessionStorage) | reloads and the trip to the provider; cleared when the tab closes | Each tab has its own sign-in. The key is **extractable**, because Web Storage holds only strings. |
| **Whole browser** | `IndexedDBTokenStore` | `IndexedDBKeyStore` | closing the browser | Every tab shares the accounts. The key stays **non-extractable**. Tokens last until sign-out. |

```js
import { IndexedDBKeyStore, OIDCClient, WebStorageKeyStore } from 'oidc-caep-client';

// Whole browser: a non-extractable key that survives reloads.
const client = await OIDCClient.discover({ /* ... */ dpop: { keyStore: new IndexedDBKeyStore() } });

// Per tab: the demo's choice.
const perTab = await OIDCClient.discover({ /* ... */ dpop: { keyStore: new WebStorageKeyStore() } });
```

`AccountManager` defaults to the whole-browser row only when DPoP is on, and to memory otherwise. Pass a persistent store without DPoP and it logs a warning: tokens readable by script and usable anywhere shouldn't outlive the page.

The in-flight sign-in (`state`, `nonce`, the PKCE verifier) always goes to `sessionStorage`. It's single use and expires after 10 minutes (`transactionTtlSec`).

## 6. Sign in

For one person per browser, `TokenManager` is enough:

```js
import { TokenManager } from 'oidc-caep-client';

const tokens = new TokenManager(client);         // memory by default; pass { store } for another

// On the sign-in button:
async function signIn() {
  const { url } = await client.createAuthorizationRequest();
  location.assign(url);
}

// On page load:
if (location.pathname === '/callback') {
  try {
    const tokenSet = await client.callback(location.href);
    await tokens.set('user', tokenSet);           // refreshed in the background from now on
  } finally {
    history.replaceState(null, '', '/');         // take the code out of the address bar
  }
}
```

`callback()` checks everything before returning tokens:

- **The response:** `state` (single use, bound to this provider and client), the `iss` parameter (RFC 9207), and that no tokens or repeated parameters arrived in the URL.
- **The tokens it gets back:** the ID token's signature and claims, `nonce` and `at_hash`.

If any check fails, it throws (section 11). Then send the person back to `signIn()`.

Useful options on `createAuthorizationRequest()`:

| Option | Use |
|---|---|
| `prompt: 'login'` | Ask for the password again (a fresh sign-in). |
| `prompt: 'none'` | Try silently, e.g. after a reload with memory storage. Fails with `login_required` if there is no session. |
| `loginHint`, `idTokenHint` | Name the person you expect. |
| `expectedSub` | Refuse a sign-in as anybody else (`account_mismatch`). |
| `acrValues`, `maxAge` | Step-up: ask for a stronger or more recent authentication. With `enforceAcr` (the default), a returned `acr` outside `acrValues` is refused. |
| `context` | Your own JSON data, handed back by `completeAuthorization()`. Use it, for example, to return to the page the person started from. |

## 7. Call your APIs

```js
const tokenSet = await tokens.getTokenSet('user');          // refreshed first if due
const res = await client.fetchResource(tokenSet, 'https://api.example.com/orders', {
  method: 'POST',
  headers: { 'content-type': 'application/json' },
  body: JSON.stringify(order),
});
```

`fetchResource()` sends the access token. When the token is DPoP-bound, it also sends a fresh proof for this method and URL. If your API asks for a DPoP nonce, it retries with that nonce. With your own HTTP client, get the headers from `client.resourceHeaders(tokenSet, { method, url })` and send them yourself.

Your API must then verify the proof as RFC 9449 says: `htm`, `htu`, `ath` and `jti`, and that the key matches the token's `cnf.jkt`.

## 8. Several accounts in one browser

Some providers, iya-sts among them, keep several people signed in to one browser. `AccountManager` handles the app's side of that:

- every account's tokens are cached;
- each tab has one **active** account;
- the others are **dormant**: kept, but neither refreshed nor used.

```js
import { AccountManager, WebStorageTokenStore } from 'oidc-caep-client';

const accounts = await new AccountManager(client, {
  store: new WebStorageTokenStore(),            // or the default IndexedDBTokenStore for the whole browser
  onActivate: async (account, { getTokenSet }) => { /* start this account's CAEP receiver */ },
  onDeactivate: (account) => { /* stop polling its stream */ },
  onLeave: async (account, { getTokenSet }) => { /* signed out or ended: delete its stream */ },
}).init();

location.assign((await accounts.signIn()).url);          // or addAccount() for another person
const { account } = await accounts.handleCallback(location.href);
const tokenSet = await accounts.getTokenSet();           // always the active account's
```

- **Switching accounts.** `accounts.activate(key)` makes another account active. It refreshes that account's tokens first, and lets its receiver catch up on events queued while it was dormant.
- **Signing a signed-out account back in.** `reauthenticate(key)` starts a sign-in that names that account (`login_hint`, `prompt=login`) and refuses anybody else.
- **Events.** `on('signed-out' | 'ended' | 'activated' | ...)` tells you when to update the page.

The README's *Several accounts in one browser* section has every rule.

## 9. Receive CAEP events

### Start a receiver for the signed-in person

```js
import { SSFReceiver, Subject, subjectMatches } from 'oidc-caep-client';

const receiver = new SSFReceiver({
  transmitterIssuer: 'https://idp.example.com',          // reads /.well-known/ssf-configuration
  // Every call to the transmitter carries this person's token, with a DPoP proof when bound.
  authorizationHeaders: async (req) => client.resourceHeaders(await tokens.getTokenSet('user'), req),
  description: `my-spa @ ${location.origin}`,
  pollIntervalMs: 5000,
});

await receiver.start({ catchUp: true });               // discover, create or reuse the stream, act on what's queued
await receiver.addSubject(Subject.issSub(user.iss, user.sub)).catch(() => {}); // needs ssf.manage
```

`start()` either opens an existing stream or creates one:

- **Opening an existing stream:** pass its id as `streamId`. Keep the id, for example in `localStorage`, to reopen the same stream later.
- **Creating a stream:** this needs `ssf.manage`. If the transmitter already has a stream for this person, it is reused.

`catchUp: true` handles the events queued while nobody was polling, before `start()` returns. Do this before the person uses the app, so a session revoked in the meantime is acted on first.

With `ssf.read` only, you can't create a stream. Find one with `listStreams()` and pass its id as `streamId`. The demo shows both paths (`startCaep()` in [`demo/public/app.js`](../../../demo/public/app.js)).

### Choose the event types

A new stream asks for every CAEP event type unless you pass `eventsRequested`. To change an existing stream's types (needs `ssf.manage`):

```js
import { CAEP } from 'oidc-caep-client';

await receiver.updateStream({ events_requested: [CAEP.SESSION_REVOKED, CAEP.CREDENTIAL_CHANGE, CAEP.RISK_LEVEL_CHANGE] });
console.log(receiver.stream.events_delivered);          // what the transmitter will actually send
```

The transmitter decides `events_delivered`: the types you asked for that it supports. The scopes control which operations you may perform on the stream, not which event types you may receive. The demo's CAEP tab lets the person tick types and applies them with this call.

### Handle the events

Register one handler per event type. Each handler gets a validated event: `type`, `name`, `payload`, `subject`, `reasonUser`, `reasonAdmin`, `jti` and more.

```js
receiver
  .onSessionRevoked(async () => signOutLocally('Your session was ended by the identity provider.'))
  .onTokenClaimsChange(async () => tokens.refresh('user'))
  .onCredentialChange(async (evt) => {
    if (['revoke', 'delete'].includes(evt.payload.change_type)) await signOutLocally('Sign in again.');
  })
  .onAssuranceLevelChange((evt) => {
    if (evt.payload.change_direction === 'decrease') askForStepUp();   // createAuthorizationRequest({ acrValues, prompt: 'login' })
  })
  .onDeviceComplianceChange(async (evt) => {
    if (evt.payload.current_status === 'not-compliant') await signOutLocally('This device no longer meets policy.');
  })
  .onRiskLevelChange(async (evt) => {
    if (evt.payload.current_level === 'HIGH') await signOutLocally('Unusual activity was detected.');
  })
  .onSessionEstablished(() => {})                       // informational
  .onSessionPresented(() => {})                         // informational
  .onError((err, ctx) => console.warn('CAEP', ctx.phase, err));
```

Which events need action is your policy. These are reasonable defaults:

| Event | Reasonable reaction |
|---|---|
| session-revoked | End the local session and discard its tokens. |
| token-claims-change | Refresh tokens so the new claims (`payload.claims`) take effect. |
| credential-change | Revoked or deleted: end the session. Otherwise tell the person. |
| assurance-level-change | Decrease: require step-up before sensitive actions. |
| device-compliance-change | Not compliant: end the session, or limit what the app allows. |
| risk-level-change | HIGH: end the session. MEDIUM: require step-up. |
| session-established, session-presented | Informational; record or display them. |

**Check who an event is about.** A stream can carry events about other sessions of the same person. Before acting, compare the event's subject with the session you hold:

```js
if (!subjectMatches(evt.subject, { iss: user.iss, sub: user.sub, sid: idTokenClaims.sid })) return;
```

An email or phone number subject counts only with `email_verified` / `phone_number_verified: true` in the identity: an unverified address could belong to anybody. An event that names a session matches only the identity holding that `sid`.

### Add your own logic for every event

`onEventReceived` runs once for every accepted event, before the typed handlers. By default it prints the event's name and `jti` to the console (`logEventReceived`), leaving out the payload and subject, which can carry personal data. Put logging, auditing or analytics here:

```js
import { logEventReceived } from 'oidc-caep-client';

const receiver = new SSFReceiver({
  /* ... */
  onEventReceived: async (evt) => {
    logEventReceived(evt);                               // keep the console line, or drop it
    await myAudit.record({ event: evt.name, subject: evt.subject, at: evt.eventTimestamp });
  },
});
```

Pass `onEventReceived: null` to turn it off. If it throws, `onError` gets the error with `phase: 'hook'`, and the typed handlers still run.

### What the receiver checks for you

Every event (a signed SET) is refused unless all of these hold:

- **The signature** verifies against the transmitter's keys, uses an asymmetric algorithm, and has `typ: secevent+jwt`.
- **`iss`** is the transmitter.
- **`aud`** is your stream's.
- **`iat`** isn't in the future. There's no age limit by default, so events queued while nobody was polling are still acted on when the receiver catches up.
- **`events`** holds exactly one event, and a stream event (verification, stream-updated) names this stream.
- **`jti`** hasn't been seen before. A repeat is dropped.

The receiver is careful about what it tells the transmitter, because an acknowledged event, or one reported as an error, is never sent again:

- **An invalid event** goes to `onError`, is reported back to the transmitter on the next poll, and never reaches your handlers.
- **An event that couldn't be checked** for a reason that may pass (a network error fetching the keys, a key the cached set doesn't hold yet) is left for the transmitter to send again.
- **An event is acknowledged only after your handlers succeed.** If one throws, the event comes back on a later poll, up to `maxDeliveryAttempts` times (default 5). Write handlers so that running twice is harmless; a reload can also bring an event back.
- **The poll URL** must use https and be at the transmitter's origin, because every poll carries the person's access token.

Without an `onError`, errors are written to `console.error`, so a lost event always leaves a trace.

### Stop and clean up

```js
receiver.stop();                              // stop polling; the stream keeps queueing events
await receiver.stop({ deleteStream: true });  // on sign-out, with ssf.manage: remove the stream
```

## 10. Sign out

```js
async function signOut() {
  const tokenSet = await tokens.getTokenSet('user');
  await receiver.stop({ deleteStream: true }).catch(() => {});
  const logout = await client.createEndSessionRequest({ idTokenHint: tokenSet.id_token });
  await tokens.delete('user', { revoke: true });        // revokes at the provider (RFC 7009)
  clearAppState();                                      // including any CAEP events you stored
  location.assign(logout.url);
}

// On the post-logout page:
if (new URLSearchParams(location.search).has('state')) {
  await client.validateEndSessionCallback(location.href);
  history.replaceState(null, '', '/');
}
```

With `AccountManager`, `accounts.signOut(key)` does the revocation and builds the logout request for that account only. Its `signed-out` event is a good place to clear that account's data.

## 11. Errors

Every error the library throws is an `OIDCClientError` with a `code`.

| Class | When | Examples of `code` |
|---|---|---|
| `OAuthError` | The provider answered with an OAuth error. `error_description` is in the message. | `login_required`, `consent_required`, `account_selection_required`, `invalid_grant`, `invalid_scope`, `use_dpop_nonce` |
| `ValidationError` | A response or token failed a check. | `state_missing`, `state_mismatch`, `state_reused`, `transaction_expired`, `issuer_mismatch`, `nonce_mismatch`, `invalid_id_token`, `acr_mismatch`, `account_mismatch`, `front_channel_token` |
| `SETValidationError` | A security event was refused. Reported to `onError`. | `invalid_key`, `invalid_audience` |
| `SSFError` | The transmitter can't be used as configured. | no poll delivery, no stream |
| `OIDCClientError` | Everything else. | `network_error`, `http_error`, `insecure_endpoint`, `pkce_not_supported`, `public_client_not_supported`, `no_refresh_token` |

`needsInteraction(err)` is true when only a visible sign-in can fix the problem: `login_required`, `interaction_required`, `consent_required` or `account_selection_required`. When it's true, send the person to sign in rather than retrying silently.

## 12. Security checklist

- [ ] The client is public. The app holds no secret.
- [ ] DPoP is on. With persistent storage, the key is in IndexedDB (non-extractable), or you accept an extractable per-tab key.
- [ ] The CSP has no inline script and no `eval`, and `frame-ancestors 'none'` is set.
- [ ] `Referrer-Policy: no-referrer` is set, and the callback strips the code from the URL (`history.replaceState`).
- [ ] The provider allows only your exact redirect URIs and your origin for CORS.
- [ ] The app asks for only the scopes it uses. `ssf.manage` is only for apps that manage their own stream.
- [ ] The receiver catches up (`start({ catchUp: true })`) before a restored session is used.
- [ ] CAEP handlers check `subjectMatches()` before acting, and fail safe.
- [ ] Signing out revokes tokens, deletes or stops the stream, and clears any stored events.

## 13. Troubleshooting

| Symptom | Likely cause |
|---|---|
| `network_error` or "Failed to fetch" on discovery, token or SSF calls | The provider doesn't allow your origin (CORS), or the browser doesn't trust its certificate. Open the provider URL in a tab to check the certificate. |
| `insecure_endpoint` / `insecure_redirect_uri` | An endpoint or redirect URI isn't `https`. Only loopback may use `http`. |
| `public_client_not_supported` | The provider's metadata doesn't list `none` in `token_endpoint_auth_methods_supported`. |
| `state_mismatch` or `transaction_expired` on the callback | The sign-in started in another tab or browser, took longer than 10 minutes, or the callback page was reloaded. Start again. |
| `invalid_scope`, or a scope missing from the token | The client isn't allowed that scope, or (iya-sts) the person or application lacks the role. iya-sts logs `STS-ADMIN-0821` saying which condition failed. |
| The SSF calls answer 401 or 403 | The access token lacks `ssf.read` / `ssf.manage`, or the stream belongs to somebody else. |
| No events arrive | The stream doesn't ask for that type (`receiver.stream.events_delivered`), has no subject, or isn't polling (`onError` with `phase: 'poll'`). |
| `account_mismatch` | A request that named an account came back signed in as somebody else. The tokens were revoked; ask the person to sign in as the named account. |

To check a setup end to end, run the demo against your provider (`docker compose up --build`, then open `http://localhost:3000`), and send test events from the provider's admin console or API.
