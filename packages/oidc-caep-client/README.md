# oidc-caep-client

An OpenID Connect client library for **browser apps**, configured from the provider's metadata document. It runs as a **public client**: no client secret, and `token_endpoint_auth_method: none`. It covers:

- signing users in;
- caching tokens and refreshing them before they expire;
- subscribing to **CAEP** events through the OpenID Shared Signals Framework, with **one handler per CAEP event**.

It uses Web APIs only (`fetch`, WebCrypto, `URL`, Web Storage, IndexedDB), so it runs in browsers and in Node.js 24.22.1 or later (the release that fixes HTTP2Shell, CVE-2026-111497). Its only dependency is [`jose`](https://github.com/panva/jose).

**New to the library?** [Building a browser single-page app](docs/spa-guide.md) walks through it step by step: setting up the identity provider, serving the page, sign-in, storage, calling APIs, CAEP events and sign-out. This README is the reference.

## Security features

These follow RFC 9700 (the OAuth 2.0 Security Best Current Practice), OpenID Connect Core, and the IETF guidance for browser-based apps.

| Protection | What the library does |
|---|---|
| **Authorization Code + PKCE** | Uses only `response_type=code`, with PKCE `S256`. It refuses an OP whose metadata doesn't offer S256 (downgrade protection). |
| **`state`** | A new random 256-bit value per request, stored with the transaction in `sessionStorage`. On return, `state` is **required** and compared in constant time, and the transaction is **single use** (a replayed response is refused with `state_reused`). It **expires** after `transactionTtlSec` (default 10 minutes) and is **bound to the issuer and client** that started it. It is checked *before* an error response is reported. |
| **`nonce`** | A new random 256-bit value per request, compared in constant time with the ID token's `nonce`. |
| **Mix-up defence** | RFC 9207: the `iss` response parameter must match, and is required when the OP advertises it. Transactions are bound to their issuer. |
| **Authorization response hygiene** | Refuses tokens in the front channel (`access_token`, `id_token` and so on, including in the fragment) and repeated parameters. |
| **PAR** (RFC 9126) | The authorization request is pushed to the OP, so only `client_id` and `request_uri` pass through the browser. Used automatically when advertised (`par: 'auto'`), and required when the OP sets `require_pushed_authorization_requests`. |
| **DPoP** (RFC 9449) | Access and refresh tokens are bound to a **non-extractable** WebCrypto key. Script can use the key but never read it, so stolen tokens are useless elsewhere. The authorization code is bound too (`dpop_jkt`). Proofs are sent to the token endpoint, UserInfo, the SSF endpoints and your own APIs (`fetchResource()`). Server nonces are handled (a retry on `use_dpop_nonce`). With DPoP on, a `Bearer` token response is refused (`requireDpop`, default on), and a DPoP-bound grant is never refreshed into a Bearer one. `IndexedDBKeyStore` keeps the key across page loads. |
| **ID token validation** | Covers everything in OIDC Core §3.1.3.7: signature against the JWKS with the expected `alg` only, `iss`, `aud`, `azp`, `exp`, `iat` (no older than `maxIdTokenAgeSec`), `nonce`, `at_hash`, `max_age`/`auth_time`, and the refresh rules in §12.2. It also refuses other JWT types presented as ID tokens (`typ` `at+jwt`, `logout+jwt` and so on), unknown `crit` headers, and an `acr` outside the requested `acr_values` (`enforceAcr`). |
| **TLS** | Every OP endpoint, every SSF transmitter URL (including the JWKS and the stream's poll endpoint), the registration endpoint and `registration_client_uri`, the redirect URI and every post-logout redirect URI must use `https`. Loopback `http` is allowed for local development. |
| **Audience-restricted tokens** | RFC 8707 resource indicators (`resource`) on the authorization, token and refresh requests. |
| **Refresh tokens** | Rotation is handled. Concurrent refreshes are merged into one request, so rotation stays safe. With DPoP, refresh tokens are sender-constrained, as RFC 9700 §2.2.2 recommends for public clients. A refreshed ID token must keep the original `iss`, `sub`, `aud` and `azp` (OIDC Core §12.2). A deletion waits for a refresh in flight, so revoked tokens are never written back. |
| **Logout** | RP-Initiated Logout with its own single-use, expiring `state`, validated on return (`validateEndSessionCallback()`). `TokenManager.delete(key, { revoke: true })` and `AccountManager.signOut()` revoke the tokens (RFC 7009); `createEndSessionRequest()` alone does not. |
| **Token storage** | `TokenManager`: memory by default (`MemoryTokenStore`). `AccountManager`: IndexedDB by default only when DPoP is on, otherwise memory; a persistent store without DPoP logs a warning. The response cannot set the token set's prototype, `claims` or expiry. |
| **UserInfo** | The response `sub` must equal the ID token's: `expectedSub`, or by default the TokenSet's ID token `sub` (OIDC Core §5.3.2). A signed UserInfo response is verified with an asymmetric algorithm (`userinfoSignedResponseAlg` pins one). |

**Not included:**

- Confidential-client authentication: client secrets, `private_key_jwt`, mTLS. This library is a public client only.
- JAR/JARM (signed request objects and responses).
- Back- and front-channel logout, which need a server endpoint.
- CAEP push delivery, which a browser can't receive.

Your page also needs strict HTTP headers. The demo sets a CSP with no inline script, `Referrer-Policy: no-referrer` (the code arrives in the URL), and `frame-ancestors 'none'`.

## Signing in

```js
import { OIDCClient, TokenManager, IndexedDBKeyStore } from 'oidc-caep-client';

const client = await OIDCClient.discover({
  issuer: 'https://idp.example.com',          // or OIDCClient.fromMetadata(metadataJson, {...})
  clientId: 'my-spa',                         // a PUBLIC client
  redirectUri: `${location.origin}/callback`,
  postLogoutRedirectUri: `${location.origin}/`,
  dpop: { keyStore: new IndexedDBKeyStore() }, // optional but recommended
});
const tokens = new TokenManager(client);      // in-memory, auto-refreshing

// 1. Start: state, nonce and the PKCE verifier go to sessionStorage; PAR is used if offered.
const { url } = await client.createAuthorizationRequest();
location.assign(url);

// 2. On /callback: consumes the transaction for the returned state (once), then validates everything.
const tokenSet = await client.callback(location.href);
history.replaceState(null, '', '/');
await tokens.set('user', tokenSet);

// 3. Call APIs. The token is fresh, and carries a DPoP proof when bound.
const res = await client.fetchResource(await tokens.getTokenSet('user'), 'https://api.example.com/me');

// 4. Sign out.
const logout = await client.createEndSessionRequest({ idTokenHint: tokenSet.id_token });
await tokens.delete('user', { revoke: true });
location.assign(logout.url);
// … and on the post-logout page:
await client.validateEndSessionCallback(location.href);
```

### Dynamic Client Registration

```js
const { client } = await OIDCClient.register(metadata, {
  redirect_uris: [`${location.origin}/callback`],
  id_token_signed_response_alg: 'ES256',        // tells the IdP how to sign ID tokens
  // software_statement: '<signed JWT>',        // if the IdP only accepts trusted statements
}, { initialAccessToken, dpop: true });
```

The registration always requests `token_endpoint_auth_method: none`. It fails if the OP issues a client secret, or registers a different ID token `alg` than requested (`registration_mismatch`). `readClientRegistration()` and `deleteClientRegistration()` implement RFC 7592.

## Several accounts in one browser

Some OPs keep several people signed in in one browser and let each request say which one it is for. iya-sts does this with `authn.multipleAccounts`, which is on by default. `AccountManager` is the relying party's side of that, and it follows two rules:

- **One token cache for the whole browser.** Every signed-in account's tokens are cached until that account is signed out or its session ends. The cache is in IndexedDB by default (`IndexedDBTokenStore`) and shared by every tab of the origin. A trip to the OP, a reload or a new tab doesn't lose any account, and any tab can make any cached account active without a password.
- **One active account per tab.** Only the active account's tokens can be reached: `getTokenSet()` takes no account. Only its tokens are refreshed in the background. The other accounts are **dormant**: their tokens stay stored, but they aren't refreshed or used. Two tabs can have different active accounts; the active account is remembered per tab, in `sessionStorage`.

```js
import { AccountManager, needsInteraction } from 'oidc-caep-client';

const accounts = await new AccountManager(client, {
  // Runs before an account becomes active, with that account's tokens: catch up on its signals.
  onActivate: async (account, { getTokenSet }) => { /* e.g. receiver.start({ catchUp: true }) */ },
  onDeactivate: (account) => { /* stop polling its stream */ },
  onLeave: async (account, { getTokenSet }) => { /* signed out or ended: delete its stream */ },
}).init();                                              // reactivates this tab's account after a reload

location.assign((await accounts.signIn()).url);        // the OP decides (its picker if several are signed in)
location.assign((await accounts.chooseAccount()).url); // prompt=select_account: always the OP's picker
location.assign((await accounts.addAccount()).url);    // prompt=login: a fresh sign-in, added as an account

// On the redirect URI: the account is cached and becomes this tab's active account.
const { account, added } = await accounts.handleCallback(location.href);

await accounts.activate(otherKey);                     // the previous account goes dormant
const tokens = await accounts.getTokenSet();           // the ACTIVE account's, refreshed when due

const logout = await accounts.signOut(key);            // revokes; id_token_hint ends that sid only
```

- **Activating** a dormant account refreshes its tokens first if they are due, then runs `onActivate`, and only then makes the account active. If a signal handled during `onActivate` ends the account, it becomes active with status `ended` and its tokens are never handed out. If the refresh or the hook fails, the previously active account is reactivated.
- **Across tabs:**
  - A refresh holds a Web Lock (`navigator.locks`), so two tabs never present the same rotating refresh token. A tab that was waiting for the lock reuses the tokens the other tab just got.
  - Changes to the account list go through a lock too, and are announced to the other tabs (`BroadcastChannel`). A tab whose active account was signed out elsewhere sees its status change, and stops refreshing that account.
- **A request that names an account only accepts that account.** `resume(key)` asks without a screen (`prompt=none`); `reauthenticate(key)` uses `prompt=login`. Both send `login_hint` and the cached `id_token_hint`. If the OP signs in somebody else, the callback refuses with `account_mismatch` and revokes the tokens it got. `createAuthorizationRequest({ expectedSub })` gives the same check to any request.
- **`prompt=none` failures say which account they were for.** With several accounts signed in and nothing naming one, the OP answers `account_selection_required` (OpenID Connect Core §3.1.2.6). `needsInteraction(err)` covers it, along with `login_required`, `interaction_required` and `consent_required`. For `resume` and `reauth`, `err.account` is set.
- **Signing out one account leaves the others signed in.** Its logout request names its ID token, so the OP ends that session only. If it was this tab's active account, the most recently added signed-in account becomes active. `signOutAll()` sends one logout request that names nobody, so the OP asks which accounts to end.
- **Security events reach the account they are about.** `accountsForSubject(sub_id)` matches by `iss`/`sub`, a **verified** `email` or phone number (`email_verified` / `phone_number_verified` in the ID token), and `sid`. An SSF complex subject that names a session matches only the account holding that session; an account whose ID token has no `sid` doesn't match it. `end(key, reason)` drops the account's cached tokens; it stays listed as `ended`.
- **Statuses:** `signed-in`, `tokens-missing` (the cached tokens expired and can't be refreshed; `resume()` gets new ones while the OP session lasts), `signed-out` and `ended`. Past `maxAccounts` (default 10), the account that left longest ago is forgotten. If every account is signed in, a new sign-in is refused (`too_many_accounts`).
- **Streams are per person.** iya-sts gives a stream created with a person's token to that person, and sends it only events about them. So each account keeps its own stream. A tab polls only its active account's stream. A dormant account's stream keeps queueing at the transmitter, and `start({ catchUp: true })` in `onActivate` acts on what it queued before the account is used.

The cache is readable by script in the page, like any browser storage, so pair it with DPoP. A DPoP-bound token is useless without the non-extractable key. Cached tokens last until the account is signed out, its session ends, or its refresh is refused; closing the browser doesn't clear them.

## CAEP: one handler per event

```js
import { SSFReceiver, Subject } from 'oidc-caep-client';

const caep = new SSFReceiver({
  transmitterIssuer: 'https://idp.example.com',          // reads /.well-known/ssf-configuration
  // The signed-in user's token authorizes the stream, with a DPoP proof when bound:
  authorizationHeaders: async (req) => client.resourceHeaders(await tokens.getTokenSet('user'), req),
});

caep
  .onSessionRevoked(async (evt) => { /* sign the user out */ })
  .onTokenClaimsChange(async (evt) => { /* evt.payload.claims — refresh tokens */ })
  .onCredentialChange(async (evt) => { /* evt.payload.credential_type, change_type */ })
  .onAssuranceLevelChange(async (evt) => { /* evt.payload.current_level, change_direction */ })
  .onDeviceComplianceChange(async (evt) => { /* evt.payload.current_status */ })
  .onSessionEstablished(async (evt) => { /* evt.payload.acr, amr, fp_ua */ })
  .onSessionPresented(async (evt) => { /* evt.payload.fp_ua, ext_id */ })
  .onRiskLevelChange(async (evt) => { /* evt.payload.current_level, risk_reason */ })
  .onError((err, ctx) => console.warn(ctx.phase, err));

await caep.start();                                      // discover, create the stream, start polling
// caep.start({ catchUp: true }) first acts on the SETs already queued (e.g. while the account was dormant)
await caep.addSubject(Subject.issSub(user.iss, user.sub)); // events about this user only
```

Delivery is **poll** (RFC 8936). If you prefer a static bearer token, pass `accessToken: () => token` instead of `authorizationHeaders`.

| CAEP event | Method | `handlers` key | Notable `payload` fields |
|---|---|---|---|
| session-revoked | `onSessionRevoked` | `sessionRevoked` | — |
| token-claims-change | `onTokenClaimsChange` | `tokenClaimsChange` | `claims` |
| credential-change | `onCredentialChange` | `credentialChange` | `credential_type`, `change_type`, `friendly_name` |
| assurance-level-change | `onAssuranceLevelChange` | `assuranceLevelChange` | `namespace`, `current_level`, `previous_level`, `change_direction` |
| device-compliance-change | `onDeviceComplianceChange` | `deviceComplianceChange` | `previous_status`, `current_status` |
| session-established | `onSessionEstablished` | `sessionEstablished` | `fp_ua`, `acr`, `amr`, `ext_id` |
| session-presented | `onSessionPresented` | `sessionPresented` | `fp_ua`, `ext_id` |
| risk-level-change | `onRiskLevelChange` | `riskLevelChange` | `principal`, `current_level`, `previous_level`, `risk_reason` |
| SSF verification | `onVerification` | `verification` | `state` |
| SSF stream-updated | `onStreamUpdated` | `streamUpdated` | `status`, `reason` |

**Your own logic for every event.** `onEventReceived` in the receiver's options is called once for each accepted event, before the typed handlers below, and is awaited. By default it is `logEventReceived`, which prints `[oidc-caep-client] CAEP event received: <name> (jti …)` to the console. It leaves the payload and subject out, because they can carry personal data. Replace it with your own function, call `logEventReceived` from yours to keep the line, or pass `null` to turn it off. If it throws, `onError` gets the error with `phase: 'hook'`, and the typed handlers still run.

```js
import { logEventReceived, SSFReceiver } from 'oidc-caep-client';

const caep = new SSFReceiver({
  transmitterIssuer: 'https://idp.example.com',
  onEventReceived: async (evt) => {
    logEventReceived(evt);
    await audit.record(evt.name, evt.subject, evt.payload); // your logic
  },
});
```

The receiver also has these generic hooks:

- `onEvent(uri, fn)` handles any event type, for example the RISC events in `RISC.*`.
- `onAnyEvent(fn)` runs for every event.
- `onUnhandledEvent(fn)` runs for events that have no specific handler.
- `onError(fn)` runs on errors.

Every handler receives `{ type, name, payload, subject, eventTimestamp, initiatingEntity, reasonAdmin, reasonUser, jti, iss, aud, iat, txn, set, raw }`. Use `subjectMatches(evt.subject, { iss, sub, sid, email, email_verified })` to tell whether an event is about your user. An email or phone number counts only when verified, and a session-scoped subject matches only the identity holding that `sid`.

**SET validation.** Every SET must meet all of the following, or it is rejected:

- It is a compact JWS with `typ` `secevent+jwt`, signed with an asymmetric algorithm.
- Its signature verifies against the transmitter's JWKS.
- `iss` matches the transmitter.
- `aud` matches the stream's `aud` (or the `audience` option). If neither exists, the check fails closed.
- `jti`, `iat` and `events` are present, and `events` holds exactly one event (SSF 1.0).
- `iat` is not in the future. There is no age limit by default: a polled SET waits at the transmitter until it is read, so catching up after a stop must not throw old signals away. Set `maxSetAgeSec` to impose one.
- A verification or stream-updated event names this stream (an opaque `sub_id`), if it names anything.

In addition, a replayed `jti` is dropped.

**Acknowledgement (RFC 8936).** An acknowledged SET, and one reported back as an error, is never sent again, so the receiver is careful with both:

- A SET is acknowledged only after its handlers ran without throwing. If one throws, the SET is left for the transmitter to send again, up to `maxDeliveryAttempts` times (default 5). After that it is acknowledged and `onError` gets `handler_failed`. Make handlers idempotent: a reload can also bring a handled SET back before its acknowledgement was sent.
- Only a definitely invalid SET is reported as an error (bad signature, issuer, audience, `typ`, claims). One that couldn't be checked for a reason that may pass is left for redelivery: a network error fetching the JWKS, or a key the cached JWKS doesn't hold yet.
- `stop()` sends the acknowledgements still owed.
- The poll endpoint must use TLS and share an origin with the transmitter (`trustedPollOrigins` adds others), because every poll carries the person's access token.
- Errors go to `onError`; without one, they are written to `console.error`, so a lost signal always leaves a trace.

## API summary

**`OIDCClient`**:

- `discover(config)`, `fromMetadata(metadata, config)`, `register(metadata, clientMetadata, config)`
- `createAuthorizationRequest(opts)` (also `idTokenHint`, `expectedSub`, `context`), `callback(url)`, `completeAuthorization(url)` → `{ tokenSet, context }`
- `refresh(tokenSet)`
- `resourceHeaders(token, { method, url })`, `fetchResource(token, url, init)`
- `userinfo(token, { expectedSub })`, `revoke(token, hint)`
- `createEndSessionRequest(opts)` (also `context`), `validateEndSessionCallback(url)`, `completeEndSession(url)` → `{ context }`
- `validateIdToken(jwt, opts)`
- `securityFeatures`: a summary of the protections in effect

These are the `OIDCClient` config options:

| Option | Default |
|---|---|
| `issuer` or `metadata` | one is required |
| `clientId` | required |
| `redirectUri`, `postLogoutRedirectUri` | — |
| `scope` | `openid profile email` + `offline_access` if supported |
| `resource` | — |
| `idTokenSignedResponseAlg` | `RS256` |
| `par` | `'auto'` |
| `dpop` | `false`; `true` or `{ keyStore, alg }` |
| `transactionStore` | sessionStorage |
| `transactionTtlSec` | 600 |
| `maxIdTokenAgeSec` | 600 |
| `enforceAcr` | `true` |
| `requireAuthTime` | `false` |
| `allowInsecureRequests` | `false` |
| `clockToleranceSec` | 30 |
| `httpTimeoutMs` | 10000 |
| `fetch` | global `fetch` |

**`TokenManager(client, { store, refreshSkewSec, autoRefresh })`** (refreshes hold a lock shared by the tabs):

- `set(key, ts, { schedule })`, `get`, `getTokenSet`, `getAccessToken`, `refresh`, `schedule(key)`, `unschedule(key)`, `delete(key, { revoke })`, `close`
- Events: `refreshed`, `refresh_error`, `expired`, `removed`

**`AccountManager(client, { store, tabStore, refreshSkewSec, maxAccounts, rememberSignedOutDays, loginHint, onActivate, onDeactivate, onLeave, broadcast })`**:

- `init`, `list`, `get`, `active`, `activeKey`, `identity(key)`, `accountsForSubject(subId)`
- `signIn`, `chooseAccount`, `addAccount`, `resume(key)`, `reauthenticate(key)`, `handleCallback(url)`
- `activate(key)`, `getTokenSet()` and `refresh()` (the active account's only), `signOut(key?, { revoke, endSession })`, `signOutAll`, `end(key, reason)`, `forget(key)`, `close`
- Events: `added`, `updated`, `activated`, `refreshed`, `signed-out`, `ended`, `forgotten`, `activation_error`, `change`
- Also exported: `needsInteraction(err)`, `INTERACTION_REQUIRED`, `accountKey(iss, sub)`

**Stores:** `MemoryTokenStore` (default), `WebStorageTokenStore`, `IndexedDBTokenStore` (shared by the tabs), `TransactionStore`, `IndexedDBKeyStore` (non-extractable DPoP key), `WebStorageKeyStore` (extractable DPoP key in sessionStorage) and `MemoryKeyStore`.

## Tests

```sh
npm test   # from the repo root: node:test against a strict in-memory OP stub injected via `fetch`
```

## License

MIT © 2026 Iya CyberSecurity Solutions, LLC. See [LICENSE](LICENSE).
