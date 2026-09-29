# oidc-caep-client

An OpenID Connect client library for **browser apps**, configured from the provider's metadata document. It runs as a **public client**: no client secret, and `token_endpoint_auth_method: none`. It covers:

- signing users in;
- caching tokens and refreshing them before they expire;
- subscribing to **CAEP** events through the OpenID Shared Signals Framework, with **one handler per CAEP event**.

It uses Web APIs only (`fetch`, WebCrypto, `URL`, Web Storage, IndexedDB), so it runs in browsers and in Node.js 20 or later. Its only dependency is [`jose`](https://github.com/panva/jose).

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
| **DPoP** (RFC 9449) | Access and refresh tokens are bound to a **non-extractable** WebCrypto key. Script can use the key but never read it, so stolen tokens are useless elsewhere. The authorization code is bound too (`dpop_jkt`). Proofs are sent to the token endpoint, UserInfo, the SSF endpoints and your own APIs (`fetchResource()`). Server nonces are handled (a retry on `use_dpop_nonce`). `IndexedDBKeyStore` keeps the key across page loads. |
| **ID token validation** | Covers everything in OIDC Core §3.1.3.7: signature against the JWKS with the expected `alg` only, `iss`, `aud`, `azp`, `exp`, `iat` (no older than `maxIdTokenAgeSec`), `nonce`, `at_hash`, `max_age`/`auth_time`, and the refresh rules in §12.2. It also refuses other JWT types presented as ID tokens (`typ` `at+jwt`, `logout+jwt` and so on), unknown `crit` headers, and an `acr` outside the requested `acr_values` (`enforceAcr`). |
| **TLS** | Every OP endpoint, the redirect URI and the post-logout redirect URI must use `https`. Loopback `http` is allowed for local development. |
| **Audience-restricted tokens** | RFC 8707 resource indicators (`resource`) on the authorization, token and refresh requests. |
| **Refresh tokens** | Rotation is handled. Concurrent refreshes are merged into one request, so rotation stays safe. With DPoP, refresh tokens are sender-constrained, as RFC 9700 §2.2.2 recommends for public clients. |
| **Logout** | RP-Initiated Logout with its own single-use, expiring `state`, validated on return (`validateEndSessionCallback()`). Tokens are revoked (RFC 7009). |
| **Token storage** | Memory by default (`MemoryTokenStore`). `WebStorageTokenStore` (sessionStorage) is opt-in; pair it with DPoP. |
| **UserInfo** | The response `sub` must equal the ID token's (`expectedSub`). A signed UserInfo response is verified. |

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

The receiver also has these generic hooks:

- `onEvent(uri, fn)` handles any event type, for example the RISC events in `RISC.*`.
- `onAnyEvent(fn)` runs for every event.
- `onUnhandledEvent(fn)` runs for events that have no specific handler.
- `onError(fn)` runs on errors.

Every handler receives `{ type, name, payload, subject, eventTimestamp, initiatingEntity, reasonAdmin, reasonUser, jti, iss, aud, iat, txn, set, raw }`. Use `subjectMatches(evt.subject, { iss, sub, email, sid })` to tell whether an event is about your user.

**SET validation.** Every SET must meet all of the following, or it is rejected:

- It is a compact JWS with `typ` `secevent+jwt`, signed with an asymmetric algorithm.
- Its signature verifies against the transmitter's JWKS.
- `iss` matches the transmitter.
- `aud` matches the stream's `aud` (or the `audience` option). If neither exists, the check fails closed.
- `jti`, `iat` and `events` are present.
- `iat` is no older than `maxSetAgeSec` (default 3600) and not in the future.

In addition, a replayed `jti` is dropped.

## API summary

**`OIDCClient`**:

- `discover(config)`, `fromMetadata(metadata, config)`, `register(metadata, clientMetadata, config)`
- `createAuthorizationRequest(opts)`, `callback(url)`
- `refresh(tokenSet)`
- `resourceHeaders(token, { method, url })`, `fetchResource(token, url, init)`
- `userinfo(token, { expectedSub })`, `revoke(token, hint)`
- `createEndSessionRequest(opts)`, `validateEndSessionCallback(url)`
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

**`TokenManager(client, { store, refreshSkewSec, autoRefresh })`**:

- `set`, `get`, `getTokenSet`, `getAccessToken`, `refresh`, `delete(key, { revoke })`, `close`
- Events: `refreshed`, `refresh_error`, `expired`, `removed`

**Stores:** `MemoryTokenStore` (default), `WebStorageTokenStore`, `TransactionStore`, `IndexedDBKeyStore` and `MemoryKeyStore` (for the DPoP key).

## Tests

```sh
npm test   # from the repo root: node:test against a strict in-memory OP stub injected via `fetch`
```

## License

MIT © 2026 Iya CyberSecurity Solutions, LLC. See [LICENSE](LICENSE).
