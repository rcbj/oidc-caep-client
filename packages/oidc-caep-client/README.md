# oidc-caep-client

An OpenID Connect Relying Party library for Node.js (≥ 20) that includes:

- **Metadata-driven configuration**, either discovered from `<issuer>/.well-known/openid-configuration` or taken from a metadata document you supply (`OIDCClient.fromMetadata`).
- **Authorization Code flow with PKCE (S256)**, `state`, `nonce`, and RFC 9207 `iss` checking.
- **Full ID Token validation** per OIDC Core §3.1.3.7: signature via JWKS with key rotation, `iss`, `aud`, `azp`, `exp`, `iat`, `nonce`, `max_age`/`auth_time`, and `at_hash`. Refreshed ID tokens are also checked per §12.2.
- **Token cache with automatic renewal**. Tokens are refreshed shortly before they expire, both in the background and on demand. Concurrent refreshes are coalesced, which keeps refresh-token rotation safe, and the store is pluggable.
- **Client authentication** with `client_secret_basic`, `client_secret_post`, `private_key_jwt`, or `none`.
- **UserInfo**, **token revocation** (RFC 7009), and **RP-Initiated Logout**.
- **A CAEP receiver** built on the OpenID Shared Signals Framework 1.0. It covers stream management, push (RFC 8935) and poll (RFC 8936) delivery, and SET validation (RFC 8417). There is **one handler per CAEP event**.

Its only runtime dependency is [`jose`](https://github.com/panva/jose).

## Quick start

```js
import { OIDCClient, TokenManager, SSFReceiver, Subject, subjectMatches } from 'oidc-caep-client';

// 1. Configure from the discovery document
const client = await OIDCClient.discover({
  issuer: 'https://idp.example.com',
  clientId: 'my-app',
  clientSecret: process.env.CLIENT_SECRET,
  redirectUri: 'https://app.example.com/callback',
});

// …or from a metadata document you already have (validated the same way, no discovery request)
const client2 = await OIDCClient.fromMetadata(metadataJson, { clientId: 'my-app', redirectUri: '…' });

// 2. Sign in
app.get('/login', (req, res) => {
  const { url, transaction } = client.authorizationUrl();
  req.session.oidc = transaction;           // persist server-side
  res.redirect(url);
});

const tokens = new TokenManager(client, { refreshSkewSec: 60 });

app.get('/callback', async (req, res) => {
  const tokenSet = await client.callback(req.query, req.session.oidc);
  await tokens.set(req.session.id, tokenSet); // cached and auto-refreshed from here on
  req.session.user = tokenSet.claims;
  res.redirect('/');
});

// 3. Use a token that is always fresh
const accessToken = await tokens.getAccessToken(req.session.id);
```

## Dynamic Client Registration

To register a client and fix its ID token signing algorithm at the IdP:

```js
const metadata = await discoverOpenIdProvider('https://idp.example.com');
const { client, registration } = await OIDCClient.register(metadata, {
  redirect_uris: ['https://app.example.com/callback'],
  grant_types: ['authorization_code', 'refresh_token'],
  token_endpoint_auth_method: 'client_secret_basic',
  id_token_signed_response_alg: 'ES256',     // tells the IdP how to sign ID tokens for this client
  // software_statement: '<signed JWT>',     // if the IdP only accepts trusted software statements
}, { initialAccessToken });                  // if the IdP requires one
```

This implements OpenID Connect Dynamic Client Registration 1.0 and RFC 7591. The returned client is configured with the registered `client_id`, `client_secret`, auth method and ID token algorithm.

The request is refused before it is sent if the algorithm is not one this library can verify, or if the OP doesn't advertise it. The registration fails with `registration_mismatch` if the OP registers a different `id_token_signed_response_alg` or `token_endpoint_auth_method` than you asked for.

`readClientRegistration(registration)` and `deleteClientRegistration(registration)` implement RFC 7592.

## CAEP: one handler per event

```js
const caep = new SSFReceiver({
  transmitterIssuer: 'https://idp.example.com',          // reads /.well-known/ssf-configuration
  pushEndpointUrl: 'https://app.example.com/caep/events',
  accessToken: () => tokens.getClientCredentialsToken({ scope: 'ssf.manage' }),
});

caep
  .onSessionRevoked(async (evt) => { /* end local sessions for evt.subject */ })
  .onTokenClaimsChange(async (evt) => { /* evt.payload.claims — refresh tokens */ })
  .onCredentialChange(async (evt) => { /* evt.payload.credential_type, change_type */ })
  .onAssuranceLevelChange(async (evt) => { /* evt.payload.current_level, change_direction */ })
  .onDeviceComplianceChange(async (evt) => { /* evt.payload.current_status */ })
  .onSessionEstablished(async (evt) => { /* evt.payload.acr, amr, fp_ua */ })
  .onSessionPresented(async (evt) => { /* evt.payload.fp_ua, ext_id */ })
  .onRiskLevelChange(async (evt) => { /* evt.payload.current_level, risk_reason */ })
  .onError((err, ctx) => console.warn(ctx.phase, err));

app.post('/caep/events', caep.pushHandler());   // Express/Connect/node:http compatible
await caep.start();                              // discover + create stream (+ start polling)

// Ask the transmitter to send events about a user:
await caep.addSubject(Subject.issSub(user.iss, user.sub));
```

You can also pass handlers to the constructor:
`new SSFReceiver({ ..., handlers: { sessionRevoked, credentialChange, error } })`.

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

Every handler receives a `SecurityEvent`:

```ts
{
  type, name,               // full URI and short name ("session-revoked")
  payload,                  // the event object from the SET
  subject,                  // RFC 9493 sub_id (e.g. { format: 'iss_sub', iss, sub })
  eventTimestamp, initiatingEntity, reasonAdmin, reasonUser,
  jti, iss, aud, iat, txn,
  set,                      // all validated SET claims
  raw,                      // the SET as received
}
```

Use `subjectMatches(evt.subject, { iss, sub, email, sid })` to find the local sessions an event applies to. It understands the `iss_sub`, `email`, `opaque`, `phone_number`, `account`, `aliases`, and `complex` formats.

### How SETs are validated

Every SET must meet all of the following, or it is rejected:

- It is a compact JWS with the `typ` header `secevent+jwt`.
- Its signature verifies against the transmitter's `jwks_uri`, using asymmetric algorithms only.
- `iss` matches the transmitter, and `aud` matches the stream's `aud` (or the `audience` option).
- The `jti`, `iat`, and `events` claims are all present.

- The expected audience is the `audience` option or the stream's `aud`. If neither exists, every SET is rejected rather than the check being skipped.
- `iat` is no older than `maxSetAgeSec` (default 3600; `0` disables) and not in the future beyond `clockToleranceSec`.

In addition, a replayed `jti` is acknowledged but not dispatched again.

Push requests must carry the `Authorization` header that the receiver generated when it created the stream. Rejections use the RFC 8935 error codes: `invalid_request`, `invalid_key`, `invalid_issuer`, `invalid_audience`, and `authentication_failed`.

### Stream management

`start()` creates a stream. If you pass `streamId`, it reuses that stream instead. If the transmitter answers HTTP 409, `start()` adopts the existing stream and repoints it at this receiver.

The management API is exposed as:

- `listStreams()`, `getStream()`, `updateStream()`, `replaceStream()`, `deleteStream()`
- `getStatus()`, `updateStatus()`
- `addSubject()`, `removeSubject()`
- `requestVerification()`, which resolves when the verification SET arrives

### Helpers

- `discoverOpenIdProvider(issuer)` fetches and validates OP metadata.
- `validateOpenIdProviderMetadata(doc, expectedIssuer?)` validates a document you already have.
- `discoverSSFTransmitter(issuer)` fetches SSF transmitter metadata.

## API summary

### `OIDCClient`

| Method | Description |
|---|---|
| `OIDCClient.discover(config)` | Create and initialise the client from discovery metadata |
| `OIDCClient.fromMetadata(metadata, config)` | Create the client from a supplied metadata document |
| `OIDCClient.register(metadata, clientMetadata, config)` | Register the client dynamically, then create it (returns `{ client, registration }`) |
| `authorizationUrl({ scope, prompt, maxAge, loginHint, acrValues, extraParams })` | Returns `{ url, transaction }` |
| `callback(params, transaction)` | Validates the response, redeems the code, validates the ID token, and returns a `TokenSet` |
| `refresh(tokenSet)` | Refresh Token grant |
| `clientCredentials({ scope, resource, audience })` | Client Credentials grant |
| `userinfo(accessToken, { expectedSub })` | UserInfo request (JSON or signed JWT response) |
| `revoke(token, hint)` | RFC 7009 revocation |
| `endSessionUrl({ idTokenHint, postLogoutRedirectUri, state })` | RP-Initiated Logout URL |
| `validateIdToken(jwt, opts)` | Standalone ID token validation |

These are the `OIDCClient` config options:

| Option | Default |
|---|---|
| `clientId` | required |
| `issuer` or `metadata` | one is required |
| `clientSecret` | — |
| `privateJwk` | — |
| `redirectUri` | — |
| `postLogoutRedirectUri` | — |
| `scope` | `openid profile email`, plus `offline_access` if the OP supports it |
| `tokenEndpointAuthMethod` | chosen from the credentials you supply |
| `idTokenSignedResponseAlg` | `RS256` |
| `clockToleranceSec` | 30 |
| `httpTimeoutMs` | 10000 |
| `discoveryCacheTtlMs` | 1h |
| `fetch` | global `fetch` |

### `TokenManager`

| Method / event | Description |
|---|---|
| `set(key, tokenSet)` | Cache tokens and schedule background refresh |
| `get(key)` | Return the cached `TokenSet` |
| `getAccessToken(key, { forceRefresh })` | Return a valid access token, refreshing if it is within `refreshSkewSec` of expiry |
| `refresh(key)` | Refresh now (concurrent calls share one request) |
| `delete(key, { revoke })` | Remove tokens, optionally revoking them at the OP |
| `getClientCredentialsToken(params)` | Return a cached client-credentials access token |
| events | `refreshed`, `refresh_error`, `expired`, `removed` |

These are the `TokenManager` options:

| Option | Default |
|---|---|
| `store` | `MemoryTokenStore` (implement `get`/`set`/`delete` for Redis etc.) |
| `refreshSkewSec` | 60 (capped at half the token lifetime) |
| `autoRefresh` | true |
| `retryDelayMs` | 5000 |

Refreshes are coalesced per process. If several instances share a store, serialize refreshes per key yourself, for example with a distributed lock, to avoid races over refresh-token rotation.

## Tests

```sh
npm test   # from the repo root; uses an in-memory provider stub injected via the `fetch` option
```

## License

MIT © 2026 Iya CyberSecurity Solutions, LLC. See [LICENSE](LICENSE).
