# OIDC + CAEP client library and demo

The demo is a CAEP **receiver**: it subscribes to your IdP's SSF transmitter and reacts to the events it delivers. It never sends CAEP events.

| Path | What it is |
|---|---|
| [`packages/oidc-caep-client`](packages/oidc-caep-client) | **The library.** It is an OpenID Connect Core 1.0 Relying Party configured from the provider's metadata document, with a token cache that refreshes automatically and a Shared Signals / CAEP receiver that has one handler per CAEP event. See its [README](packages/oidc-caep-client/README.md). |
| [`demo`](demo) | A small SPA served by a Node.js BFF that runs in one container. You configure it on its main screen against your own OIDC provider and SSF/CAEP transmitter. |

## Run the demo

```sh
docker compose up --build
```

Then open **http://localhost:3000**. The **Identity provider** card on the main screen asks for the following:

1. **Metadata document.** Type the issuer (or its `/.well-known/openid-configuration` URL) and click **Fetch**, or paste the JSON document directly. The server validates it against OpenID Connect Discovery 1.0: required fields, `response_type=code`, and the ID token signing algorithms. Fetch also checks whether the issuer publishes `/.well-known/ssf-configuration`.
2. **Client:** choose one of the following.
   - **Use an existing client:** enter a `client_id` and an optional `client_secret`. With a secret, the client authenticates with `client_secret_basic` or `client_secret_post`. Without one, it runs as a public client using PKCE.
   - **Register a new client:** available when the metadata has a `registration_endpoint`. The app registers itself using OpenID Connect Dynamic Client Registration, sending the redirect URIs, grant types, scopes and the chosen **ID token signing alg** as `id_token_signed_response_alg`. The registration is rejected if the IdP assigns a different algorithm. Provide an initial access token or a software statement if your IdP requires one. When you replace a dynamically registered client, the old one is deleted at the IdP (RFC 7592) where supported.

   The **ID token signing alg** list shows only algorithms the IdP advertises that the library can verify. For an existing client it must match the client's registration. Auth method and scopes are under **Advanced OIDC settings**.
3. **CAEP settings**:

   | Setting | Default / notes |
   |---|---|
   | SSF transmitter issuer | The OIDC issuer |
   | Delivery method | **Poll** when the app runs on localhost, because a transmitter can't push to your machine |
   | Events to request | The five core CAEP events |
   | Management API credential | **Signed-in user's access token** (default): the stream is created when a user signs in, with that user's access token, which the token cache keeps fresh for polling. Include the transmitter's scopes (e.g. `ssf:read ssf:write`) in the OIDC scope; Fetch pre-fills them. Alternatively, a **client credentials** token (needs a confidential client) or a pasted **static bearer token** |

4. Register the URLs shown in the **Register these with your IdP** box with your provider: the `redirect_uri`, the `post_logout_redirect_uri`, and, for push delivery, the CAEP push endpoint.

Click **Save & connect**. The app configures itself from the document and creates an SSF stream at the transmitter. It then requests a verification event and shows the stream status in the **CAEP stream** card.

**Which users' events arrive.** By default the app adds each signed-in user to the stream's subject list, so the transmitter sends events only about them. This matters with `default_subjects: ALL`: there, an **empty** subject list means every user in the realm. For the same reason, the last subject is never removed on such a transmitter, since emptying the list would widen the stream back to everyone. Untick *Only receive events about signed-in users* to leave the list empty and receive everything.

**SET checks.** Beyond signature, `iss`, `typ`, replay and structure, a SET must be addressed to the stream's `aud`, and fails closed if there is none. Its `iat` must be no older than **Max event age** (default 3600 s, `0` disables) and not in the future.

The SSF transmitter issuer is filled in from the OIDC issuer and follows it, unless you type a different one.

With the user-token credential, the stream lives while someone is signed in. Polling pauses when the last user's session ends; signing out deletes the stream while the token is still valid, and the next sign-in creates a new one (deleting any paused one first).

A **Tokens** card shows the signed-in user's access, refresh and ID tokens, raw and decoded, both as returned at sign-in and as currently cached after refreshes. This is a debugging aid: a production BFF would never send tokens to the browser.

Once you sign in, the app registers you as a stream subject (as `iss_sub` or `email`). CAEP events your IdP sends about you appear in the **Event log**, along with what the app did:

| Event | What the demo does |
|---|---|
| `session-revoked` | Ends the local session, drops cached tokens, and shows the IdP's reason |
| `token-claims-change` | Refreshes tokens immediately to pick up the new claims |
| `credential-change` | Notifies the user. The session is ended if the credential was revoked or deleted |
| `assurance-level-change` | Requires step-up when assurance decreases |
| `device-compliance-change` | Ends the session when the device becomes `not-compliant` |
| `risk-level-change` | MEDIUM requires step-up. HIGH ends the session |
| `session-established` / `session-presented` | Logs the event (informational) |

The form remembers what you type in this browser's localStorage and restores it after a restart, so you only re-enter the secrets. The `client_secret`, the management API bearer token and the DCR initial access token are never stored.

Saving a new configuration ends every current session and deletes the old stream. Configuration is held in memory only, so after a restart you configure it again, or pre-configure it with the environment variables below.

> The configuration endpoint has no authentication. Anyone who can reach the app can repoint it at another IdP. Run it on localhost or behind your own access control.

### How it fits together

```
 Browser (SPA)                Node.js process (container)                     Your IdP / SSF transmitter
 ─────────────                ───────────────────────────                     ──────────────────────────
  config form ───────────▶  OIDCClient.fromMetadata(doc, {client_id, secret})
  /login  ───────────────▶  authorizationUrl (PKCE, state, nonce) ──302────▶  authorization_endpoint
  /callback ◀── code ──────  callback: code exchange + ID token validation ──▶  token_endpoint, jwks_uri
  /api/events (SSE) ◀─────  TokenManager auto-refresh ─── refresh_token ─────▶  token_endpoint
                            SSFReceiver: create stream, add subject ─────────▶  configuration_endpoint …
                            poll (RFC 8936) or push (RFC 8935) ◀── SETs ──────  transmitter
                            CAEP handlers → end session / refresh / step-up
```

Tokens stay in the Node process (the BFF pattern). The browser only sees session state and CAEP activity, pushed over Server-Sent Events.

### Environment variables

All of these are optional.

| Variable | Default | Purpose |
|---|---|---|
| `PUBLIC_URL` | `http://localhost:3000` | The URL browsers use. It is the basis for `redirect_uri` and the push endpoint. With Compose, change it together with `HOST_PORT` |
| `OIDC_ISSUER` + `OIDC_CLIENT_ID` | — | Pre-configure at startup through discovery. You can still edit the configuration in the UI |
| `OIDC_CLIENT_SECRET`, `OIDC_SCOPE`, `OIDC_TOKEN_ENDPOINT_AUTH_METHOD` | — | Client settings |
| `SSF_TRANSMITTER_ISSUER`, `SSF_DELIVERY`, `SSF_SCOPE`, `SSF_ACCESS_TOKEN`, `SSF_SUBJECT_FORMAT`, `SSF_EVENTS` | — | CAEP settings. `SSF_EVENTS` is a comma-separated list of short event names |
| `SSF_DISABLED` | — | Set to `true` to run OIDC only |
| `TOKEN_REFRESH_SKEW_SEC` | `60` | How long before expiry tokens are refreshed (capped at half the token lifetime) |

## Tests

```sh
npm install
npm test
```

There are 36 tests. They run the library against an in-memory provider stub injected through its `fetch` option. They cover:

- **Configuration:** discovery, supplied metadata, invalid documents, and unsupported algorithms.
- **Dynamic Client Registration:** the requested algorithm is sent and honoured, a substituted algorithm is rejected, software statements and initial access tokens are passed through, and unsupported or unadvertised algorithms are refused before anything is sent.
- **Code flow:** state, nonce, `iss` mix-up, PKCE, forged ID tokens, and error responses.
- **Token refresh:** on-demand, background, coalesced/rotation-safe, and revoked grants.
- **SSF:** stream lifecycle, all eight CAEP handlers, push authorization, bad signature, wrong or missing audience, wrong `typ`, too-old or future `iat`, replay, poll delivery with verification, and stream status.

## License

MIT © 2026 Iya CyberSecurity Solutions, LLC. See [LICENSE](LICENSE).
