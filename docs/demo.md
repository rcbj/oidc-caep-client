---
title: Running the demo
---

# Running the demo

The demo is a single-page app built on `oidc-caep-client`. The OIDC client runs in the browser; a small static server in one container serves the page, the library and the security headers. It holds no tokens.

## Start it

```sh
docker compose up --build
```

Open <http://localhost:3000>. The page reads [`demo/public/oidc.json`](https://github.com/rcbj/oidc-caep-client/blob/main/demo/public/oidc.json): the provider's metadata URL, a public `client_id` and the scopes. The browser fetches the metadata itself, so the provider must allow CORS from the demo's origin, and the browser must trust the provider's certificate.

| Variable | Default | Purpose |
|---|---|---|
| `PUBLIC_URL` | `http://localhost:3000` | The URL browsers use. The redirect URI is `${PUBLIC_URL}/callback`. With Compose, change it together with `HOST_PORT`. |

## Register the client on iya-sts

The default `oidc.json` points at iya-sts on `https://localhost:8081`, client `oidc-caep-demo`. Register it in the default realm:

```sh
ADMIN_API_CLIENT_SECRET=… npm run register-iya-sts
```

[`scripts/register-iya-sts-client.mjs`](https://github.com/rcbj/oidc-caep-client/blob/main/scripts/register-iya-sts-client.mjs) gets a management API token as `sts-management-api` and:

- creates the public client (`token_endpoint_auth_method: none`) with the demo's redirect URIs, the file's scopes and the demo's origin for CORS;
- adds the client to `SSF_READ` and `SSF_MANAGE`, for whichever of `ssf.read` and `ssf.manage` the file asks for (iya-sts issues each only when the application is a member of the role and the person is in its group, `ssf-read` or `ssf-manage`);
- creates a test user, `caep-demo-user`, in those groups. Its password is `CAEP_DEMO_USER_PASSWORD`, or one is generated and printed once.

| Option | Use |
|---|---|
| `--public-url url` | The demo isn't on `http://localhost:3000`. |
| `--config path` | Another OIDC file. |
| `--test-user name`, `--no-test-user` | Name the test user, or skip it. |

The secret is `ADMIN_API_CLIENT_SECRET` or `STS_ADMIN_API_CLIENT_SECRET`. Every step can be repeated safely.

## What it does

- **DPoP** binds tokens to a key kept in the tab's session storage.
- **PAR** is used whenever the provider offers it.
- **Tokens** for every signed-in account are cached in the tab's session storage; closing the tab clears them.
- **CAEP:** the stream is created with the person's access token (with a DPoP proof) and polled from the browser. With `ssf.manage`, the person is added as the stream's subject, and the stream asks for the event types picked on the CAEP tab.

The page has two tabs:

- **Identity:** sign-in, the protections in effect, the session, the token cache, and the tokens.
- **CAEP events:** the stream, the event-type picker, and the active account's event log.

It reacts to events about the signed-in person: `session-revoked` signs them out, `token-claims-change` refreshes their tokens, an assurance drop asks for step-up.

## Several accounts

iya-sts can keep several people signed in to one browser (`authn.multipleAccounts`). Each tab has **one active account**: only its tokens are used and refreshed, and only its stream is polled. The others are dormant.

- **Switching** (the menu under your name) needs no password. The account's stream first catches up on the events queued while it was dormant.
- **A signed-out or ended account** in the menu starts a sign-in that names it (`login_hint`) and refuses anybody else.
- **Sign in with another account** is a fresh sign-in (`prompt=login`).
- **The event log** shows the active account's events only, and is cleared for an account when it signs out.
- **An event that ends a session** ends that account only. A `session-revoked` naming another of the person's sessions is ignored.
- **Sign out** ends that account's session at the provider and keeps the others.
- **Each tab has its own cache.** A new tab starts signed out.

## The server

[`demo/server.js`](https://github.com/rcbj/oidc-caep-client/blob/main/demo/server.js) serves the page (also at `/callback`), `/oidc.json`, the library and `jose` as ES modules, with no bundler. Its headers:

- **CSP:** scripts only from this origin, plus the inline import map by its hash; no `eval`; no framing.
- **`Referrer-Policy: no-referrer`:** the authorization code arrives in the URL.
- **`X-Frame-Options: DENY`**, `nosniff`, and a cross-origin opener policy.
- **`Cache-Control: no-store`** on the page.
