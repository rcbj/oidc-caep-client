# oidc-caep-client

A public OpenID Connect client for a browser application, and a CAEP receiver. Authorization Code with PKCE (S256), PAR when the provider offers it, and DPoP. Tokens stay in the page. The source is JavaScript with JSDoc, and the only runtime dependency is `jose`. It imports no Node.js built-in.

The server-side confidential client is [oidc-caep-risc-nodejs](https://github.com/rcbj/oidc-caep-risc-nodejs). The native macOS counterpart is [swift-oidc-caep-native-app](https://github.com/rcbj/swift-oidc-caep-native-app) (product `OIDCCAEPClient`).

Documentation: <https://rcbj.github.io/oidc-caep-client/>. The license is the MIT License in `LICENSE`. The Business Source License used by iya-sts does not apply here.

Node.js 24.22.1 or later. That is the engines field, `.nvmrc`, and the only version in the test matrix. It is the release that fixes HTTP2Shell (CVE-2026-111497).

## Layout

| Path | What it is |
|---|---|
| `packages/oidc-caep-client` | The library published to npm as `oidc-caep-client`, version line 0.2. Source is `src/*.js` (`oidc-client.js`, `dpop.js`, `pkce.js`, `token-manager.js`, `accounts.js`, `caep/`). Tests are `test/`. The package is published from the source. `npm run build:types` writes declarations under `types/`, which is not committed. |
| `demo` | The static demo. `demo/server.js` serves `demo/public/` (`app.js`, `oidc.json`). |
| `scripts` | `register-iya-sts-client.mjs` registers the public client on iya-sts. `version.mjs` stamps the published version. |
| `docs` | The GitHub Pages site. |
| `tools/apidocs` | TypeDoc and JSDoc. It is outside the npm workspace because TypeDoc runs on a different TypeScript than the declaration build. |
| `Dockerfile`, `docker-compose.yml` | The demo image. Compose publishes `PORT` to the same host port. |

The root `package.json` is a private workspace named `oidc-caep-client-monorepo`. Committed manifests stay at `M.N.0` from the root `VERSION` file. The current line is 0.2, so the committed version is 0.2.0.

## Usage

```sh
npm install oidc-caep-client
```

```js
import { OIDCClient, TokenManager, IndexedDBKeyStore } from 'oidc-caep-client';

const client = await OIDCClient.discover({
  issuer: 'https://idp.example.com',
  clientId: 'my-spa',
  redirectUri: `${location.origin}/callback`,
  postLogoutRedirectUri: `${location.origin}/`,
  dpop: { keyStore: new IndexedDBKeyStore() },
});
const tokens = new TokenManager(client);
const { url } = await client.createAuthorizationRequest();
```

The redirect is `location.origin` plus `/callback`. The package README and the guide on the documentation site are the reference.

## Tests

```sh
npm ci
npm test
npm run test:types
npm run version:check
```

`npm test` runs `node:test` on `packages/oidc-caep-client/test/*.test.js` and `scripts/*.test.mjs`, against a strict in-memory provider and SSF transmitter injected through the library's `fetch` option. `test:types` builds the declarations and type-checks a TypeScript consumer and a `// @ts-check` consumer, including the `ts` examples in the documentation. `version:check` fails unless every manifest is `M.N.0`.

`.github/workflows/tests.yml` also builds the demo image and checks the page. That job publishes host port 3000. Do not run it while a demo is already bound there. The in-process commands above do not need the container.

## Live test and the nightly suite

`scripts/live_iya_sts.py` is host Python, standard library only. It starts a fresh iya-sts (`IYA_STS_IMAGE`, or a clone of `main` built here, or a running one at `IYA_STS_URL` that it never stops) on `127.0.0.1:${LIVE_STS_PORT:-18504}` with `STS_PERSISTENCE_MODE=memory`, `STS_CLUSTER_MODE=off` and no workers. It runs `scripts/register-iya-sts-client.mjs` in `node:24.22.1-alpine` against an `oidc.json` pointing at that iya-sts, with `--public-url http://127.0.0.1:${LIVE_DEMO_PORT:-18604}` (the page's redirect is `location.origin`, so that origin is exactly what is registered) and the test user `caep-demo-user`. It serves the demo image with that `oidc.json` mounted over `demo/public/oidc.json`, on the host network.

`scripts/live_browser.py` runs only in `oidc-caep-client-live:browser`, built by `scripts/live-browser.Dockerfile` from `mcr.microsoft.com/playwright/python:v1.55.0-noble` (that image has the browsers but not the `playwright` package or `certutil`), and drives headless Chromium: Sign in on the page, then iya-sts's `/authn` screens (username and password, consent, an optional step's skip). It keeps the page open and answers `status` on stdin with the page's `#live-status` JSON. The host script emits `credential-change` and `session-revoked` through `POST /admin-api/caep/emit` and requires the first while `signedIn` is true and the second with `signedIn` false. The page receives both by polling its own SSF stream from the browser.

`#live-status` is a hidden element `app.js` redraws with every log render: `signedIn`, the active account's `subject`, the receiver state (`connected` while polling) and its last poll error, and each received event's `type` URI and `jti`. Never a token or a payload. It reports the last account the tab had active, because an ended account stops being active.

The demo's signal handlers start `accounts.end()` on a timer instead of awaiting it. Ending an account stops its stream, and `SSFReceiver.stop()` waits for the poll in flight, which is the one running the handler: awaited, the end waited for itself, the SET was never logged or acknowledged, polling stopped, and the account stayed signed in. The live test found it.

TLS: the host script takes the one self-signed certificate from the chain `GET /tls/server-certificate` serves (`CN = sts Root CA`), verifies iya-sts against it, and mounts it into the browser container, which adds it to Chromium's NSS database (`certutil`, trust `C,,`). The browser is never told to ignore certificate errors. Container names: `iya-sts-live-oidc-caep-client`, `oidc-caep-client-live-demo`, `oidc-caep-client-live-browser`; images `oidc-caep-client-live:demo` and `oidc-caep-client-live:browser`. Never bind 3000, 8081 or 18481 to 18495.

`.github/workflows/nightly.yml` runs at 06:15 UTC (`15 6 * * *`) and on demand: the unit suite in the Node image, then the live test. `tests.yml` has no schedule.

## Demo

Compose maps `${PORT:-3000}:${PORT:-3000}`. The page's redirect is `location.origin`, so the client registered on iya-sts has to use that same origin. `scripts/register-iya-sts-client.mjs` follows `PORT` unless an explicit public URL is set.

```sh
npm install
ADMIN_API_CLIENT_SECRET=… npm run register-iya-sts
docker compose up --build
```

Open <http://localhost:3000>. The image health check requests `http://127.0.0.1:${PORT}/`.

An explicit `PUBLIC_URL` replaces the origin and keeps the path. The default `http://localhost:3000` is not explicit. `pollIntervalMs` is a millisecond pause, not a port.

## Releases

`main` publishes `M.N.P` as npm `latest`. `develop` publishes `M.N.P-next.R` as `next`. The patch is chosen at publish time by `scripts/version.mjs` from the versions already on npm. After bumping `VERSION`, run `npm run version:sync`.

`.github/workflows/npm-publish.yml` runs only when the push changes the package directory, `VERSION`, `package-lock.json`, `scripts/version.mjs`, or that workflow. A change that is only this file, the demo, or the docs does not publish. A pull request packs and publishes nothing.

## Changes

Branch from `develop`. Open a pull request into `develop` and merge it there. The default branch is `main`, so a closing keyword on that pull request does not close the issue. Close the issue in a comment that names the `develop` commit. Then merge `develop` into `main`, and fast-forward `develop` to that same commit so both branches name one hash.
