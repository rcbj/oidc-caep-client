# oidc-caep-client

An OpenID Connect client for browser single-page apps, written in JavaScript with TypeScript declarations, and a demo app built on it. The client runs in the page as a public client (PKCE, PAR, DPoP) and receives CAEP security events through the Shared Signals Framework.

**Documentation:** <https://rcbj.github.io/oidc-caep-client/>

| Path | |
|---|---|
| [`packages/oidc-caep-client`](packages/oidc-caep-client) | The library, published to npm as [`oidc-caep-client`](https://www.npmjs.com/package/oidc-caep-client). |
| [`demo`](demo) | A demo single-page app, run in one container. |

## Install

```sh
npm install oidc-caep-client
```

See [Installing](https://rcbj.github.io/oidc-caep-client/reference.html#installing) for version ranges and loading it in the browser, and the [SPA guide](https://rcbj.github.io/oidc-caep-client/spa-guide.html) to build an app with it.

## Run the demo

```sh
ADMIN_API_CLIENT_SECRET=… npm run register-iya-sts   # once: register the client on iya-sts
docker compose up --build
```

Open <http://localhost:3000>. See [Running the demo](https://rcbj.github.io/oidc-caep-client/demo.html).

## Develop

```sh
npm install
npm test
```

Branch from `develop`. See [Development and releases](https://rcbj.github.io/oidc-caep-client/development.html) for CI, branches and versioning.

## License

MIT © 2026 Iya CyberSecurity Solutions, LLC. See [LICENSE](LICENSE).
