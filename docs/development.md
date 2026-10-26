---
title: Development and releases
---

# Development and releases

## Tests

```sh
npm install
npm test
```

`npm run test:types` builds the TypeScript declarations from the source's JSDoc (`types/`, not committed; `npm pack` builds them too) and type-checks two consumers through the package's `exports`: a TypeScript file and a `// @ts-check` JavaScript file, each with deliberate mistakes that must still fail. It also compiles every ```` ```ts ```` example in the documentation, so an example that no longer matches the API fails the check.

The tests run with `node:test` against a strict in-memory OpenID Provider and SSF transmitter, injected through the library's `fetch` option. The stub enforces public clients, PKCE, PAR and DPoP (proof signature, `htm`/`htu`/`ath`, key binding and nonces). The suite covers:

- state, the front channel, RFC 9207 and the setup checks;
- ID token validation, refresh (OIDC Core §12.2) and UserInfo;
- DPoP, PAR, resource indicators, logout and dynamic registration;
- the token cache, and several accounts per browser;
- the SSF receiver: polling, catch-up, SET validation, acknowledgement and redelivery;
- that the library imports no Node.js built-ins.

Node.js 24.22.1 or later is required (`.nvmrc`), the release that fixes HTTP2Shell (CVE-2026-111497).

## API references

The site's [TypeScript API](https://rcbj.github.io/oidc-caep-client/api/) (TypeDoc) and [JavaScript API](https://rcbj.github.io/oidc-caep-client/jsdoc/) (JSDoc) are generated from the source's JSDoc by `tools/apidocs`. That is a package of its own, outside the npm workspace, because TypeDoc runs on TypeScript 6 and the library builds its declarations with 7. To build them locally:

```sh
cd tools/apidocs && npm ci && npm run build   # writes _site_api/api and _site_api/jsdoc
```

## Continuous integration

| Workflow | Runs on | Does |
|---|---|---|
| [`tests.yml`](https://github.com/rcbj/oidc-caep-client/blob/main/.github/workflows/tests.yml) | every push and pull request | `npm test`, then builds the demo container and smoke-tests the page, its headers and the modules it loads |
| [`npm-publish.yml`](https://github.com/rcbj/oidc-caep-client/blob/main/.github/workflows/npm-publish.yml) | pushes to `main` and `develop` that change the package | tests, stamps the version, packs and publishes to npm with provenance |
| [`pages.yml`](https://github.com/rcbj/oidc-caep-client/blob/main/.github/workflows/pages.yml) | pushes to `main` that change the docs or the library's source | builds this site and the API references, and deploys them |

## Branches

- **`develop`** is where work comes together. Create every feature or fix branch from it, and merge back into it.
- **`main`** is what is released. It receives `develop` when a release is cut.

```sh
git switch develop && git pull
git switch -c feature/<short-name>    # or fix/<short-name>
# commit, push, and open a pull request into develop
```

## Versions and releases

Versions are **M.N.O**, the same scheme as iya-sts ([`scripts/version.mjs`](https://github.com/rcbj/oidc-caep-client/blob/main/scripts/version.mjs)):

- **M.N** is in the [`VERSION`](https://github.com/rcbj/oidc-caep-client/blob/main/VERSION) file. After bumping it, run `npm run version:sync` so the committed `package.json` files say `M.N.0`. `npm run version:check` (also run in CI) fails if they don't.
- **O** is the build number: the UTC build time as `YYYYMMDDHHMMSS`, or `BUILD_NUMBER` when set. CI writes it into the package just before packing, so a release needs no version commit.

| Push to | npm dist-tag |
|---|---|
| `main` | `latest` |
| `develop` | `next` |

A pull request builds, tests and packs, and publishes nothing. Each published commit is tagged `v<version>`. Publishing uses the repository secret `NPM_TOKEN`, or npm trusted publishing once it is configured.
