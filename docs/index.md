---
title: oidc-caep-client
---

# oidc-caep-client

An OpenID Connect client library for **browser single-page apps**. It runs entirely in the page as a **public client**, with no client secret and no server holding tokens. It covers:

- **Signing in:** Authorization Code with PKCE, PAR, DPoP-bound tokens, RFC 9207 mix-up defence, and full ID token validation.
- **Tokens:** caching and refreshing them before they expire, safely across tabs.
- **Several accounts:** several people signed in to one browser, with one active account per tab.
- **CAEP:** subscribing to the identity provider's Shared Signals stream, with one handler per CAEP event and a hook for your own logic.

It uses Web APIs only and depends on nothing but [`jose`](https://github.com/panva/jose).

## Where to read

- **[Building a browser SPA](spa-guide.md)**, the walkthrough:
  - setting up the identity provider and serving the page;
  - signing in and choosing where tokens live;
  - calling your APIs;
  - receiving CAEP events;
  - signing out, errors and troubleshooting.
- **[API reference](reference.md):** the security features, every option, method and event, and the CAEP event table.
- **[The demo](https://github.com/rcbj/oidc-caep-client/tree/main/demo)**, a complete app built this way:
  - several accounts in one browser;
  - a CAEP event log;
  - a picker for the event types its stream subscribes to.

## Quick look

```js
import { OIDCClient, SSFReceiver, TokenManager } from 'oidc-caep-client';

const client = await OIDCClient.discover({
  issuer: 'https://idp.example.com',
  clientId: 'my-spa',
  redirectUri: `${location.origin}/callback`,
  dpop: true,
});
const tokens = new TokenManager(client);

// Sign in, then on /callback:
await tokens.set('user', await client.callback(location.href));

// React to security events about the signed-in person.
const caep = new SSFReceiver({
  transmitterIssuer: 'https://idp.example.com',
  authorizationHeaders: async (req) => client.resourceHeaders(await tokens.getTokenSet('user'), req),
});
caep.onSessionRevoked(() => signOutLocally());
await caep.start({ catchUp: true });
```

MIT licensed. © 2026 Iya CyberSecurity Solutions, LLC.
