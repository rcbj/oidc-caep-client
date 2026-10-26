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

## Install

```sh
npm install oidc-caep-client
```

That adds the package to your `package.json`:

```json
{
  "dependencies": {
    "oidc-caep-client": "^0.1.0"
  }
}
```

Versions are `M.N.O`, with `O` the UTC build time, so `^0.1.0` takes every later 0.1 build; `npm install oidc-caep-client@next` gets the one built from `develop`. [Installing](reference.md#installing) in the reference covers pinning a version and loading the package with or without a bundler.

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
import { logEventReceived, OIDCClient, SSFReceiver, TokenManager } from 'oidc-caep-client';

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
  // Runs for every event, before the handlers below. The default, logEventReceived, prints
  // the event's name and jti; replace it with your own logic, or pass null to turn it off.
  onEventReceived: async (evt) => {
    logEventReceived(evt);
    await audit.record(evt.name, evt.subject);
  },
});

// One handler per event type. Register your own to decide what each event does.
caep
  .onSessionRevoked(() => signOutLocally('Your session was ended.'))
  .onTokenClaimsChange(() => tokens.refresh('user'))
  .onCredentialChange((evt) => {
    if (['revoke', 'delete'].includes(evt.payload.change_type)) signOutLocally('Sign in again.');
  })
  .onAssuranceLevelChange((evt) => {
    if (evt.payload.change_direction === 'decrease') requireStepUp();
  })
  .onDeviceComplianceChange((evt) => {
    if (evt.payload.current_status === 'not-compliant') signOutLocally('This device no longer meets policy.');
  })
  .onRiskLevelChange((evt) => {
    if (evt.payload.current_level === 'HIGH') signOutLocally('Unusual activity was detected.');
  })
  .onError((err, ctx) => console.warn('CAEP', ctx.phase, err.message));

await caep.start({ catchUp: true });
```

Registering a handler for an event type adds to what runs; `caep.off(CAEP.SESSION_REVOKED, fn)` removes one again. `onEvent(uri, fn)` handles any other type, such as RISC events. The [guide](spa-guide.md#9-receive-caep-events) suggests a reaction for each event, and the [reference](reference.md) lists every handler and its payload fields.

MIT licensed. © 2026 Iya CyberSecurity Solutions, LLC.
