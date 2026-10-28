import assert from 'node:assert/strict';
import { createHash, randomUUID } from 'node:crypto';
import { afterEach, beforeEach, describe, it } from 'node:test';
import { calculateJwkThumbprint, decodeProtectedHeader, exportJWK, generateKeyPair, importJWK, jwtVerify, SignJWT } from 'jose';
import {
  AccountManager, CAEP, clearDiscoveryCache, DPoPKey, logEventReceived, needsInteraction, OAuthError, OIDCClient, registerClient, SETValidationError, SSF, SSFReceiver, Subject,
  MemoryTokenStore, subjectMatches, TokenManager, TransactionStore, WebStorageKeyStore,
} from '../src/index.js';
import { onceEvent } from '../src/util.js';

/**
 * In-memory test double for an OpenID Provider + SSF transmitter that ENFORCES what a strict OP would:
 * public clients only, PKCE S256, PAR, DPoP (proof signature, htm/htu/ath, jkt binding, nonces).
 * Injected through the library's `fetch` option — no network.
 */
async function createStubProvider(opts = {}) {
  const { issuer = 'https://op.test', accessTokenTtl = 3600, registrationOverride = {}, metadataOverride = {} } = opts;
  const { privateKey, publicKey } = await generateKeyPair('RS256');
  const kid = 'k1';
  const jwks = { keys: [{ ...(await exportJWK(publicKey)), kid, alg: 'RS256', use: 'sig' }] };
  const clientId = 'spa';
  const state = {
    registrations: [], codes: new Map(), par: new Map(), accessTokens: new Map(), refreshTokens: new Map(),
    tokenCalls: 0, parCalls: 0, streams: new Map(), lastAuthorize: null, lastToken: null,
    requireNonce: { token: false, resource: false }, nonce: 'n-' + randomUUID(), acr: 'urn:acr:pwd',
  };
  const now = () => Math.floor(Date.now() / 1000);
  const rnd = () => randomUUID().replaceAll('-', '');

  const metadata = {
    issuer,
    authorization_endpoint: `${issuer}/authorize`,
    token_endpoint: `${issuer}/token`,
    userinfo_endpoint: `${issuer}/userinfo`,
    jwks_uri: `${issuer}/jwks`,
    end_session_endpoint: `${issuer}/logout`,
    revocation_endpoint: `${issuer}/revoke`,
    registration_endpoint: `${issuer}/register`,
    pushed_authorization_request_endpoint: `${issuer}/par`,
    grant_types_supported: ['authorization_code', 'refresh_token'],
    scopes_supported: ['openid', 'profile', 'email', 'offline_access', 'ssf:read', 'ssf:write'],
    response_types_supported: ['code'],
    subject_types_supported: ['public'],
    id_token_signing_alg_values_supported: ['RS256', 'ES256'],
    token_endpoint_auth_methods_supported: ['none'],
    code_challenge_methods_supported: ['S256'],
    dpop_signing_alg_values_supported: ['ES256'],
    authorization_response_iss_parameter_supported: true,
    ...metadataOverride,
  };
  const ssfMetadata = {
    spec_version: '1_0',
    issuer,
    jwks_uri: `${issuer}/jwks`,
    delivery_methods_supported: ['urn:ietf:rfc:8936'],
    configuration_endpoint: `${issuer}/ssf/stream`,
    status_endpoint: `${issuer}/ssf/status`,
    add_subject_endpoint: `${issuer}/ssf/subjects/add`,
    verification_endpoint: `${issuer}/ssf/verify`,
  };

  const json = (body, status = 200, headers = {}) => new Response(body === undefined ? null : JSON.stringify(body), { status, headers: { 'content-type': 'application/json', ...headers } });
  const sign = (claims, typ, sub) => {
    const jwt = new SignJWT(claims).setProtectedHeader({ alg: 'RS256', kid, ...(typ ? { typ } : {}) }).setIssuer(issuer).setIssuedAt();
    if (sub) jwt.setSubject(sub);
    return jwt;
  };
  const b64sha = (v) => createHash('sha256').update(v).digest('base64url');

  async function idToken(sub, { nonce, accessToken, authTime, typ, iat, sid }) {
    return new SignJWT({ nonce, at_hash: createHash('sha256').update(accessToken).digest().subarray(0, 16).toString('base64url'), auth_time: authTime, acr: state.acr, email: `${sub}@example.com`, email_verified: true, preferred_username: sub, sid })
      .setProtectedHeader({ alg: 'RS256', kid, ...(typ ? { typ } : {}) }).setIssuer(issuer).setSubject(sub)
      .setAudience(clientId).setIssuedAt(iat ?? now()).setExpirationTime('5m').sign(privateKey);
  }

  /** Verifies a DPoP proof; answers { jkt } or { error }. */
  async function checkProof(proof, method, url, accessToken, where) {
    if (!proof) return {};
    try {
      const header = decodeProtectedHeader(proof);
      const key = await importJWK(header.jwk, header.alg);
      const { payload } = await jwtVerify(proof, key, { typ: 'dpop+jwt', maxTokenAge: 60 });
      const u = new URL(url);
      if (payload.htm !== method || payload.htu !== `${u.origin}${u.pathname}`) return { error: 'invalid_dpop_proof' };
      if (accessToken && payload.ath !== b64sha(accessToken)) return { error: 'invalid_dpop_proof' };
      if (state.requireNonce[where] && payload.nonce !== nonceFor(where)) return { error: 'use_dpop_nonce' };
      return { jkt: await calculateJwkThumbprint(header.jwk, 'sha256') };
    } catch {
      return { error: 'invalid_dpop_proof' };
    }
  }

  async function makeSet(stream, eventType, payload, subId) {
    return sign({ jti: rnd(), sub_id: subId, events: { [eventType]: payload } }, 'secevent+jwt').setAudience(stream.aud).sign(privateKey);
  }

  /** Checks an Authorization header against issued tokens (Bearer or DPoP-bound). */
  async function resourceAuth(headers, method, url) {
    const [scheme, token] = (headers.get('authorization') ?? '').split(' ');
    const at = state.accessTokens.get(token);
    if (!at) return { error: 'invalid_token' };
    if (at.jkt) {
      if (!/^dpop$/i.test(scheme)) return { error: 'invalid_token' };
      const proof = await checkProof(headers.get('dpop'), method, url, token, 'resource');
      if (proof.error) return proof;
      if (proof.jkt !== at.jkt) return { error: 'invalid_dpop_proof' };
    } else if (!/^bearer$/i.test(scheme)) {
      return { error: 'invalid_token' };
    }
    return { at };
  }

  // One nonce for every server, or one each (state.nonces.token / .resource), as RFC 9449 §8 and §9 allow.
  const nonceFor = (where) => state.nonces?.[where] ?? state.nonce;
  const nonceChallenge = () => new Response(null, { status: 401, headers: { 'www-authenticate': 'DPoP error="use_dpop_nonce"', 'dpop-nonce': nonceFor('resource') } });

  async function handle(url, init) {
    const u = new URL(url);
    const method = init?.method ?? 'GET';
    const headers = new Headers(init?.headers);
    const body = init?.body;
    const form = body instanceof URLSearchParams ? body : new URLSearchParams(typeof body === 'string' && !body.startsWith('{') ? body : '');
    const data = typeof body === 'string' && body.startsWith('{') ? JSON.parse(body) : {};
    const p = u.pathname;

    if (p === '/.well-known/openid-configuration') return json(metadata);
    if (p === '/.well-known/ssf-configuration') return json(ssfMetadata);
    if (p === '/jwks') return json(jwks);

    if (p === '/par') {
      state.parCalls++;
      if (form.get('client_id') !== clientId || headers.get('authorization')) return json({ error: 'invalid_client' }, 401);
      const requestUri = `urn:ietf:params:oauth:request_uri:${rnd()}`;
      state.par.set(requestUri, new URLSearchParams(form));
      return json({ request_uri: requestUri, expires_in: 60 }, 201);
    }

    if (p === '/token') {
      state.tokenCalls++;
      if (form.get('client_id') !== clientId || headers.get('authorization') || form.get('client_secret')) return json({ error: 'invalid_client' }, 401);
      const proof = await checkProof(headers.get('dpop'), 'POST', url, undefined, 'token');
      if (proof.error === 'use_dpop_nonce') return json({ error: 'use_dpop_nonce' }, 400, { 'dpop-nonce': nonceFor('token') });
      if (proof.error) return json({ error: proof.error }, 400);
      state.lastToken = new URLSearchParams(form);
      const issue = (sub, scope) => {
        const at = `at-${rnd()}`;
        state.accessTokens.set(at, { sub, scope, jkt: proof.jkt });
        return at;
      };
      const tokenType = proof.jkt ? 'DPoP' : 'Bearer';
      if (form.get('grant_type') === 'authorization_code') {
        const code = state.codes.get(form.get('code'));
        state.codes.delete(form.get('code'));
        if (!code || code.redirectUri !== form.get('redirect_uri')) return json({ error: 'invalid_grant' }, 400);
        if (b64sha(form.get('code_verifier') ?? '') !== code.challenge) return json({ error: 'invalid_grant', error_description: 'PKCE' }, 400);
        if (code.dpopJkt && code.dpopJkt !== proof.jkt) return json({ error: 'invalid_grant', error_description: 'dpop_jkt' }, 400);
        const at = issue(code.sub, code.scope);
        const rt = `rt-${rnd()}`;
        state.refreshTokens.set(rt, { sub: code.sub, authTime: code.authTime, jkt: proof.jkt, scope: code.scope, sid: code.sid });
        return json({ access_token: at, token_type: tokenType, expires_in: accessTokenTtl, refresh_token: rt, scope: code.scope,
          id_token: await idToken(code.sub, { nonce: code.nonce, accessToken: at, authTime: code.authTime, sid: code.sid }) });
      }
      if (form.get('grant_type') === 'refresh_token') {
        const rt = state.refreshTokens.get(form.get('refresh_token'));
        if (!rt || rt.jkt !== proof.jkt) return json({ error: 'invalid_grant' }, 400);
        state.refreshTokens.delete(form.get('refresh_token'));
        const at = issue(rt.sub, rt.scope);
        const next = `rt-${rnd()}`;
        state.refreshTokens.set(next, rt);
        return json({ access_token: at, token_type: tokenType, expires_in: accessTokenTtl, refresh_token: next,
          id_token: await idToken(rt.sub, { accessToken: at, authTime: rt.authTime, sid: rt.sid }) });
      }
      return json({ error: 'unauthorized_client' }, 400);
    }

    if (p === '/userinfo') {
      const auth = await resourceAuth(headers, method, url);
      if (auth.error === 'use_dpop_nonce') return nonceChallenge();
      if (auth.error) return new Response(null, { status: 401, headers: { 'www-authenticate': `Bearer error="${auth.error}"` } });
      return json({ sub: auth.at.sub, email: `${auth.at.sub}@example.com` });
    }
    if (p === '/revoke') {
      if (form.get('client_id') !== clientId) return json({ error: 'invalid_client' }, 401);
      state.refreshTokens.delete(form.get('token'));
      state.accessTokens.delete(form.get('token'));
      return new Response(null, { status: 200 });
    }
    if (p === '/register' && method === 'POST') {
      state.registrations.push({ body: data, authorization: headers.get('authorization') });
      return json({ ...data, client_id: clientId, registration_access_token: 'rat', ...registrationOverride }, 201);
    }

    if (p.startsWith('/ssf/')) {
      const auth = await resourceAuth(headers, method, url);
      if (auth.error === 'use_dpop_nonce') return nonceChallenge();
      if (auth.error) return json({ error: 'invalid_token' }, 401);
      if (p === '/ssf/stream' && method === 'POST') {
        // iya-sts past ssf.maxStreams: 403, never 409.
        if (state.streamLimit != null && state.streams.size >= state.streamLimit) {
          return json({ err: 'access_denied', description: 'at the stream limit' }, 403);
        }
        const id = rnd();
        const stream = { stream_id: id, iss: issuer, aud: clientId, delivery: { method: data.delivery.method, endpoint_url: `${issuer}/ssf/poll/${id}` },
          events_requested: data.events_requested, events_delivered: data.events_requested, description: data.description,
          status: 'enabled', subjects: [], queue: new Map() };
        state.streams.set(id, stream);
        const { subjects, queue, ...pub } = stream;
        return json(pub, 201);
      }
      if (p === '/ssf/stream' && method === 'GET' && !u.searchParams.get('stream_id')) {
        return json([...state.streams.values()].map(({ subjects, queue, ...pub }) => pub));
      }
      const stream = state.streams.get(u.searchParams.get('stream_id') ?? data.stream_id ?? p.split('/').pop());
      if (!stream) return json({ error: 'not_found' }, 404);
      if (p === '/ssf/stream' && method === 'PATCH') {
        for (const [k, v] of Object.entries(data)) if (k !== 'stream_id') stream[k] = v;
        const { subjects, queue, ...pub } = stream;
        return json(pub);
      }
      if (p === '/ssf/stream' && method === 'GET') {
        const { subjects, queue, ...pub } = stream;
        return json(pub);
      }
      if (p === '/ssf/stream' && method === 'DELETE') {
        state.streams.delete(stream.stream_id);
        return new Response(null, { status: 204 });
      }
      if (p === '/ssf/status') {
        if (method === 'POST') stream.status = data.status;
        return json({ stream_id: stream.stream_id, status: stream.status });
      }
      if (p === '/ssf/subjects/add') {
        stream.subjects.push(data.subject);
        return new Response(null, { status: 200 });
      }
      if (p === '/ssf/verify') {
        stream.queue.set(rnd(), await makeSet(stream, SSF.VERIFICATION, { state: data.state }, { format: 'opaque', id: stream.stream_id }));
        return new Response(null, { status: 204 });
      }
      if (p.startsWith('/ssf/poll/')) {
        for (const jti of data.ack ?? []) stream.queue.delete(jti);
        for (const [jti, err] of Object.entries(data.setErrs ?? {})) {
          (stream.errs ??= {})[jti] = err;
          stream.queue.delete(jti);
        }
        state.lastPoll = data;
        return json({ sets: Object.fromEntries(stream.queue), moreAvailable: false });
      }
    }
    return json({ error: 'not_found' }, 404);
  }

  return {
    issuer, clientId, metadata, state, privateKey, makeSet, idToken,
    fetch: (input, init) => handle(String(input instanceof Request ? input.url : input), init),
    /** Simulates the user signing in at the authorization endpoint; returns the redirect back to the RP. */
    authorize(authorizationUrl, sub = 'alice') {
      let q = new URL(authorizationUrl).searchParams;
      if (q.get('request_uri')) {
        const pushed = state.par.get(q.get('request_uri'));
        state.par.delete(q.get('request_uri'));
        if (!pushed || q.get('client_id') !== clientId) throw new Error('unknown request_uri');
        q = pushed;
      }
      state.lastAuthorize = new URLSearchParams(q);
      const code = rnd();
      state.codes.set(code, { sub, nonce: q.get('nonce'), challenge: q.get('code_challenge'), redirectUri: q.get('redirect_uri'),
        authTime: now(), dpopJkt: q.get('dpop_jkt'), scope: q.get('scope'), sid: `sid-${sub}-${rnd().slice(0, 8)}` });
      return `${q.get('redirect_uri')}?${new URLSearchParams({ code, state: q.get('state'), iss: issuer })}`;
    },
    /** The OP answering an authorization request with an error (e.g. login_required to prompt=none). */
    deny(authorizationUrl, error) {
      let q = new URL(authorizationUrl).searchParams;
      if (q.get('request_uri')) q = state.par.get(q.get('request_uri'));
      state.lastAuthorize = new URLSearchParams(q);
      return `${q.get('redirect_uri')}?${new URLSearchParams({ error, state: q.get('state'), iss: issuer })}`;
    },
  };
}

let op;
beforeEach(async () => {
  clearDiscoveryCache();
  op = await createStubProvider();
});

const REDIRECT = 'https://app.test/callback';
const memoryStore = () => new TransactionStore({ storage: null });
const newClient = (extra = {}) => OIDCClient.discover({ issuer: op.issuer, clientId: op.clientId, redirectUri: REDIRECT, fetch: op.fetch, transactionStore: memoryStore(), ...extra });

async function signIn(client, sub, authOpts) {
  const { url } = await client.createAuthorizationRequest(authOpts);
  return client.callback(op.authorize(url, sub));
}

describe('configuration', () => {
  it('discovers OP metadata and uses PAR when it is advertised', async () => {
    const client = await newClient();
    assert.equal(client.metadata.issuer, op.issuer);
    assert.equal(client.config.tokenEndpointAuthMethod, 'none');
    assert.equal(client.config.par, true);
    assert.match(client.config.scope, /offline_access/);
  });

  it('is a public client only: secrets and confidential auth are refused', () => {
    assert.throws(() => new OIDCClient({ issuer: op.issuer, clientId: 'x', clientSecret: 's' }), /public client/);
    assert.throws(() => new OIDCClient({ issuer: op.issuer, clientId: 'x', tokenEndpointAuthMethod: 'client_secret_basic' }), /public client/);
    assert.throws(() => new OIDCClient({ issuer: op.issuer, clientId: 'x', privateJwk: {} }), /public client/);
  });

  it('refuses an OP that does not accept public clients or does not offer PKCE S256', async () => {
    await assert.rejects(OIDCClient.fromMetadata({ ...op.metadata, token_endpoint_auth_methods_supported: ['client_secret_basic'] }, { clientId: 'x' }),
      (e) => e.code === 'public_client_not_supported');
    await assert.rejects(OIDCClient.fromMetadata({ ...op.metadata, code_challenge_methods_supported: ['plain'] }, { clientId: 'x' }),
      (e) => e.code === 'pkce_not_supported');
  });

  it('requires TLS for OP endpoints and redirect URIs, except loopback', async () => {
    await assert.rejects(OIDCClient.fromMetadata({ ...op.metadata, token_endpoint: 'http://op.test/token' }, { clientId: 'x' }), (e) => e.code === 'insecure_endpoint');
    await assert.rejects(OIDCClient.fromMetadata(op.metadata, { clientId: 'x', redirectUri: 'http://app.test/cb' }), (e) => e.code === 'insecure_redirect_uri');
    await OIDCClient.fromMetadata(op.metadata, { clientId: 'x', redirectUri: 'http://localhost:3000/callback' });
    await OIDCClient.fromMetadata(op.metadata, { clientId: 'x', redirectUri: 'http://127.0.0.1:3000/callback' });
    await OIDCClient.fromMetadata({ ...op.metadata, token_endpoint: 'http://op.test/token' }, { clientId: 'x', allowInsecureRequests: true });
  });

  it('configures from a supplied metadata document, and rejects incomplete ones', async () => {
    const client = await OIDCClient.fromMetadata(op.metadata, { clientId: op.clientId, redirectUri: REDIRECT, fetch: op.fetch, transactionStore: memoryStore() });
    assert.equal((await signIn(client)).claims.sub, 'alice');
    const { jwks_uri: _, ...incomplete } = op.metadata;
    await assert.rejects(OIDCClient.fromMetadata(incomplete, { clientId: 'x' }), /jwks_uri/);
  });

  it('honours require_pushed_authorization_requests and par settings', async () => {
    await assert.rejects(OIDCClient.fromMetadata({ ...op.metadata, require_pushed_authorization_requests: true }, { clientId: 'x', par: 'never' }), /requires PAR/);
    const noPar = { ...op.metadata };
    delete noPar.pushed_authorization_request_endpoint;
    const client = await OIDCClient.fromMetadata(noPar, { clientId: op.clientId, redirectUri: REDIRECT, fetch: op.fetch, transactionStore: memoryStore() });
    const { url } = await client.createAuthorizationRequest();
    assert.ok(new URL(url).searchParams.get('code_challenge'), 'without PAR the parameters are in the URL');
    await assert.rejects(OIDCClient.fromMetadata(noPar, { clientId: 'x', par: 'always' }), /no pushed_authorization_request_endpoint/);
  });
});

describe('authorization request', () => {
  it('pushes the request (PAR) and sends only client_id + request_uri through the browser', async () => {
    const client = await newClient();
    const { url } = await client.createAuthorizationRequest();
    assert.deepEqual([...new URL(url).searchParams.keys()].sort(), ['client_id', 'request_uri']);
    assert.equal(op.state.parCalls, 1);
  });

  it('carries state, nonce, PKCE S256 and resource indicators', async () => {
    const client = await newClient({ resource: ['https://api.test/', 'https://ssf.test/'] });
    const tokens = await signIn(client);
    const a = op.state.lastAuthorize;
    assert.equal(a.get('code_challenge_method'), 'S256');
    assert.equal(a.get('state').length, 43);
    assert.equal(a.get('nonce').length, 43);
    assert.deepEqual(a.getAll('resource'), ['https://api.test/', 'https://ssf.test/']);
    assert.deepEqual(op.state.lastToken.getAll('resource'), ['https://api.test/', 'https://ssf.test/']);
    assert.equal(tokens.claims.sub, 'alice');
  });
});

describe('state and the authorization response', () => {
  it('signs in and validates the ID token', async () => {
    const client = await newClient();
    const tokens = await signIn(client);
    assert.equal(tokens.claims.sub, 'alice');
    assert.equal(tokens.token_type, 'Bearer');
    assert.ok(tokens.refresh_token);
    assert.equal((await client.userinfo(tokens, { expectedSub: 'alice' })).email, 'alice@example.com');
  });

  it('accepts each authorization response once (state is single use)', async () => {
    const client = await newClient();
    const { url } = await client.createAuthorizationRequest();
    const redirect = op.authorize(url);
    await client.callback(redirect);
    await assert.rejects(client.callback(redirect), (e) => e.code === 'state_reused');
  });

  it('rejects an unknown, missing or tampered state', async () => {
    const client = await newClient();
    const { url } = await client.createAuthorizationRequest();
    const redirect = new URL(op.authorize(url));
    const tampered = new URL(redirect);
    tampered.searchParams.set('state', redirect.searchParams.get('state').replace(/.$/, (c) => (c === 'A' ? 'B' : 'A')));
    await assert.rejects(client.callback(tampered.href), (e) => e.code === 'state_mismatch');
    const missing = new URL(redirect);
    missing.searchParams.delete('state');
    await assert.rejects(client.callback(missing.href), (e) => e.code === 'state_missing');
    assert.equal((await client.callback(redirect.href)).claims.sub, 'alice', 'the genuine response still works');
  });

  it('expires an authorization request after transactionTtlSec', async () => {
    const store = memoryStore();
    const client = await newClient({ transactionStore: store, transactionTtlSec: 60 });
    const { url, state } = await client.createAuthorizationRequest();
    const txn = store.take(state);
    store.set(state, { ...txn, createdAt: Date.now() - 61_000 });
    await assert.rejects(client.callback(op.authorize(url)), (e) => e.code === 'transaction_expired');
  });

  it('binds a transaction to the OP and client that started it', async () => {
    const store = memoryStore();
    const client = await newClient({ transactionStore: store });
    const { url, state } = await client.createAuthorizationRequest();
    const txn = store.take(state);
    store.set(state, { ...txn, issuer: 'https://other-op.test' });
    await assert.rejects(client.callback(op.authorize(url)), (e) => e.code === 'issuer_mismatch');
  });

  it('rejects tokens in the front channel and repeated parameters', async () => {
    const client = await newClient();
    const { url } = await client.createAuthorizationRequest();
    const redirect = op.authorize(url);
    await assert.rejects(client.callback(`${redirect}&access_token=stolen`), (e) => e.code === 'front_channel_token');
    await assert.rejects(client.callback(`${redirect}#id_token=x`), (e) => e.code === 'front_channel_token');
    await assert.rejects(client.callback(`${redirect}&code=other`), (e) => e.code === 'duplicate_parameter');
  });

  it('enforces RFC 9207 iss when the OP advertises it', async () => {
    const client = await newClient();
    let { url } = await client.createAuthorizationRequest();
    const wrong = new URL(op.authorize(url));
    wrong.searchParams.set('iss', 'https://evil.test');
    await assert.rejects(client.callback(wrong.href), (e) => e.code === 'issuer_mismatch');
    ({ url } = await client.createAuthorizationRequest());
    const none = new URL(op.authorize(url));
    none.searchParams.delete('iss');
    await assert.rejects(client.callback(none.href), (e) => e.code === 'issuer_missing');
  });

  it('checks state before reporting an authorization error', async () => {
    const client = await newClient();
    const { state } = await client.createAuthorizationRequest();
    const iss = encodeURIComponent(op.issuer);
    await assert.rejects(client.callback(`${REDIRECT}?error=access_denied&state=${state}&iss=${iss}`), (e) => e instanceof OAuthError && e.error === 'access_denied');
    await assert.rejects(client.callback(`${REDIRECT}?error=access_denied&state=forged&iss=${iss}`), (e) => e.code === 'state_mismatch');
  });

  it('rejects a wrong PKCE verifier or nonce', async () => {
    const store = memoryStore();
    const client = await newClient({ transactionStore: store });
    let { url, state } = await client.createAuthorizationRequest();
    let txn = store.take(state);
    store.set(state, { ...txn, codeVerifier: 'x'.repeat(43) });
    await assert.rejects(client.callback(op.authorize(url)), (e) => e instanceof OAuthError && e.error === 'invalid_grant');
    ({ url, state } = await client.createAuthorizationRequest());
    txn = store.take(state);
    store.set(state, { ...txn, nonce: 'other' });
    await assert.rejects(client.callback(op.authorize(url)), (e) => e.code === 'nonce_mismatch');
  });
});

describe('ID token', () => {
  it('rejects a token of another type presented as an ID token (token confusion)', async () => {
    const client = await newClient();
    const at = await op.idToken('alice', { accessToken: 'a', authTime: 1, typ: 'at+jwt' });
    await assert.rejects(client.validateIdToken(at), /not an ID token/);
  });

  it('rejects a stale iat and a forged signature', async () => {
    const client = await newClient({ maxIdTokenAgeSec: 300 });
    const old = await op.idToken('alice', { accessToken: 'a', authTime: 1, iat: Math.floor(Date.now() / 1000) - 3600 });
    await assert.rejects(client.validateIdToken(old), (e) => e.code === 'invalid_id_token');
    const { privateKey } = await generateKeyPair('RS256');
    const forged = await new SignJWT({}).setProtectedHeader({ alg: 'RS256', kid: 'k1' }).setIssuer(op.issuer).setSubject('alice')
      .setAudience(op.clientId).setIssuedAt().setExpirationTime('5m').sign(privateKey);
    await assert.rejects(client.validateIdToken(forged), (e) => e.code === 'invalid_id_token');
  });

  it('enforces requested acr_values', async () => {
    const client = await newClient();
    await assert.rejects(signIn(client, 'alice', { acrValues: 'urn:acr:mfa' }), (e) => e.code === 'acr_mismatch');
    const ok = await signIn(client, 'alice', { acrValues: 'urn:acr:mfa urn:acr:pwd' });
    assert.equal(ok.claims.acr, 'urn:acr:pwd');
    const lax = await newClient({ enforceAcr: false });
    await signIn(lax, 'alice', { acrValues: 'urn:acr:mfa' });
  });
});

describe('DPoP (RFC 9449)', () => {
  it('keeps an extractable DPoP key in session storage and reloads the same thumbprint', async () => {
    const map = new Map();
    const storage = {
      getItem: (k) => (map.has(k) ? map.get(k) : null),
      setItem: (k, v) => map.set(k, String(v)),
      removeItem: (k) => map.delete(k),
    };
    const store = new WebStorageKeyStore({ storage, key: 'dpop' });
    const key = await DPoPKey.loadOrCreate(store);
    assert.equal(key.keyPair.privateKey.extractable, true);
    const saved = JSON.parse(storage.getItem('dpop'));
    assert.equal(saved.alg, 'ES256');
    assert.equal(typeof saved.privateJwk.d, 'string');
    const again = await DPoPKey.loadOrCreate(new WebStorageKeyStore({ storage, key: 'dpop' }));
    assert.equal(again.thumbprint, key.thumbprint);
    const proof = await again.proof({ method: 'POST', url: 'https://op.test/token' });
    const { payload, protectedHeader } = await jwtVerify(proof, await importJWK(saved.publicJwk, 'ES256'), { typ: 'dpop+jwt' });
    assert.equal(payload.htm, 'POST');
    assert.equal(protectedHeader.jwk.x, saved.publicJwk.x);
  });

  it('binds the code and tokens to a non-extractable key and uses it for resources and refresh', async () => {
    const client = await newClient({ dpop: true });
    assert.equal(client.dpopKey.alg, 'ES256');
    assert.equal(client.dpopKey.keyPair.privateKey.extractable, false);
    const tokens = await signIn(client);
    assert.equal(tokens.token_type, 'DPoP');
    assert.equal(op.state.lastAuthorize.get('dpop_jkt'), client.dpopKey.thumbprint);
    assert.equal((await client.userinfo(tokens, { expectedSub: 'alice' })).sub, 'alice');
    assert.equal((await client.refresh(tokens)).token_type, 'DPoP');
    // The same token presented as a plain bearer token is refused by the resource server.
    await assert.rejects(client.userinfo(tokens.access_token, { expectedSub: 'alice' }), (e) => e.status === 401);
  });

  it('retries with the server nonce at the token endpoint and at a resource server', async () => {
    const client = await newClient({ dpop: true });
    op.state.requireNonce = { token: true, resource: true };
    const tokens = await signIn(client);
    assert.equal(tokens.token_type, 'DPoP');
    assert.equal((await client.userinfo(tokens)).sub, 'alice');
  });

  it('refuses to use a DPoP-bound token without the DPoP key', async () => {
    const tokens = await signIn(await newClient({ dpop: true }));
    const plain = await newClient();
    await assert.rejects(plain.resourceHeaders(tokens, { url: 'https://api.test/' }), (e) => e.code === 'dpop_key_missing');
  });
});

describe('logout', () => {
  it('sends and validates a single-use state on RP-initiated logout', async () => {
    const client = await newClient({ postLogoutRedirectUri: 'https://app.test/' });
    const { url, state } = await client.createEndSessionRequest({ idTokenHint: 'hint' });
    const q = new URL(url).searchParams;
    assert.equal(q.get('state'), state);
    assert.equal(q.get('client_id'), op.clientId);
    assert.equal(q.get('id_token_hint'), 'hint');
    assert.equal(await client.validateEndSessionCallback(`https://app.test/?state=${state}`), true);
    await assert.rejects(client.validateEndSessionCallback(`https://app.test/?state=${state}`), (e) => e.code === 'state_mismatch');
  });
});

describe('AccountManager (one token cache for the browser, one active account per tab)', () => {
  const managers = [];
  afterEach(() => { for (const m of managers.splice(0)) m.close(); });
  /** A "tab": its own tab store, sharing the browser-wide cache `shared`. */
  const tab = async (client, shared, opts = {}) => {
    const m = new AccountManager(client, { store: shared, tabStore: new MemoryTokenStore(), broadcast: false, ...opts });
    managers.push(m);
    return m.init();
  };
  const add = async (accounts, sub, request = (a) => a.addAccount()) => {
    const { url } = await request(accounts);
    return accounts.handleCallback(op.authorize(url, sub));
  };

  it('caches every account, but only the active account\'s tokens are reachable', async () => {
    const client = await newClient();
    const accounts = await tab(client, new MemoryTokenStore());
    const activated = [];
    accounts.on('activated', (a, prev) => activated.push([a?.sub, prev?.sub]));
    const a = await add(accounts, 'alice');
    assert.equal(a.added, true);
    assert.equal(a.intent, 'add');
    assert.equal(op.state.lastAuthorize.get('prompt'), 'login');
    const b = await add(accounts, 'bob');
    assert.equal(accounts.active.sub, 'bob');
    assert.deepEqual(accounts.list().map((x) => [x.sub, x.status]), [['alice', 'signed-in'], ['bob', 'signed-in']]);
    assert.equal((await accounts.getTokenSet()).claims.sub, 'bob');
    assert.equal(accounts.getTokenSet.length, 1, 'getTokenSet takes no account key');
    const calls = op.state.tokenCalls;
    await accounts.activate(a.account.key);
    assert.equal(op.state.tokenCalls, calls, 'activating a cached account sends nothing to the OP');
    assert.equal((await accounts.getTokenSet()).claims.sub, 'alice');
    assert.deepEqual(activated, [['alice', undefined], ['bob', 'alice'], ['alice', 'bob']]);
    assert.notEqual(a.account.key, b.account.key);
    assert.doesNotMatch(JSON.stringify(accounts.list()), /at-|rt-|eyJ/, 'the account list holds no token');
  });

  it('refreshes only the active account; a dormant account is refreshed when it is activated', async () => {
    op = await createStubProvider({ accessTokenTtl: 2 });
    const client = await newClient();
    const accounts = await tab(client, new MemoryTokenStore(), { refreshSkewSec: 1 });
    const alice = await add(accounts, 'alice');
    await add(accounts, 'bob');
    const refreshed = [];
    accounts.on('refreshed', (x) => refreshed.push(x.sub));
    await new Promise((r) => setTimeout(r, 2600));
    assert.ok(refreshed.length >= 1);
    assert.ok(refreshed.every((s) => s === 'bob'), 'only the active account is refreshed in the background');
    const lastAuthCode = op.state.lastToken;
    await accounts.activate(alice.account.key);
    assert.equal(op.state.lastToken.get('grant_type'), 'refresh_token');
    assert.notEqual(op.state.lastToken, lastAuthCode);
    assert.equal((await accounts.getTokenSet()).claims.sub, 'alice');
  });

  it('runs onActivate with the account\'s tokens before it becomes active, and aborts on failure', async () => {
    const client = await newClient();
    let fail = false;
    const seen = [];
    const accounts = await tab(client, new MemoryTokenStore(), {
      onActivate: async (account, { getTokenSet }) => {
        seen.push([account.sub, (await getTokenSet()).claims.sub, accounts.activeKey === account.key]);
        if (fail && account.sub === 'alice') throw new Error('catch-up failed');
      },
    });
    const a = await add(accounts, 'alice');
    await add(accounts, 'bob');
    assert.deepEqual(seen, [['alice', 'alice', false], ['bob', 'bob', false]]);
    seen.length = 0;
    fail = true;
    await assert.rejects(accounts.activate(a.account.key), /catch-up failed/);
    assert.equal(accounts.active.sub, 'bob', 'the previous account is active again');
  });

  it('a signal that ends the account during onActivate stops its activation', async () => {
    const client = await newClient();
    let endIt = false;
    const accounts = await tab(client, new MemoryTokenStore(), {
      onActivate: async (account) => { if (endIt) await accounts.end(account.key, 'session-revoked while dormant'); },
    });
    const a = await add(accounts, 'alice');
    await add(accounts, 'bob');
    endIt = true;
    await accounts.activate(a.account.key);
    assert.equal(accounts.active.status, 'ended');
    await assert.rejects(accounts.getTokenSet(), (e) => e.code === 'no_tokens');
  });

  it('tabs share the cache, each with its own active account; refreshes are not repeated across tabs', async () => {
    const client = await newClient();
    const shared = new MemoryTokenStore();
    const tab1 = await tab(client, shared);
    const alice = await add(tab1, 'alice');
    const bob = await add(tab1, 'bob');
    const tab2 = await tab(client, shared);
    assert.equal(tab2.active, undefined, 'a new tab has no active account');
    assert.deepEqual(tab2.list().map((x) => x.sub), ['alice', 'bob']);
    const calls = op.state.tokenCalls;
    await tab2.activate(alice.account.key);
    assert.equal(op.state.tokenCalls, calls, 'no sign-in needed: the tokens are in the shared cache');
    assert.equal((await tab2.getTokenSet()).claims.sub, 'alice');
    assert.equal((await tab1.getTokenSet()).claims.sub, 'bob');
    // Both tabs active on bob refresh at once: one token-endpoint call, the other tab reuses its result.
    await tab2.activate(bob.account.key);
    const before = op.state.tokenCalls;
    const [r1, r2] = await Promise.all([tab1.refresh(), tab2.refresh()]);
    assert.equal(op.state.tokenCalls, before + 1);
    assert.equal(r1.access_token, r2.access_token);
  });

  it('a sign-out in one tab reaches the others (BroadcastChannel)', async () => {
    const client = await newClient();
    const shared = new MemoryTokenStore();
    const tab1 = await tab(client, shared, { broadcast: true, storeKey: 'bc-test' });
    const alice = await add(tab1, 'alice');
    const tab2 = await tab(client, shared, { broadcast: true, storeKey: 'bc-test' });
    await tab2.activate(alice.account.key);
    const changed = new Promise((resolve) => tab2.once('change', resolve));
    const keepAlive = setTimeout(() => {}, 5000); // the library's channel does not hold the event loop open
    await tab1.signOut(alice.account.key, { endSession: false });
    await changed;
    clearTimeout(keepAlive);
    assert.equal(tab2.active.status, 'signed-out');
    await assert.rejects(tab2.getTokenSet(), (e) => e.code === 'no_tokens');
  });

  it('signing in again as a listed person updates that account instead of adding one', async () => {
    const accounts = await tab(await newClient(), new MemoryTokenStore());
    const first = await add(accounts, 'alice');
    const again = await add(accounts, 'alice', (x) => x.signIn());
    assert.equal(again.added, false);
    assert.equal(accounts.list().length, 1);
    assert.notEqual(again.account.sid, first.account.sid);
  });

  it('chooseAccount asks the OP for its picker; resume and reauthenticate name the account', async () => {
    const accounts = await tab(await newClient(), new MemoryTokenStore());
    const { account } = await add(accounts, 'alice');
    const picker = await accounts.chooseAccount();
    assert.equal(op.state.par.get(new URL(picker.url).searchParams.get('request_uri')).get('prompt'), 'select_account');
    const { url } = await accounts.resume(account.key);
    const pushed = op.state.par.get(new URL(url).searchParams.get('request_uri'));
    assert.equal(pushed.get('prompt'), 'none');
    assert.equal(pushed.get('login_hint'), 'alice');
    assert.ok(pushed.get('id_token_hint'));
    const done = await accounts.handleCallback(op.authorize(url, 'alice'));
    assert.equal(done.intent, 'resume');
    assert.equal(done.added, false);
  });

  it('refuses a sign-in as another person when an account was named (account_mismatch)', async () => {
    const accounts = await tab(await newClient(), new MemoryTokenStore());
    const { account } = await add(accounts, 'alice');
    const { url } = await accounts.reauthenticate(account.key);
    await assert.rejects(accounts.handleCallback(op.authorize(url, 'mallory')), (e) => e.code === 'account_mismatch');
    assert.equal(accounts.list().length, 1);
    assert.equal(op.state.refreshTokens.size, 1, 'the mismatched tokens were revoked');
  });

  it('reports which account a prompt=none failure was for', async () => {
    const accounts = await tab(await newClient(), new MemoryTokenStore());
    const { account } = await add(accounts, 'alice');
    const { url } = await accounts.resume(account.key);
    await assert.rejects(accounts.handleCallback(op.deny(url, 'login_required')), (e) => needsInteraction(e) && e.account.key === account.key && e.context.intent === 'resume');
    const { url: url2 } = await accounts.signIn({ prompt: 'none' });
    await assert.rejects(accounts.handleCallback(op.deny(url2, 'account_selection_required')), (e) => needsInteraction(e) && e.account === undefined);
  });

  it('signs one account out with a logout request naming its ID token; the others stay cached', async () => {
    const client = await newClient({ postLogoutRedirectUri: 'https://app.test/' });
    const left = [];
    const accounts = await tab(client, new MemoryTokenStore(), { onLeave: async (x, { getTokenSet }) => left.push([x.sub, (await getTokenSet()).claims.sub]) });
    const a = await add(accounts, 'alice');
    const b = await add(accounts, 'bob');
    const c = await add(accounts, 'carol');
    await accounts.activate(b.account.key);
    const bobTokens = await accounts.getTokenSet();
    const logout = await accounts.signOut();
    assert.deepEqual(left, [['bob', 'bob']]);
    assert.equal(new URL(logout.url).searchParams.get('id_token_hint'), bobTokens.id_token);
    assert.equal(op.state.accessTokens.has(bobTokens.access_token), false, 'revoked');
    assert.equal(accounts.active.key, c.account.key, 'the most recently added signed-in account becomes active');
    assert.deepEqual(accounts.list().map((x) => x.status), ['signed-in', 'signed-out', 'signed-in']);
    assert.deepEqual(await client.completeEndSession(`https://app.test/?state=${logout.state}`), { context: { key: b.account.key } });
    await assert.rejects(accounts.forget(a.account.key), (e) => e.code === 'account_signed_in');
    await accounts.forget(b.account.key);
    assert.equal(accounts.list().length, 2);
    const all = await accounts.signOutAll();
    assert.equal(new URL(all.url).searchParams.get('id_token_hint'), null);
    assert.equal(accounts.active, undefined);
  });

  it('routes a security event to the account (and session) it is about, and ends that account only', async () => {
    const accounts = await tab(await newClient(), new MemoryTokenStore());
    const a = await add(accounts, 'alice');
    const b = await add(accounts, 'bob');
    assert.deepEqual(accounts.accountsForSubject(Subject.issSub(op.issuer, 'alice')).map((x) => x.sub), ['alice']);
    assert.deepEqual(accounts.accountsForSubject(Subject.email('bob@example.com')).map((x) => x.sub), ['bob']);
    const session = (sid) => Subject.complex({ user: Subject.issSub(op.issuer, 'alice'), session: Subject.opaque(sid) });
    assert.equal(accounts.accountsForSubject(session('another-sid')).length, 0);
    assert.equal(accounts.accountsForSubject(session(a.account.sid)).length, 1);
    await accounts.activate(a.account.key);
    const ended = [];
    accounts.on('ended', (x, why) => ended.push([x.sub, why]));
    await accounts.end(a.account.key, 'session-revoked');
    assert.deepEqual(ended, [['alice', 'session-revoked']]);
    assert.equal(accounts.get(a.account.key).status, 'ended');
    assert.equal(accounts.active.key, b.account.key);
    assert.equal((await accounts.getTokenSet()).claims.sub, 'bob');
  });

  it('a tab reactivates its account after a reload; unusable cached tokens become tokens-missing', async () => {
    const client = await newClient();
    const shared = new MemoryTokenStore();
    const tabStore = new MemoryTokenStore();
    const first = await tab(client, shared, { tabStore });
    const a = await add(first, 'alice');
    await add(first, 'bob');
    first.close();
    const cached = await shared.get(a.account.key);
    await shared.set(a.account.key, { ...cached, refresh_token: undefined, expires_at: 1 });
    const reloaded = await tab(client, shared, { tabStore });
    assert.equal(reloaded.active.sub, 'bob');
    assert.equal((await reloaded.getTokenSet()).claims.sub, 'bob');
    await reloaded.activate(a.account.key);
    assert.equal(reloaded.active.status, 'tokens-missing');
  });

  it('a reload while a sign-in is being recorded does not drop the new account', async () => {
    // The shared store holds the token write of the new account until the test lets it go.
    let release;
    let hold = false;
    const gate = new Promise((r) => { release = r; });
    class SlowStore extends MemoryTokenStore {
      async set(key, value) {
        if (hold && key.startsWith('acct-')) await gate;
        return super.set(key, value);
      }
    }
    const accounts = await tab(await newClient(), new SlowStore());
    const bob = await add(accounts, 'bob');
    hold = true;
    const { url } = await accounts.addAccount();
    const signingIn = accounts.handleCallback(op.authorize(url, 'alice'));
    await new Promise((r) => setTimeout(r, 20));
    // A reload during the write: before the fix it replaced the list, and alice's record was lost.
    const ending = accounts.end(bob.account.key, 'session-revoked');
    release();
    const { account } = await signingIn;
    await ending;
    assert.equal(account.sub, 'alice');
    assert.deepEqual(accounts.list().map((x) => x.sub).sort(), ['alice', 'bob']);
    assert.equal(accounts.get(bob.account.key).status, 'ended');
  });

  it('holds at most maxAccounts: forgets the account that left longest ago, else refuses', async () => {
    const accounts = await tab(await newClient(), new MemoryTokenStore(), { maxAccounts: 2 });
    const a = await add(accounts, 'alice');
    await add(accounts, 'bob');
    await assert.rejects(add(accounts, 'carol'), (e) => e.code === 'too_many_accounts');
    await accounts.signOut(a.account.key, { endSession: false });
    await add(accounts, 'carol');
    assert.deepEqual(accounts.list().map((x) => x.sub), ['bob', 'carol']);
  });
});

describe('dynamic client registration', () => {
  const request = () => ({ redirect_uris: [REDIRECT], grant_types: ['authorization_code'], id_token_signed_response_alg: 'ES256' });

  it('registers a public client with the requested ID token alg', async () => {
    const { client } = await OIDCClient.register(op.metadata, request(), { fetch: op.fetch, initialAccessToken: 'iat', dpop: true, transactionStore: memoryStore() });
    const sent = op.state.registrations[0];
    assert.equal(sent.body.token_endpoint_auth_method, 'none');
    assert.equal(sent.body.dpop_bound_access_tokens, true);
    assert.equal(sent.authorization, 'Bearer iat');
    assert.equal(client.config.idTokenSignedResponseAlg, 'ES256');
  });

  it('refuses a confidential registration or a substituted alg', async () => {
    op = await createStubProvider({ registrationOverride: { client_secret: 'oops' } });
    await assert.rejects(OIDCClient.register(op.metadata, request(), { fetch: op.fetch }), /confidential/);
    op = await createStubProvider({ registrationOverride: { id_token_signed_response_alg: 'RS256' } });
    await assert.rejects(OIDCClient.register(op.metadata, request(), { fetch: op.fetch }), (e) => e.code === 'registration_mismatch');
    await assert.rejects(registerClient(op.metadata, { ...request(), id_token_signed_response_alg: 'ML-DSA-65' }, { fetch: op.fetch }), /cannot verify/);
  });
});

describe('TokenManager', () => {
  it('refreshes on demand once inside the skew window, keeping the DPoP binding', async () => {
    op = await createStubProvider({ accessTokenTtl: 2 });
    const client = await newClient({ dpop: true });
    const tm = new TokenManager(client, { refreshSkewSec: 5, autoRefresh: false });
    const initial = await tm.set('s1', await signIn(client));
    assert.equal(await tm.getAccessToken('s1'), initial.access_token);
    await new Promise((r) => setTimeout(r, 1100));
    const ts = await tm.getTokenSet('s1');
    assert.notEqual(ts.access_token, initial.access_token);
    assert.equal(ts.token_type, 'DPoP');
  });

  it('coalesces concurrent refreshes (refresh-token rotation safe)', async () => {
    const client = await newClient();
    const tm = new TokenManager(client, { autoRefresh: false });
    await tm.set('s1', await signIn(client));
    const before = op.state.tokenCalls;
    const [a, b] = await Promise.all([tm.refresh('s1'), tm.refresh('s1')]);
    assert.equal(op.state.tokenCalls - before, 1);
    assert.equal(a.access_token, b.access_token);
  });

  it('refreshes automatically in the background before expiry', async () => {
    op = await createStubProvider({ accessTokenTtl: 2 });
    const client = await newClient();
    const tm = new TokenManager(client, { refreshSkewSec: 1, minRefreshDelayMs: 50 });
    const initial = await tm.set('s1', await signIn(client));
    const keepAlive = setInterval(() => {}, 100);
    try {
      const [key, refreshed] = await onceEvent(tm, 'refreshed');
      assert.equal(key, 's1');
      assert.notEqual(refreshed.access_token, initial.access_token);
    } finally {
      clearInterval(keepAlive);
      tm.close();
    }
  });

  it('drops tokens when the refresh token is revoked', async () => {
    const client = await newClient();
    const tm = new TokenManager(client, { autoRefresh: false });
    const ts = await tm.set('s1', await signIn(client));
    await client.revoke(ts.refresh_token, 'refresh_token');
    const expired = onceEvent(tm, 'expired');
    await assert.rejects(tm.refresh('s1'), (e) => e.error === 'invalid_grant');
    await expired;
    assert.equal(await tm.get('s1'), undefined);
  });
});

describe('SSF / CAEP receiver (poll)', () => {
  async function receiver(opts = {}) {
    const { dpop, ...rest } = opts;
    const client = await newClient({ dpop });
    const tokens = await signIn(client);
    return new SSFReceiver({
      transmitterIssuer: op.issuer,
      authorizationHeaders: (req) => client.resourceHeaders(tokens, req),
      fetch: op.fetch,
      pollIntervalMs: 50,
      // Quiet unless a test is about the hook: the default prints every event.
      onEventReceived: null,
      ...rest,
    });
  }
  const stream = (r) => op.state.streams.get(r.stream.stream_id);
  const waitFor = async (fn, label = 'condition') => {
    const end = Date.now() + 3000;
    while (!(await fn())) {
      if (Date.now() > end) throw new Error(`Timed out waiting for ${label}`);
      await new Promise((res) => setTimeout(res, 20));
    }
  };

  it('refuses push delivery: a browser cannot receive one', () => {
    assert.throws(() => new SSFReceiver({ transmitterIssuer: op.issuer, deliveryMethod: 'push' }), /poll/);
  });

  it('reuses an existing stream when the transmitter refuses a new one at its limit (403), preferring its own description', async () => {
    op.state.streams.clear();
    const other = await receiver({ description: 'another app', pollIntervalMs: 60_000 });
    await other.start();
    await other.stop();
    const mine = await receiver({ description: 'this app', pollIntervalMs: 60_000 });
    await mine.start();
    await mine.stop();
    const mineId = mine.stream.stream_id;
    op.state.streamLimit = 2;
    try {
      const again = await receiver({ description: 'this app', pollIntervalMs: 60_000 });
      await again.start();
      await again.stop();
      assert.equal(again.stream.stream_id, mineId);
      assert.equal(op.state.streams.size, 2);
      op.state.streams.clear();
      const none = await receiver({ description: 'this app', pollIntervalMs: 60_000 });
      op.state.streamLimit = 0;
      await assert.rejects(none.start(), (e) => e.status === 403);
    } finally {
      op.state.streamLimit = null;
      op.state.streams.clear();
    }
  });

  it('deleteOnPageHide deletes the stream with keepalive when the page goes for good, not for the back/forward cache, and is off by default', async () => {
    const listeners = new Map();
    const pageEvents = {
      addEventListener: (type, fn) => listeners.set(type, fn),
      removeEventListener: (type, fn) => { if (listeners.get(type) === fn) listeners.delete(type); },
    };
    const kept = await receiver({ pageEvents, pollIntervalMs: 60_000 });
    await kept.start();
    assert.equal(listeners.size, 0, 'off by default');
    await kept.stop({ deleteStream: true });

    const seen = [];
    const fetchSpy = (url, init) => { seen.push({ method: init?.method, keepalive: init?.keepalive }); return op.fetch(url, init); };
    const r = await receiver({ pageEvents, deleteOnPageHide: true, fetch: fetchSpy, pollIntervalMs: 60_000 });
    await r.start();
    const id = r.stream.stream_id;
    listeners.get('pagehide')({ persisted: true });
    assert.ok(op.state.streams.has(id), 'a page entering the back/forward cache keeps its stream');
    listeners.get('pagehide')({ persisted: false });
    await waitFor(() => !op.state.streams.has(id), 'the stream deleted');
    assert.ok(seen.some((x) => x.method === 'DELETE' && x.keepalive === true));
    await r.stop();
    assert.equal(listeners.size, 0, 'stop() removes the listener');
  });

  it('creates a poll stream with a DPoP-bound user token, verifies it and dispatches to named handlers', async () => {
    const got = [];
    const r = await receiver({ dpop: true });
    r.onDeviceComplianceChange((e) => got.push(e));
    op.state.requireNonce = { token: false, resource: true };
    await r.start();
    assert.match(r.stream.delivery.endpoint_url, /\/ssf\/poll\//);
    assert.equal((await r.requestVerification({ timeoutMs: 2000 })).type, SSF.VERIFICATION);
    await r.addSubject(Subject.issSub(op.issuer, 'alice'));
    stream(r).queue.set('j1', await op.makeSet(stream(r), CAEP.DEVICE_COMPLIANCE_CHANGE, { current_status: 'not-compliant' }, Subject.issSub(op.issuer, 'alice')));
    await waitFor(() => got.length === 1, 'event');
    assert.ok(subjectMatches(got[0].subject, { iss: op.issuer, sub: 'alice' }));
    await waitFor(() => stream(r).queue.size === 0, 'acknowledgement');
    await r.stop({ deleteStream: true });
    assert.equal(op.state.streams.size, 0);
  });

  it('catches up on the SETs queued while stopped before start({ catchUp }) resolves', async () => {
    const r1 = await receiver({ pollIntervalMs: 60_000 });
    await r1.start();
    await r1.stop();
    const s = stream(r1);
    s.queue.set('j1', await op.makeSet(s, CAEP.SESSION_REVOKED, {}, Subject.issSub(op.issuer, 'alice')));
    const got = [];
    const r2 = await receiver({ streamId: s.stream_id, pollIntervalMs: 60_000 });
    r2.onSessionRevoked((e) => got.push(e.name));
    await r2.start({ catchUp: true });
    assert.deepEqual(got, ['session-revoked']);
    await r2.stop({ deleteStream: true });
  });

  it('calls every CAEP handler type via constructor config', async () => {
    const seen = new Set();
    const names = ['sessionRevoked', 'tokenClaimsChange', 'credentialChange', 'assuranceLevelChange', 'deviceComplianceChange', 'sessionEstablished', 'sessionPresented', 'riskLevelChange'];
    const r = await receiver({ handlers: Object.fromEntries(names.map((n) => [n, (e) => seen.add(e.name)])) });
    await r.start();
    for (const type of Object.values(CAEP)) await r.receiveSet(await op.makeSet(stream(r), type, {}, Subject.email('bob@example.com')));
    assert.equal(seen.size, 8);
    await r.stop();
  });

  it('calls onEventReceived for every event before the typed handlers, and logs by default', async () => {
    const order = [];
    const r = await receiver({ onEventReceived: (e) => order.push(`hook:${e.name}`) });
    r.onSessionRevoked((e) => order.push(`typed:${e.name}`));
    await r.start();
    await r.receiveSet(await op.makeSet(stream(r), CAEP.SESSION_REVOKED, {}, Subject.email('bob@example.com')));
    await r.receiveSet(await op.makeSet(stream(r), CAEP.RISK_LEVEL_CHANGE, {}, Subject.email('bob@example.com')));
    assert.deepEqual(order, ['hook:session-revoked', 'typed:session-revoked', 'hook:risk-level-change']);
    await r.stop();

    const errors = [];
    const failing = await receiver({ onEventReceived: () => { throw new Error('boom'); } });
    failing.onError((err, ctx) => errors.push(`${ctx.phase}:${err.message}`));
    let typed = 0;
    failing.onSessionRevoked(() => { typed += 1; });
    await failing.start();
    await failing.receiveSet(await op.makeSet(stream(failing), CAEP.SESSION_REVOKED, {}, Subject.email('bob@example.com')));
    assert.deepEqual(errors, ['hook:boom']);
    assert.equal(typed, 1);
    await failing.stop();

    const lines = [];
    const original = console.log;
    console.log = (...args) => lines.push(args);
    try {
      const quiet = await receiver();
      const loud = await receiver({ onEventReceived: logEventReceived });
      await quiet.start();
      await loud.start();
      await quiet.receiveSet(await op.makeSet(stream(quiet), CAEP.CREDENTIAL_CHANGE, {}, Subject.email('bob@example.com')));
      await loud.receiveSet(await op.makeSet(stream(loud), CAEP.CREDENTIAL_CHANGE, {}, Subject.email('bob@example.com')));
      await quiet.stop();
      await loud.stop();
    } finally {
      console.log = original;
    }
    assert.equal(lines.length, 1);
    assert.equal(lines[0].length, 1, 'the default log line carries no event body (personal data)');
    assert.match(lines[0][0], /^\[oidc-caep-client\] CAEP event received: credential-change \(jti /);
    assert.throws(() => new SSFReceiver({ transmitterIssuer: op.issuer, onEventReceived: 'log' }), /function/);
  });

  // --- the 2026-10-26 security review --------------------------------------------------------------
  // start() polls once in the background; with a long interval, that is the only background poll.
  const settle = () => new Promise((resolve) => setTimeout(resolve, 50));
  const signSet = (s, claims, header = {}) => new SignJWT({ jti: randomUUID(), ...claims })
    .setProtectedHeader({ alg: 'RS256', kid: 'k1', typ: 'secevent+jwt', ...header })
    .setIssuer(op.issuer).setAudience(s.aud).sign(op.privateKey);
  const alice = () => Subject.issSub(op.issuer, 'alice');

  it('acts on a queued SET however old it is, and refuses only an iat in the future', async () => {
    const got = [];
    const r = await receiver({ pollIntervalMs: 60_000 });
    r.onSessionRevoked((e) => got.push(e.jti));
    await r.start();
    await settle(); // the poll start() kicks off, before this test drives poll() itself
    const s = stream(r);
    const old = await signSet(s, { iat: Math.floor(Date.now() / 1000) - 2 * 3600, sub_id: alice(), events: { [CAEP.SESSION_REVOKED]: {} } });
    const future = await signSet(s, { iat: Math.floor(Date.now() / 1000) + 3600, sub_id: alice(), events: { [CAEP.SESSION_REVOKED]: {} } });
    s.queue.set('old', old);
    s.queue.set('future', future);
    await r.poll();
    assert.equal(got.length, 1, 'the two-hour-old session-revoked is handled');
    await r.poll();
    assert.ok(!s.queue.has('old'), 'acknowledged');
    assert.deepEqual(op.state.lastPoll.ack, ['old']);
    assert.match(s.errs.future.description, /future/);
    await r.stop();
  });

  it('leaves a SET for redelivery when its signing keys cannot be fetched, instead of reporting it invalid', async () => {
    let failJwks = 1;
    const fetch = (input, init) => {
      if (String(input).endsWith('/jwks') && failJwks-- > 0) return Promise.reject(new TypeError('fetch failed: ECONNRESET'));
      return op.fetch(input, init);
    };
    const got = [];
    const errors = [];
    const r = await receiver({ fetch, pollIntervalMs: 60_000 });
    r.onSessionRevoked((e) => got.push(e.jti)).onError((err, ctx) => errors.push(ctx));
    await r.start();
    await settle(); // the poll start() kicks off, before this test drives poll() itself
    const s = stream(r);
    s.queue.set('j1', await op.makeSet(s, CAEP.SESSION_REVOKED, {}, alice()));
    await r.poll();
    assert.equal(got.length, 0);
    assert.equal(errors[0].willRetry, true);
    await r.poll();
    assert.equal(s.errs, undefined, 'nothing was reported to the transmitter as an error');
    assert.equal(got.length, 1, 'the redelivered SET is handled');
    await r.poll();
    assert.equal(s.queue.size, 0, 'and acknowledged');
    await r.stop();
  });

  it('acknowledges a SET only once its handlers succeed, and gives up after maxDeliveryAttempts', async () => {
    let calls = 0;
    const r = await receiver({ pollIntervalMs: 60_000 });
    r.onSessionRevoked(() => { calls += 1; if (calls === 1) throw new Error('storage unavailable'); });
    r.onError(() => {});
    await r.start();
    await settle(); // the poll start() kicks off, before this test drives poll() itself
    const s = stream(r);
    s.queue.set('j1', await op.makeSet(s, CAEP.SESSION_REVOKED, {}, alice()));
    await r.poll();
    await r.poll();
    assert.equal(calls, 2, 'redelivered after the handler threw, and not dropped as a replay');
    await r.poll();
    assert.equal(s.queue.size, 0);
    await r.stop();

    const errors = [];
    const r2 = await receiver({ pollIntervalMs: 60_000, maxDeliveryAttempts: 2 });
    r2.onSessionRevoked(() => { throw new Error('always'); }).onError((err) => errors.push(err.code));
    await r2.start();
    await settle(); // the poll start() kicks off, before this test drives poll() itself
    const s2 = stream(r2);
    s2.queue.set('j2', await op.makeSet(s2, CAEP.SESSION_REVOKED, {}, alice()));
    await r2.poll();
    await r2.poll();
    await r2.poll();
    assert.ok(errors.includes('handler_failed'));
    assert.equal(s2.queue.size, 0);
    await r2.stop();
  });

  it('reports a handler failure on the console when no onError is registered', async () => {
    const lines = [];
    const original = console.error;
    console.error = (...args) => lines.push(args.join(' '));
    try {
      const r = await receiver();
      r.onSessionRevoked(() => { throw new Error('boom'); });
      await r.start();
      await r.receiveSet(await op.makeSet(stream(r), CAEP.SESSION_REVOKED, {}, alice()));
      await r.stop();
    } finally {
      console.error = original;
    }
    assert.ok(lines.some((l) => /handler: boom/.test(l)), lines.join('\n'));
  });

  it('sends acknowledgements still owed when stopped', async () => {
    const r = await receiver({ pollIntervalMs: 60_000 });
    r.onSessionRevoked(() => {});
    await r.start();
    await settle(); // the poll start() kicks off, before this test drives poll() itself
    const s = stream(r);
    s.queue.set('j1', await op.makeSet(s, CAEP.SESSION_REVOKED, {}, alice()));
    await r.poll();
    await r.stop();
    assert.deepEqual(op.state.lastPoll.ack, ['j1']);
    assert.equal(op.state.lastPoll.maxEvents, 0);
    assert.equal(s.queue.size, 0);
  });

  it('never sends the access token to a poll endpoint off the transmitter, or to an http SSF URL', async () => {
    const seen = [];
    const fetch = (input, init) => { seen.push(String(input)); return op.fetch(input, init); };
    const r = await receiver({ fetch, pollIntervalMs: 60_000 });
    await r.start();
    await settle(); // the poll start() kicks off, before this test drives poll() itself
    r.stream.delivery.endpoint_url = 'https://evil.example/poll';
    await assert.rejects(r.poll(), (e) => e.code === 'untrusted_endpoint');
    r.stream.delivery.endpoint_url = `${op.issuer.replace('https:', 'http:')}/ssf/poll/x`;
    await assert.rejects(r.poll(), (e) => e.code === 'insecure_endpoint');
    assert.ok(!seen.some((u) => u.startsWith('https://evil.example') || u.startsWith('http:')));
    await r.stop();

    const httpJwks = async (input, init) => {
      const res = await op.fetch(input, init);
      if (!String(input).endsWith('/.well-known/ssf-configuration')) return res;
      return new Response(JSON.stringify({ ...(await res.json()), jwks_uri: 'http://op.test/jwks' }), { headers: { 'content-type': 'application/json' } });
    };
    clearDiscoveryCache();
    const r2 = await receiver({ fetch: httpJwks });
    await assert.rejects(r2.discover(), (e) => e.code === 'insecure_endpoint');
    await assert.rejects(new SSFReceiver({ transmitterIssuer: 'http://op.test' }).discover(), (e) => e.code === 'insecure_endpoint');
  });

  it('refuses a SET with more than one event, and a stream event about another stream', async () => {
    const r = await receiver();
    await r.start();
    const s = stream(r);
    const two = await signSet(s, { iat: Math.floor(Date.now() / 1000), sub_id: alice(),
      events: { [CAEP.SESSION_REVOKED]: {}, [CAEP.CREDENTIAL_CHANGE]: { credential_type: 'password', change_type: 'update' } } });
    await assert.rejects(r.receiveSet(two), /exactly one event/);
    const otherStream = await signSet(s, { iat: Math.floor(Date.now() / 1000), sub_id: { format: 'opaque', id: 'another-stream' },
      events: { [SSF.STREAM_UPDATED]: { status: 'disabled' } } });
    await assert.rejects(r.receiveSet(otherStream), /not about this stream/);
    assert.equal(r.stream.status, 'enabled');
    const notOpaque = await signSet(s, { iat: Math.floor(Date.now() / 1000), sub_id: alice(), events: { [SSF.VERIFICATION]: { state: 'x' } } });
    await assert.rejects(r.receiveSet(notOpaque), /not about this stream/);
    await r.stop();
  });

  it('never acknowledges a SET whose handler is still running when another poll receives it', async () => {
    let release;
    const gate = new Promise((r) => { release = r; });
    let calls = 0;
    const r = await receiver({ pollIntervalMs: 60_000 });
    r.onSessionRevoked(async () => {
      calls += 1;
      if (calls === 1) {
        await gate;
        throw new Error('storage unavailable');
      }
    }).onError(() => {});
    await r.start();
    await settle();
    const s = stream(r);
    s.queue.set('j1', await op.makeSet(s, CAEP.SESSION_REVOKED, {}, alice()));
    const first = r.poll();
    await new Promise((res) => setTimeout(res, 20));
    const second = r.poll();
    r.pollNow();
    // Long enough for an overlapping poll to receive j1 again while its first handling is still running.
    await new Promise((res) => setTimeout(res, 20));
    release();
    await Promise.all([first, second]);
    assert.equal(s.queue.has('j1'), true, 'not acknowledged: its handler failed');
    await r.poll();
    assert.equal(calls, 2, 'redelivered and handled');
    await r.poll();
    assert.equal(s.queue.size, 0, 'acknowledged once handled');
    await r.stop();
  });

  it('pollNow() during a poll does not start a second poll loop', async () => {
    let polls = 0;
    // Each poll takes 30 ms, so the pollNow() calls below land while one is in flight.
    const fetch = async (input, init) => {
      if (String(input).includes('/ssf/poll/')) {
        polls += 1;
        await new Promise((res) => setTimeout(res, 30));
      }
      return op.fetch(input, init);
    };
    const r = await receiver({ fetch, pollIntervalMs: 100 });
    await r.start();
    for (let i = 0; i < 5; i++) {
      await new Promise((res) => setTimeout(res, 10));
      r.pollNow();
      await new Promise((res) => setTimeout(res, 120));
    }
    polls = 0;
    await new Promise((res) => setTimeout(res, 1000));
    await r.stop();
    // One loop: a poll every 100 ms plus 30 ms for the request, about 8 a second.
    assert.ok(polls <= 10, `one poll loop, not ${polls} polls a second`);
  });

  it('never reports a SET it could not check for a passing reason, however many polls that takes', async () => {
    let failJwks = 8;
    const fetch = (input, init) => {
      if (String(input).endsWith('/jwks') && failJwks-- > 0) return Promise.reject(new TypeError('fetch failed: network down'));
      return op.fetch(input, init);
    };
    const got = [];
    const r = await receiver({ fetch, pollIntervalMs: 60_000, maxDeliveryAttempts: 2 });
    r.onSessionRevoked((e) => got.push(e.jti)).onError(() => {});
    await r.start();
    await settle();
    const s = stream(r);
    s.queue.set('j1', await op.makeSet(s, CAEP.SESSION_REVOKED, {}, alice()));
    for (let i = 0; i < 8; i++) await r.poll();
    assert.equal(s.errs, undefined, 'not reported to the transmitter');
    assert.equal(got.length, 0);
    await r.poll();
    assert.equal(got.length, 1, 'handled once the keys can be fetched');
    await r.stop();
  });

  it('catches a rejection from an async onError handler', async () => {
    const unhandled = [];
    const onUnhandled = (err) => unhandled.push(err);
    process.on('unhandledRejection', onUnhandled);
    try {
      const r = await receiver();
      r.onSessionRevoked(() => { throw new Error('boom'); });
      r.onError(async () => { throw new Error('error handler failed'); });
      await r.start();
      await r.receiveSet(await op.makeSet(stream(r), CAEP.SESSION_REVOKED, {}, alice()));
      await new Promise((res) => setTimeout(res, 20));
      await r.stop();
    } finally {
      process.off('unhandledRejection', onUnhandled);
    }
    assert.deepEqual(unhandled, []);
  });

  it('validates SETs: signature, audience, typ, age, replay', async () => {
    const r = await receiver({ maxSetAgeSec: 600 });
    await r.start();
    const { privateKey } = await generateKeyPair('RS256');
    const forged = await new SignJWT({ jti: 'x', events: { [CAEP.SESSION_REVOKED]: {} } }).setProtectedHeader({ alg: 'RS256', kid: 'k1', typ: 'secevent+jwt' })
      .setIssuer(op.issuer).setAudience(r.stream.aud).setIssuedAt().sign(privateKey);
    await assert.rejects(r.receiveSet(forged), (e) => e instanceof SETValidationError && e.code === 'invalid_key');
    await assert.rejects(r.receiveSet(await op.makeSet({ ...stream(r), aud: 'other' }, CAEP.SESSION_REVOKED, {}, Subject.opaque('x'))), (e) => e.code === 'invalid_audience');
    const old = await new SignJWT({ jti: randomUUID(), events: { [CAEP.SESSION_REVOKED]: {} } }).setProtectedHeader({ alg: 'RS256', kid: 'k1', typ: 'secevent+jwt' })
      .setIssuer(op.issuer).setAudience(r.stream.aud).setIssuedAt(Math.floor(Date.now() / 1000) - 3600).sign(op.privateKey);
    await assert.rejects(r.receiveSet(old), /too old/);
    const wrongTyp = await new SignJWT({ jti: 'y', events: { [CAEP.SESSION_REVOKED]: {} } }).setProtectedHeader({ alg: 'RS256', kid: 'k1', typ: 'JWT' })
      .setIssuer(op.issuer).setAudience(r.stream.aud).setIssuedAt().sign(op.privateKey);
    await assert.rejects(r.receiveSet(wrongTyp), /typ/);
    const set = await op.makeSet(stream(r), CAEP.CREDENTIAL_CHANGE, {}, Subject.opaque('x'));
    assert.equal((await r.receiveSet(set)).length, 1);
    assert.deepEqual(await r.receiveSet(set), []);
    r.stream = { ...r.stream, aud: undefined };
    await assert.rejects(r.receiveSet(await op.makeSet(stream(r), CAEP.SESSION_REVOKED, {}, Subject.opaque('x'))), /No expected SET audience/);
    await r.stop();
  });

  it('manages stream status', async () => {
    const r = await receiver();
    await r.start();
    assert.equal((await r.getStatus()).status, 'enabled');
    assert.equal((await r.updateStatus('paused')).status, 'paused');
    await r.stop();
  });
});

describe('subjectMatches', () => {
  it('matches the RFC 9493 formats', () => {
    const id = { iss: 'https://op', sub: 'u1', email: 'A@x.com', email_verified: true, sid: 's9' };
    assert.ok(subjectMatches(Subject.issSub('https://op', 'u1'), id));
    assert.ok(!subjectMatches(Subject.issSub('https://other', 'u1'), id));
    assert.ok(subjectMatches(Subject.email('a@X.com'), id));
    assert.ok(subjectMatches(Subject.opaque('u1'), id));
    assert.ok(subjectMatches(Subject.aliases(Subject.email('no@x'), Subject.issSub('https://op', 'u1')), id));
    assert.ok(subjectMatches(Subject.complex({ user: Subject.issSub('https://op', 'u1'), session: Subject.opaque('s9') }), id));
    assert.ok(!subjectMatches(Subject.complex({ user: Subject.issSub('https://op', 'u1'), session: Subject.opaque('s1') }), id));
  });

  it('refuses subjects that could name somebody else', () => {
    const id = { iss: 'https://op', sub: 'u1', email: 'a@x.com', phone_number: '+15550100', sid: 's9' };
    // An email or phone number the OP did not verify identifies nobody (OIDC Core §5.7).
    assert.ok(!subjectMatches(Subject.email('a@x.com'), id));
    assert.ok(!subjectMatches(Subject.phone('+15550100'), id));
    assert.ok(!subjectMatches(Subject.account('acct:a@x.com'), id));
    assert.ok(subjectMatches(Subject.phone('+15550100'), { ...id, phone_number_verified: true }));
    // A session-scoped event matches only an identity holding that session.
    const sessionEvent = Subject.complex({ user: Subject.issSub('https://op', 'u1'), session: Subject.opaque('s9') });
    assert.ok(!subjectMatches(sessionEvent, { ...id, sid: undefined }));
    // An opaque id must be a string, and a top-level one is a subject, not a session.
    assert.ok(!subjectMatches({ format: 'opaque' }, { sub: 'u1' }));
    assert.ok(!subjectMatches({ format: 'opaque' }, { iss: 'https://op', sub: undefined }));
    assert.ok(!subjectMatches(Subject.opaque('s9'), id));
    assert.ok(!subjectMatches(Subject.complex({ user: Subject.issSub('https://op', 'u1'), session: { format: 'opaque' } }), id));
  });
});

describe('security review fixes (client)', () => {
  // Rewrites one endpoint's JSON answer.
  const rewrite = (path, change) => async (input, init) => {
    const res = await op.fetch(input, init);
    if (new URL(String(input)).pathname !== path || !res.ok) return res;
    const body = change(await res.json());
    return new Response(typeof body === 'string' ? body : JSON.stringify(body), { status: res.status, headers: { 'content-type': 'application/json' } });
  };

  it('refuses a refreshed ID token whose aud or azp changed (OIDC Core §12.2)', async () => {
    let swap = false;
    const fetch = async (input, init) => {
      const res = await op.fetch(input, init);
      if (!swap || !String(input).endsWith('/token')) return res;
      const body = await res.json();
      body.id_token = await new SignJWT({ sub: 'alice', azp: op.clientId, auth_time: Math.floor(Date.now() / 1000),
        at_hash: createHash('sha256').update(body.access_token).digest().subarray(0, 16).toString('base64url') })
        .setProtectedHeader({ alg: 'RS256', kid: 'k1' }).setIssuer(op.issuer).setAudience([op.clientId, 'another-api'])
        .setIssuedAt().setExpirationTime('5m').sign(op.privateKey);
      return new Response(JSON.stringify(body), { headers: { 'content-type': 'application/json' } });
    };
    const client = await newClient({ fetch });
    const tokens = await signIn(client);
    swap = true;
    await assert.rejects(client.refresh(tokens), (e) => e.code === 'invalid_id_token' && /(azp|aud) changed/.test(e.message));
  });

  it('refuses an ID token from a refresh with no previous claims to hold it to', async () => {
    const client = await newClient();
    const tokens = await signIn(client);
    await assert.rejects(client.refresh(tokens.refresh_token), (e) => e.code === 'invalid_id_token' && /previousClaims/.test(e.message));
    const again = await signIn(client);
    assert.equal((await client.refresh(again.refresh_token, { previousClaims: again.claims })).claims.sub, 'alice');
  });

  it('refuses a Bearer token when DPoP is on, and never refreshes DPoP-bound tokens into Bearer ones', async () => {
    let downgrade = false;
    const fetch = rewrite('/token', (b) => (downgrade ? { ...b, token_type: 'Bearer' } : b));
    const client = await newClient({ dpop: true, fetch });
    const tokens = await signIn(client);
    downgrade = true;
    await assert.rejects(client.refresh(tokens), (e) => e.code === 'dpop_downgrade');
    await assert.rejects(signIn(client), (e) => e.code === 'dpop_downgrade');
    const lenient = await newClient({ dpop: true, requireDpop: false, fetch });
    const signedIn = await signIn(lenient);
    assert.equal(signedIn.token_type, 'Bearer');
  });

  it('checks the UserInfo sub against the ID token by default, and refuses a non-object answer', async () => {
    let mode = 'other';
    const fetch = rewrite('/userinfo', (b) => (mode === 'other' ? { ...b, sub: 'mallory' } : 'null'));
    const client = await newClient({ fetch });
    const tokens = await signIn(client);
    await assert.rejects(client.userinfo(tokens), (e) => e.code === 'sub_mismatch');
    await assert.rejects(client.userinfo(tokens.access_token), (e) => e.code === 'sub_mismatch' && /expectedSub/.test(e.message));
    mode = 'null';
    await assert.rejects(client.userinfo(tokens), (e) => e.code === 'invalid_userinfo');
  });

  it('requires TLS for registration, registration management and a per-request logout redirect', async () => {
    await assert.rejects(registerClient({ registration_endpoint: 'http://op.example/register' }, { redirect_uris: [REDIRECT] }),
      (e) => e.code === 'insecure_endpoint');
    const { readClientRegistration } = await import('../src/index.js');
    await assert.rejects(readClientRegistration({ registration_client_uri: 'http://op.example/reg/1', registration_access_token: 'rat' }),
      (e) => e.code === 'insecure_endpoint');
    const client = await newClient();
    await assert.rejects(client.createEndSessionRequest({ postLogoutRedirectUri: 'http://evil.example/' }), (e) => e.code === 'insecure_redirect_uri');
  });

  it('builds a TokenSet without letting the response set its prototype, claims or expiry', async () => {
    const { TokenSet } = await import('../src/index.js');
    const ts = new TokenSet(JSON.parse('{"access_token":"a","token_type":"Bearer","__proto__":{"polluted":true},"claims":{"sub":"evil"},"expires_in":60}'));
    assert.ok(ts instanceof TokenSet);
    assert.equal(typeof ts.isExpired, 'function');
    assert.equal(ts.polluted, undefined);
    assert.equal(ts.claims, undefined);
    const client = await newClient({ fetch: rewrite('/token', (b) => ({ ...b, expires_at: 1, issued_at: 1 })) });
    const tokens = await signIn(client);
    assert.ok(tokens.expires_at > Math.floor(Date.now() / 1000), 'expires_at comes from expires_in, not the response');
  });

  it('keeps AccountManager tokens in memory without DPoP, and warns about a persistent store without it', async () => {
    const warnings = [];
    const original = console.warn;
    console.warn = (...args) => warnings.push(args.join(' '));
    try {
      const storage = new Map();
      const fakeStorage = { getItem: (k) => storage.get(k) ?? null, setItem: (k, v) => storage.set(k, v), removeItem: (k) => storage.delete(k),
        key: (i) => [...storage.keys()][i] ?? null, get length() { return storage.size; } };
      const { WebStorageTokenStore } = await import('../src/index.js');
      new AccountManager(await newClient(), { store: new WebStorageTokenStore({ storage: fakeStorage }), broadcast: false });
      assert.equal(warnings.length, 1);
      new AccountManager(await newClient({ dpop: true }), { store: new WebStorageTokenStore({ storage: fakeStorage }), broadcast: false });
      new AccountManager(await newClient(), { store: new MemoryTokenStore(), broadcast: false });
      assert.equal(warnings.length, 1);
    } finally {
      console.warn = original;
    }
  });

  it('a delete waits for a refresh in flight, so the refresh cannot write the tokens back', async () => {
    let release;
    const gate = new Promise((r) => { release = r; });
    let hold = false;
    const fetch = async (input, init) => {
      if (hold && String(input).endsWith('/token')) await gate;
      return op.fetch(input, init);
    };
    const client = await newClient({ fetch });
    const tm = new TokenManager(client, { autoRefresh: false });
    await tm.set('u', await signIn(client), { schedule: false });
    hold = true;
    const refreshing = tm.refresh('u').catch(() => {});
    await new Promise((r) => setTimeout(r, 10));
    const deleting = tm.delete('u');
    release();
    await Promise.all([refreshing, deleting]);
    assert.equal(await tm.get('u'), undefined);
    tm.close();
  });
});

describe('second security review fixes (client)', () => {
  it('refuses extraParams that would replace the parameters the client sets, and passes others through', async () => {
    const client = await newClient({ dpop: true });
    for (const name of ['response_type', 'code_challenge_method', 'redirect_uri', 'state', 'dpop_jkt']) {
      await assert.rejects(client.createAuthorizationRequest({ extraParams: { [name]: 'x' } }), (e) => e instanceof TypeError && e.message.includes(name));
    }
    const claims = JSON.stringify({ id_token: { email: null } });
    await client.createAuthorizationRequest({ extraParams: { claims } });
    assert.equal(op.state.par.size ? [...op.state.par.values()].pop().get('claims') : op.state.lastAuthorize?.get('claims'), claims);
  });

  it('keeps TokenSet methods whatever the response contains, and never decodes an unverified ID token', async () => {
    const { TokenSet } = await import('../src/index.js');
    const ts = new TokenSet({ access_token: 'a', token_type: 'Bearer', expires_in: 60, isExpired: true, toJSON: 'x', expiresIn: 1 });
    assert.equal(ts.isExpired(), false);
    assert.equal(typeof ts.toJSON(), 'object');
    const client = await newClient();
    const signedIn = await signIn(client);
    const stored = TokenSet.from({ ...signedIn.toJSON(), claims: undefined });
    assert.equal(stored.claims, undefined, 'the id_token is not decoded without validation');
    await assert.rejects(client.userinfo(stored), (e) => e.code === 'sub_mismatch');
  });

  it('keeps the authorization server\'s and a resource server\'s DPoP nonces apart on one origin', async () => {
    const client = await newClient({ dpop: true });
    op.state.requireNonce = { token: true, resource: true };
    op.state.nonces = { token: 'n-token', resource: 'n-resource' };
    const tokens = await signIn(client);
    await client.userinfo(tokens);
    const before = op.state.tokenCalls;
    await client.refresh(tokens);
    assert.equal(op.state.tokenCalls - before, 1, 'the refresh presents the token endpoint\'s nonce, with no retry');
  });

  it('reports a failing listener without rethrowing it', async () => {
    const { Emitter } = await import('../src/index.js');
    const lines = [];
    const original = console.error;
    console.error = (...args) => lines.push(args.join(' '));
    const uncaught = [];
    const onUncaught = (err) => uncaught.push(err);
    process.on('uncaughtException', onUncaught);
    try {
      const e = new Emitter();
      const seen = [];
      e.on('x', () => { throw new Error('first'); });
      e.on('x', async () => { throw new Error('second'); });
      e.on('x', () => seen.push('third'));
      e.emit('x');
      await new Promise((res) => setTimeout(res, 10));
      assert.deepEqual(seen, ['third']);
    } finally {
      console.error = original;
      process.off('uncaughtException', onUncaught);
    }
    assert.deepEqual(uncaught, []);
    assert.equal(lines.length, 2);
  });
});

describe('browser compatibility', () => {
  it('the library imports no Node.js built-ins', async () => {
    const { readdir, readFile } = await import('node:fs/promises');
    const { join } = await import('node:path');
    const root = new URL('../src/', import.meta.url).pathname;
    for (const dir of ['', 'caep/']) {
      for (const f of await readdir(join(root, dir))) {
        if (!f.endsWith('.js')) continue;
        const text = await readFile(join(root, dir, f), 'utf8');
        assert.doesNotMatch(text, /from ['"]node:|require\(|\bBuffer\b|\bprocess\./, join(dir, f));
      }
    }
  });
});
