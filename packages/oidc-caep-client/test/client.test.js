import assert from 'node:assert/strict';
import { createHash, randomUUID } from 'node:crypto';
import { beforeEach, describe, it } from 'node:test';
import { calculateJwkThumbprint, decodeProtectedHeader, exportJWK, generateKeyPair, importJWK, jwtVerify, SignJWT } from 'jose';
import {
  CAEP, clearDiscoveryCache, OAuthError, OIDCClient, registerClient, SETValidationError, SSF, SSFReceiver, Subject,
  subjectMatches, TokenManager, TransactionStore,
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

  async function idToken(sub, { nonce, accessToken, authTime, typ, iat }) {
    return new SignJWT({ nonce, at_hash: createHash('sha256').update(accessToken).digest().subarray(0, 16).toString('base64url'), auth_time: authTime, acr: state.acr, email: `${sub}@example.com` })
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
      if (state.requireNonce[where] && payload.nonce !== state.nonce) return { error: 'use_dpop_nonce' };
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

  const nonceChallenge = () => new Response(null, { status: 401, headers: { 'www-authenticate': 'DPoP error="use_dpop_nonce"', 'dpop-nonce': state.nonce } });

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
      if (proof.error === 'use_dpop_nonce') return json({ error: 'use_dpop_nonce' }, 400, { 'dpop-nonce': state.nonce });
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
        state.refreshTokens.set(rt, { sub: code.sub, authTime: code.authTime, jkt: proof.jkt, scope: code.scope });
        return json({ access_token: at, token_type: tokenType, expires_in: accessTokenTtl, refresh_token: rt, scope: code.scope,
          id_token: await idToken(code.sub, { nonce: code.nonce, accessToken: at, authTime: code.authTime }) });
      }
      if (form.get('grant_type') === 'refresh_token') {
        const rt = state.refreshTokens.get(form.get('refresh_token'));
        if (!rt || rt.jkt !== proof.jkt) return json({ error: 'invalid_grant' }, 400);
        state.refreshTokens.delete(form.get('refresh_token'));
        const at = issue(rt.sub, rt.scope);
        const next = `rt-${rnd()}`;
        state.refreshTokens.set(next, rt);
        return json({ access_token: at, token_type: tokenType, expires_in: accessTokenTtl, refresh_token: next,
          id_token: await idToken(rt.sub, { accessToken: at, authTime: rt.authTime }) });
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
        const id = rnd();
        const stream = { stream_id: id, iss: issuer, aud: clientId, delivery: { method: data.delivery.method, endpoint_url: `${issuer}/ssf/poll/${id}` },
          events_requested: data.events_requested, events_delivered: data.events_requested, status: 'enabled', subjects: [], queue: new Map() };
        state.streams.set(id, stream);
        const { subjects, queue, ...pub } = stream;
        return json(pub, 201);
      }
      const stream = state.streams.get(u.searchParams.get('stream_id') ?? data.stream_id ?? p.split('/').pop());
      if (!stream) return json({ error: 'not_found' }, 404);
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
        authTime: now(), dpopJkt: q.get('dpop_jkt'), scope: q.get('scope') });
      return `${q.get('redirect_uri')}?${new URLSearchParams({ code, state: q.get('state'), iss: issuer })}`;
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
    await assert.rejects(client.userinfo(tokens.access_token), (e) => e.status === 401);
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

  it('calls every CAEP handler type via constructor config', async () => {
    const seen = new Set();
    const names = ['sessionRevoked', 'tokenClaimsChange', 'credentialChange', 'assuranceLevelChange', 'deviceComplianceChange', 'sessionEstablished', 'sessionPresented', 'riskLevelChange'];
    const r = await receiver({ handlers: Object.fromEntries(names.map((n) => [n, (e) => seen.add(e.name)])) });
    await r.start();
    for (const type of Object.values(CAEP)) await r.receiveSet(await op.makeSet(stream(r), type, {}, Subject.email('bob@example.com')));
    assert.equal(seen.size, 8);
    await r.stop();
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
    const id = { iss: 'https://op', sub: 'u1', email: 'A@x.com', sid: 's9' };
    assert.ok(subjectMatches(Subject.issSub('https://op', 'u1'), id));
    assert.ok(!subjectMatches(Subject.issSub('https://other', 'u1'), id));
    assert.ok(subjectMatches(Subject.email('a@X.com'), id));
    assert.ok(subjectMatches(Subject.opaque('s9'), id));
    assert.ok(subjectMatches(Subject.aliases(Subject.email('no@x'), Subject.issSub('https://op', 'u1')), id));
    assert.ok(subjectMatches(Subject.complex({ user: Subject.issSub('https://op', 'u1'), session: Subject.opaque('s9') }), id));
    assert.ok(!subjectMatches(Subject.complex({ user: Subject.issSub('https://op', 'u1'), session: Subject.opaque('s1') }), id));
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
