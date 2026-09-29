import assert from 'node:assert/strict';
import { createHash, randomUUID } from 'node:crypto';
import { once } from 'node:events';
import { Readable } from 'node:stream';
import { afterEach, beforeEach, describe, it } from 'node:test';
import { exportJWK, generateKeyPair, SignJWT } from 'jose';
import {
  CAEP, clearDiscoveryCache, OAuthError, OIDCClient, registerClient, SETValidationError, SSF, SSFReceiver, Subject, subjectMatches, TokenManager, ValidationError,
} from '../src/index.js';

/**
 * In-memory test double for an OpenID Provider + SSF transmitter, injected through the library's `fetch`
 * option. No network, no server: each test gets a fresh one.
 */
async function createStubProvider({ issuer = 'https://op.test', accessTokenTtl = 3600, registrationOverride = {} } = {}) {
  const { privateKey, publicKey } = await generateKeyPair('RS256');
  const kid = 'k1';
  const jwks = { keys: [{ ...(await exportJWK(publicKey)), kid, alg: 'RS256', use: 'sig' }] };
  const client = { id: 'rp', secret: 's3cret' };
  const state = { registrations: [], codes: new Map(), accessTokens: new Set(), refreshTokens: new Map(), tokenCalls: 0, streams: new Map(), verifications: [] };
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
    grant_types_supported: ['authorization_code', 'refresh_token', 'client_credentials'],
    scopes_supported: ['openid', 'profile', 'email', 'offline_access'],
    response_types_supported: ['code'],
    subject_types_supported: ['public'],
    id_token_signing_alg_values_supported: ['RS256', 'ES256'],
    token_endpoint_auth_methods_supported: ['client_secret_basic', 'client_secret_post'],
    authorization_response_iss_parameter_supported: true,
  };
  const ssfMetadata = {
    spec_version: '1_0',
    issuer,
    jwks_uri: `${issuer}/jwks`,
    delivery_methods_supported: ['urn:ietf:rfc:8935', 'urn:ietf:rfc:8936'],
    configuration_endpoint: `${issuer}/ssf/stream`,
    status_endpoint: `${issuer}/ssf/status`,
    add_subject_endpoint: `${issuer}/ssf/subjects/add`,
    remove_subject_endpoint: `${issuer}/ssf/subjects/remove`,
    verification_endpoint: `${issuer}/ssf/verify`,
  };

  const json = (body, status = 200) => new Response(body === undefined ? null : JSON.stringify(body), { status, headers: { 'content-type': 'application/json' } });
  const sign = (claims, typ, sub) => {
    const jwt = new SignJWT(claims).setProtectedHeader({ alg: 'RS256', kid, typ }).setIssuer(issuer).setIssuedAt();
    if (sub) jwt.setSubject(sub);
    return jwt;
  };
  const atHash = (at) => createHash('sha256').update(at).digest().subarray(0, 16).toString('base64url');

  async function idToken(sub, { nonce, accessToken, authTime }) {
    return sign({ nonce, at_hash: atHash(accessToken), auth_time: authTime, email: `${sub}@example.com` }, 'JWT', sub)
      .setAudience(client.id).setExpirationTime('5m').sign(privateKey);
  }

  function clientAuth(headers, form) {
    const basic = /^Basic (.+)$/.exec(headers.get('authorization') ?? '')?.[1];
    const [id, secret] = basic ? Buffer.from(basic, 'base64').toString().split(':').map(decodeURIComponent) : [form.get('client_id'), form.get('client_secret')];
    return id === client.id && secret === client.secret;
  }

  function bearerOk(headers) {
    return state.accessTokens.has(/^Bearer (.+)$/.exec(headers.get('authorization') ?? '')?.[1]);
  }

  /** Builds a SET for a stream, as the transmitter would. */
  async function makeSet(stream, eventType, payload, subId) {
    return sign({ jti: rnd(), sub_id: subId, events: { [eventType]: payload } }, 'secevent+jwt')
      .setAudience(stream.aud).sign(privateKey);
  }

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

    if (p === '/token') {
      state.tokenCalls++;
      if (!clientAuth(headers, form)) return json({ error: 'invalid_client' }, 401);
      const grant = form.get('grant_type');
      const issue = () => {
        const at = rnd();
        state.accessTokens.add(at);
        return at;
      };
      if (grant === 'authorization_code') {
        const code = state.codes.get(form.get('code'));
        state.codes.delete(form.get('code'));
        if (!code || code.redirectUri !== form.get('redirect_uri')) return json({ error: 'invalid_grant' }, 400);
        if (createHash('sha256').update(form.get('code_verifier') ?? '').digest('base64url') !== code.challenge) {
          return json({ error: 'invalid_grant', error_description: 'PKCE' }, 400);
        }
        const at = issue();
        const rt = rnd();
        state.refreshTokens.set(rt, { sub: code.sub, authTime: code.authTime });
        return json({ access_token: at, token_type: 'Bearer', expires_in: accessTokenTtl, refresh_token: rt, id_token: await idToken(code.sub, { nonce: code.nonce, accessToken: at, authTime: code.authTime }) });
      }
      if (grant === 'refresh_token') {
        const rt = state.refreshTokens.get(form.get('refresh_token'));
        if (!rt) return json({ error: 'invalid_grant' }, 400);
        state.refreshTokens.delete(form.get('refresh_token'));
        const at = issue();
        const next = rnd();
        state.refreshTokens.set(next, rt);
        return json({ access_token: at, token_type: 'Bearer', expires_in: accessTokenTtl, refresh_token: next, id_token: await idToken(rt.sub, { accessToken: at, authTime: rt.authTime }) });
      }
      if (grant === 'client_credentials') return json({ access_token: issue(), token_type: 'Bearer', expires_in: accessTokenTtl });
      return json({ error: 'unsupported_grant_type' }, 400);
    }

    if (p === '/register' && method === 'POST') {
      state.registrations.push({ body: data, authorization: headers.get('authorization') });
      const reg = {
        ...data,
        client_id: `dyn-${state.registrations.length}`,
        client_secret: 'dyn-secret',
        registration_access_token: 'rat',
        registration_client_uri: `${issuer}/register/dyn-${state.registrations.length}`,
        ...registrationOverride,
      };
      return json(reg, 201);
    }

    if (p === '/userinfo') {
      if (!bearerOk(headers)) return new Response(null, { status: 401, headers: { 'www-authenticate': 'Bearer error="invalid_token"' } });
      return json({ sub: 'alice', email: 'alice@example.com' });
    }
    if (p === '/revoke') {
      state.refreshTokens.delete(form.get('token'));
      state.accessTokens.delete(form.get('token'));
      return new Response(null, { status: 200 });
    }

    if (p.startsWith('/ssf/')) {
      if (!bearerOk(headers)) return json({ error: 'invalid_token' }, 401);
      if (p === '/ssf/stream' && method === 'POST') {
        const id = rnd();
        const delivery = data.delivery.method.endsWith('8936') ? { method: data.delivery.method, endpoint_url: `${issuer}/ssf/poll/${id}` } : data.delivery;
        const stream = { stream_id: id, iss: issuer, aud: client.id, delivery, events_requested: data.events_requested, events_delivered: data.events_requested, status: 'enabled', subjects: [], queue: new Map() };
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
        state.verifications.push(data.state);
        if (stream.delivery.method.endsWith('8936')) {
          const set = await makeSet(stream, SSF.VERIFICATION, { state: data.state }, { format: 'opaque', id: stream.stream_id });
          stream.queue.set(rnd(), set);
        }
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
    issuer,
    client,
    metadata,
    state,
    privateKey,
    makeSet,
    fetch: (input, init) => handle(String(input instanceof Request ? input.url : input), init),
    /** Simulates the user authenticating at the authorization endpoint; returns the redirect back to the RP. */
    authorize(authorizationUrl, sub = 'alice') {
      const q = new URL(authorizationUrl).searchParams;
      const code = rnd();
      state.codes.set(code, { sub, nonce: q.get('nonce'), challenge: q.get('code_challenge'), redirectUri: q.get('redirect_uri'), authTime: now() });
      return new URLSearchParams({ code, state: q.get('state'), iss: issuer });
    },
  };
}

let op;
beforeEach(async () => {
  clearDiscoveryCache();
  op = await createStubProvider();
});

const REDIRECT = 'https://rp.test/callback';
const newClient = (extra = {}) => OIDCClient.discover({
  issuer: op.issuer, clientId: op.client.id, clientSecret: op.client.secret, redirectUri: REDIRECT, fetch: op.fetch, ...extra,
});

async function signIn(client, sub) {
  const { url, transaction } = client.authorizationUrl();
  return client.callback(op.authorize(url, sub), transaction);
}

describe('configuration', () => {
  it('discovers OP metadata', async () => {
    const client = await newClient();
    assert.equal(client.metadata.issuer, op.issuer);
    assert.match(client.config.scope, /offline_access/);
    assert.equal(client.config.tokenEndpointAuthMethod, 'client_secret_basic');
  });

  it('configures from a supplied metadata document without discovery', async () => {
    let calls = 0;
    const counting = (url, init) => {
      if (String(url).includes('openid-configuration')) calls++;
      return op.fetch(url, init);
    };
    const client = await OIDCClient.fromMetadata(op.metadata, { clientId: op.client.id, clientSecret: op.client.secret, redirectUri: REDIRECT, fetch: counting });
    assert.equal(calls, 0);
    const tokens = await signIn(client);
    assert.equal(tokens.claims.sub, 'alice');
  });

  it('rejects incomplete metadata documents', async () => {
    const { jwks_uri: _, ...incomplete } = op.metadata;
    await assert.rejects(OIDCClient.fromMetadata(incomplete, { clientId: 'x' }), /missing required fields: jwks_uri/);
    await assert.rejects(OIDCClient.fromMetadata({ ...op.metadata, response_types_supported: ['id_token'] }, { clientId: 'x' }), /response_type=code/);
  });

  it('refuses an ID token algorithm it cannot verify', async () => {
    const metadata = { ...op.metadata, id_token_signing_alg_values_supported: ['RS256', 'ML-DSA-65'] };
    await assert.rejects(OIDCClient.fromMetadata(metadata, { clientId: 'x', idTokenSignedResponseAlg: 'ML-DSA-65' }), /ML-DSA-65 cannot be verified/);
  });

  it('uses no client authentication when there is no secret', async () => {
    const client = await OIDCClient.fromMetadata(op.metadata, { clientId: 'public-app' });
    assert.equal(client.config.tokenEndpointAuthMethod, 'none');
  });

  it('rejects discovery metadata whose issuer does not match', async () => {
    await assert.rejects(
      OIDCClient.discover({ issuer: `${op.issuer}/`, clientId: 'x', fetch: op.fetch }),
      (err) => err instanceof ValidationError && err.code === 'issuer_mismatch',
    );
  });
});

describe('dynamic client registration', () => {
  const request = () => ({ redirect_uris: [REDIRECT], grant_types: ['authorization_code'], id_token_signed_response_alg: 'ES256', token_endpoint_auth_method: 'client_secret_basic' });

  it('registers a client with the requested ID token alg and configures from the response', async () => {
    const { client, registration } = await OIDCClient.register(op.metadata, request(), { initialAccessToken: 'iat-123', fetch: op.fetch });
    assert.equal(registration.client_id, 'dyn-1');
    assert.equal(op.state.registrations[0].body.id_token_signed_response_alg, 'ES256');
    assert.equal(op.state.registrations[0].authorization, 'Bearer iat-123');
    assert.equal(client.clientId, 'dyn-1');
    assert.equal(client.config.idTokenSignedResponseAlg, 'ES256');
    assert.equal(client.config.tokenEndpointAuthMethod, 'client_secret_basic');
  });

  it('passes a software statement through to the registration request', async () => {
    await registerClient(op.metadata, { ...request(), software_statement: 'eyJ.ss.sig' }, { fetch: op.fetch });
    assert.equal(op.state.registrations[0].body.software_statement, 'eyJ.ss.sig');
  });

  it('rejects a registration where the OP substituted a different alg', async () => {
    clearDiscoveryCache();
    op = await createStubProvider({ registrationOverride: { id_token_signed_response_alg: 'RS256' } });
    await assert.rejects(OIDCClient.register(op.metadata, request(), { fetch: op.fetch }), (e) => e.code === 'registration_mismatch' && /RS256 instead of the requested ES256/.test(e.message));
  });

  it('refuses to register an alg it cannot verify, or one the OP does not advertise', async () => {
    await assert.rejects(registerClient(op.metadata, { ...request(), id_token_signed_response_alg: 'ML-DSA-65' }, { fetch: op.fetch }), /cannot verify/);
    await assert.rejects(registerClient(op.metadata, { ...request(), id_token_signed_response_alg: 'PS256' }, { fetch: op.fetch }), /does not support/);
    assert.equal(op.state.registrations.length, 0, 'nothing was sent');
  });

  it('fails clearly when the OP has no registration endpoint', async () => {
    const { registration_endpoint: _, ...metadata } = op.metadata;
    await assert.rejects(registerClient(metadata, request()), (e) => e.code === 'registration_not_supported');
  });
});

describe('authorization code flow', () => {
  it('signs in and validates the ID token', async () => {
    const client = await newClient();
    const tokens = await signIn(client);
    assert.equal(tokens.claims.sub, 'alice');
    assert.ok(tokens.refresh_token);
    assert.ok(tokens.expires_at > Date.now() / 1000);
    assert.equal((await client.userinfo(tokens.access_token, { expectedSub: 'alice' })).email, 'alice@example.com');
  });

  it('rejects a mismatched state', async () => {
    const client = await newClient();
    const { url, transaction } = client.authorizationUrl();
    await assert.rejects(client.callback(op.authorize(url), { ...transaction, state: 'other' }), /state mismatch/);
  });

  it('rejects a mismatched nonce', async () => {
    const client = await newClient();
    const { url, transaction } = client.authorizationUrl();
    await assert.rejects(client.callback(op.authorize(url), { ...transaction, nonce: 'other' }), (e) => e.code === 'nonce_mismatch');
  });

  it('rejects a mix-up (wrong iss in the authorization response)', async () => {
    const client = await newClient();
    const { url, transaction } = client.authorizationUrl();
    const params = op.authorize(url);
    params.set('iss', 'https://evil.test');
    await assert.rejects(client.callback(params, transaction), (e) => e.code === 'issuer_mismatch');
  });

  it('rejects a wrong PKCE verifier at the token endpoint', async () => {
    const client = await newClient();
    const { url, transaction } = client.authorizationUrl();
    await assert.rejects(client.callback(op.authorize(url), { ...transaction, codeVerifier: 'x'.repeat(43) }), (e) => e instanceof OAuthError && e.error === 'invalid_grant');
  });

  it('rejects an ID token signed by another key', async () => {
    const client = await newClient();
    const { privateKey } = await generateKeyPair('RS256');
    const forged = await new SignJWT({}).setProtectedHeader({ alg: 'RS256', kid: 'k1' }).setIssuer(op.issuer).setSubject('alice')
      .setAudience(op.client.id).setIssuedAt().setExpirationTime('5m').sign(privateKey);
    await assert.rejects(client.validateIdToken(forged), (e) => e.code === 'invalid_id_token');
  });

  it('surfaces authorization errors', async () => {
    const client = await newClient();
    const { transaction } = client.authorizationUrl();
    const params = { error: 'access_denied', state: transaction.state, iss: op.issuer };
    await assert.rejects(client.callback(params, transaction), (e) => e instanceof OAuthError && e.error === 'access_denied');
  });

  it('builds an end-session URL', async () => {
    const client = await newClient();
    const url = new URL(client.endSessionUrl({ idTokenHint: 'abc', postLogoutRedirectUri: 'https://rp.test/' }));
    assert.equal(url.searchParams.get('id_token_hint'), 'abc');
    assert.equal(url.searchParams.get('client_id'), op.client.id);
  });

  it('supports client_secret_post', async () => {
    const client = await newClient({ tokenEndpointAuthMethod: 'client_secret_post' });
    assert.equal((await signIn(client, 'bob')).claims.sub, 'bob');
  });
});

describe('TokenManager', () => {
  it('serves cached tokens and refreshes once inside the skew window', async () => {
    clearDiscoveryCache();
    op = await createStubProvider({ accessTokenTtl: 2 });
    const client = await newClient();
    const tm = new TokenManager(client, { refreshSkewSec: 5, autoRefresh: false });
    const initial = await tm.set('s1', await signIn(client));
    assert.equal(await tm.getAccessToken('s1'), initial.access_token, 'fresh token is served from cache');
    // 2s lifetime → skew is capped at 1s, so after ~1s the token is inside the refresh window.
    await new Promise((r) => setTimeout(r, 1100));
    assert.notEqual(await tm.getAccessToken('s1'), initial.access_token);
    const stored = await tm.get('s1');
    assert.notEqual(stored.refresh_token, initial.refresh_token, 'refresh token rotated');
    assert.equal(stored.claims.sub, 'alice');
  });

  it('coalesces concurrent refreshes (refresh-token rotation safe)', async () => {
    const client = await newClient();
    const tm = new TokenManager(client, { autoRefresh: false });
    await tm.set('s1', await signIn(client));
    const before = op.state.tokenCalls;
    const [a, b, c] = await Promise.all([tm.refresh('s1'), tm.refresh('s1'), tm.getAccessToken('s1', { forceRefresh: true })]);
    assert.equal(op.state.tokenCalls - before, 1);
    assert.equal(a.access_token, b.access_token);
    assert.equal(a.access_token, c);
  });

  it('refreshes automatically in the background before expiry', async () => {
    clearDiscoveryCache();
    op = await createStubProvider({ accessTokenTtl: 2 });
    const client = await newClient();
    const tm = new TokenManager(client, { refreshSkewSec: 1, minRefreshDelayMs: 50 });
    const initial = await tm.set('s1', await signIn(client));
    // Refresh timers are unref()'d so they never hold a process open; keep the loop alive while waiting.
    const keepAlive = setInterval(() => {}, 100);
    try {
      const [key, refreshed] = await once(tm, 'refreshed');
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
    const expired = once(tm, 'expired');
    await assert.rejects(tm.refresh('s1'), (e) => e.error === 'invalid_grant');
    await expired;
    assert.equal(await tm.get('s1'), undefined);
  });

  it('caches client credentials tokens', async () => {
    const client = await newClient();
    const tm = new TokenManager(client);
    const a = await tm.getClientCredentialsToken({ scope: 'ssf' });
    const b = await tm.getClientCredentialsToken({ scope: 'ssf' });
    assert.equal(a, b);
  });
});

describe('SSF / CAEP receiver', () => {
  async function receiver(opts) {
    const client = await newClient();
    const tm = new TokenManager(client);
    return new SSFReceiver({
      transmitterIssuer: op.issuer,
      pushEndpointUrl: 'https://rp.test/caep/events',
      accessToken: () => tm.getClientCredentialsToken(),
      fetch: op.fetch,
      ...opts,
    });
  }

  /** Invokes the push handler like node:http would. */
  async function pushTo(r, body, authorization) {
    const req = Readable.from([Buffer.from(body)]);
    Object.assign(req, { method: 'POST', headers: { 'content-type': 'application/secevent+jwt', ...(authorization ? { authorization } : {}) } });
    const res = { statusCode: 0, headers: {}, body: '', setHeader(k, v) { this.headers[k] = v; }, end(b) { this.body = b ?? ''; } };
    await r.pushHandler()(req, res);
    return res;
  }

  const stream = (r) => op.state.streams.get(r.stream.stream_id);

  it('creates a push stream and dispatches CAEP events to named handlers', async () => {
    const r = await receiver();
    const got = [];
    r.onSessionRevoked((e) => got.push(e));
    await r.start();
    assert.ok(r.stream.stream_id);
    assert.equal(r.stream.delivery.authorization_header.startsWith('Bearer '), true);

    await r.addSubject(Subject.issSub(op.issuer, 'alice'));
    assert.deepEqual(stream(r).subjects, [{ format: 'iss_sub', iss: op.issuer, sub: 'alice' }]);

    const set = await op.makeSet(stream(r), CAEP.SESSION_REVOKED, { event_timestamp: 1, initiating_entity: 'admin' }, Subject.issSub(op.issuer, 'alice'));
    const res = await pushTo(r, set, r.stream.delivery.authorization_header);
    assert.equal(res.statusCode, 202);
    await waitFor(() => got.length === 1);
    assert.equal(got[0].name, 'session-revoked');
    assert.equal(got[0].initiatingEntity, 'admin');
    assert.ok(subjectMatches(got[0].subject, { iss: op.issuer, sub: 'alice' }));
    await r.stop({ deleteStream: true });
    assert.equal(op.state.streams.size, 0);
  });

  it('calls every CAEP handler type via constructor config', async () => {
    const seen = new Set();
    const names = ['sessionRevoked', 'tokenClaimsChange', 'credentialChange', 'assuranceLevelChange', 'deviceComplianceChange', 'sessionEstablished', 'sessionPresented', 'riskLevelChange'];
    const r = await receiver({ handlers: Object.fromEntries(names.map((n) => [n, (e) => seen.add(e.name)])) });
    await r.start();
    for (const type of Object.values(CAEP)) {
      await r.receiveSet(await op.makeSet(stream(r), type, {}, Subject.email('bob@example.com')));
    }
    assert.equal(seen.size, 8);
  });

  it('rejects pushes without the agreed Authorization header', async () => {
    const r = await receiver();
    const errors = [];
    r.onError((e) => errors.push(e));
    await r.start();
    const res = await pushTo(r, 'a.b.c');
    assert.equal(res.statusCode, 401);
    assert.equal(JSON.parse(res.body).err, 'authentication_failed');
    assert.equal(errors[0].code, 'authentication_failed');
  });

  it('rejects SETs with a bad signature, wrong audience or wrong typ, and ignores replays', async () => {
    const r = await receiver();
    await r.start();
    const { privateKey } = await generateKeyPair('RS256');
    const forged = await new SignJWT({ jti: 'x', events: { [CAEP.SESSION_REVOKED]: {} } })
      .setProtectedHeader({ alg: 'RS256', kid: 'k1', typ: 'secevent+jwt' })
      .setIssuer(op.issuer).setAudience(r.stream.aud).setIssuedAt().sign(privateKey);
    await assert.rejects(r.receiveSet(forged), (e) => e instanceof SETValidationError && e.code === 'invalid_key');

    const wrongAud = await op.makeSet({ ...stream(r), aud: 'someone-else' }, CAEP.SESSION_REVOKED, {}, Subject.opaque('x'));
    await assert.rejects(r.receiveSet(wrongAud), (e) => e.code === 'invalid_audience');

    const wrongTyp = await new SignJWT({ jti: 'y', events: { [CAEP.SESSION_REVOKED]: {} } })
      .setProtectedHeader({ alg: 'RS256', kid: 'k1', typ: 'JWT' })
      .setIssuer(op.issuer).setAudience(r.stream.aud).setIssuedAt().sign(op.privateKey);
    await assert.rejects(r.receiveSet(wrongTyp), /typ/);

    let count = 0;
    r.onAnyEvent(() => count++);
    const set = await op.makeSet(stream(r), CAEP.CREDENTIAL_CHANGE, { credential_type: 'password', change_type: 'update' }, Subject.opaque('x'));
    assert.equal((await r.receiveSet(set)).length, 1);
    assert.deepEqual(await r.receiveSet(set), [], 'replayed jti is not dispatched again');
    assert.equal(count, 1);
  });

  it('names the algorithm when a SET is signed with one it cannot verify', async () => {
    const r = await receiver();
    await r.start();
    const b64 = (o) => Buffer.from(JSON.stringify(o)).toString('base64url');
    const pq = `${b64({ alg: 'ML-DSA-65', kid: 'pq', typ: 'secevent+jwt' })}.${b64({ iss: op.issuer })}.c2ln`;
    await assert.rejects(r.receiveSet(pq), (e) => e.code === 'invalid_key' && /"ML-DSA-65"/.test(e.message));
  });

  it('rejects SETs that are too old or issued in the future', async () => {
    const r = await receiver({ maxSetAgeSec: 600 });
    await r.start();
    const sign = (iat) => new SignJWT({ jti: randomUUID(), events: { [CAEP.SESSION_REVOKED]: {} } })
      .setProtectedHeader({ alg: 'RS256', kid: 'k1', typ: 'secevent+jwt' })
      .setIssuer(op.issuer).setAudience(r.stream.aud).setIssuedAt(iat).sign(op.privateKey);
    const now = Math.floor(Date.now() / 1000);
    await assert.rejects(r.receiveSet(await sign(now - 3600)), (e) => e instanceof SETValidationError && /too old/.test(e.message));
    await assert.rejects(r.receiveSet(await sign(now + 3600)), (e) => e instanceof SETValidationError && /iat/.test(e.message));
    assert.equal((await r.receiveSet(await sign(now - 30))).length, 1, 'a recent SET is accepted');

    const noLimit = await receiver({ maxSetAgeSec: 0 });
    await noLimit.start();
    const old = await new SignJWT({ jti: randomUUID(), events: { [CAEP.SESSION_REVOKED]: {} } })
      .setProtectedHeader({ alg: 'RS256', kid: 'k1', typ: 'secevent+jwt' })
      .setIssuer(op.issuer).setAudience(noLimit.stream.aud).setIssuedAt(now - 86400).sign(op.privateKey);
    assert.equal((await noLimit.receiveSet(old)).length, 1, 'maxSetAgeSec: 0 disables the age check');
  });

  it('fails closed when there is no expected audience', async () => {
    const r = await receiver();
    await r.start();
    const set = await op.makeSet(stream(r), CAEP.SESSION_REVOKED, {}, Subject.opaque('x'));
    r.stream = { ...r.stream, aud: undefined };
    await assert.rejects(r.receiveSet(set), (e) => e.code === 'invalid_audience' && /No expected SET audience/.test(e.message));
  });

  it('supports poll delivery (RFC 8936) and verification', async () => {
    const r = await receiver({ deliveryMethod: 'poll', pollIntervalMs: 50 });
    const got = [];
    r.onDeviceComplianceChange((e) => got.push(e.payload));
    await r.start();
    assert.match(r.stream.delivery.endpoint_url, /\/ssf\/poll\//);
    const set = await op.makeSet(stream(r), CAEP.DEVICE_COMPLIANCE_CHANGE, { current_status: 'not-compliant' }, Subject.issSub(op.issuer, 'alice'));
    stream(r).queue.set('j1', set);
    await waitFor(() => got.length === 1);
    assert.equal(got[0].current_status, 'not-compliant');
    await waitFor(() => stream(r).queue.size === 0, 'acknowledged');
    const verified = await r.requestVerification({ timeoutMs: 2000 });
    assert.equal(verified.type, SSF.VERIFICATION);
    await r.stop({ deleteStream: true });
  });

  it('manages stream status', async () => {
    const r = await receiver();
    await r.start();
    assert.equal((await r.getStatus()).status, 'enabled');
    assert.equal((await r.updateStatus('paused', 'maintenance')).status, 'paused');
  });
});

describe('subjectMatches', () => {
  const id = { iss: 'https://op', sub: 'u1', email: 'A@x.com', sid: 's9' };
  it('matches the RFC 9493 formats', () => {
    assert.ok(subjectMatches(Subject.issSub('https://op', 'u1'), id));
    assert.ok(!subjectMatches(Subject.issSub('https://other', 'u1'), id));
    assert.ok(subjectMatches(Subject.email('a@X.com'), id));
    assert.ok(subjectMatches(Subject.opaque('s9'), id));
    assert.ok(subjectMatches(Subject.aliases(Subject.email('no@x'), Subject.issSub('https://op', 'u1')), id));
  });
  it('requires all evaluable members of a complex subject to match', () => {
    assert.ok(subjectMatches(Subject.complex({ user: Subject.issSub('https://op', 'u1'), session: Subject.opaque('s9') }), id));
    assert.ok(!subjectMatches(Subject.complex({ user: Subject.issSub('https://op', 'u1'), session: Subject.opaque('s1') }), id));
  });
});

afterEach(() => clearDiscoveryCache());

async function waitFor(fn, label = 'condition', timeoutMs = 3000) {
  const end = Date.now() + timeoutMs;
  while (!(await fn())) {
    if (Date.now() > end) throw new Error(`Timed out waiting for ${label}`);
    await new Promise((r) => setTimeout(r, 20));
  }
}
