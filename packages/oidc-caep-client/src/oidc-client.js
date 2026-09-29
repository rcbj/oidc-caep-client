import { createHash, randomUUID } from 'node:crypto';
import { EventEmitter } from 'node:events';
import { createRemoteJWKSet, customFetch, decodeProtectedHeader, errors as joseErrors, importJWK, jwtVerify, SignJWT } from 'jose';
import { SUPPORTED_ID_TOKEN_ALGS } from './algs.js';
import { discoverOpenIdProvider, validateOpenIdProviderMetadata } from './discovery.js';
import { registerClient } from './registration.js';
import { OAuthError, OIDCClientError, ValidationError } from './errors.js';
import { httpRequest, readJson } from './http.js';
import { codeChallengeS256, generateCodeVerifier, randomToken } from './pkce.js';
import { TokenSet } from './token-set.js';

const SUPPORTED_AUTH_METHODS = ['client_secret_basic', 'client_secret_post', 'private_key_jwt', 'none'];

/**
 * @typedef {object} OIDCClientConfig
 * @property {string} [issuer]                  Issuer identifier; metadata is loaded from `<issuer>/.well-known/openid-configuration`.
 * @property {Record<string, any>} [metadata]   A provider metadata document to use instead of discovery (issuer is taken from it).
 * @property {string} clientId
 * @property {string} [clientSecret]            Needed for client_secret_basic / client_secret_post and HS* ID tokens.
 * @property {object} [privateJwk]              Private JWK (with `alg` and `kid`) for private_key_jwt client authentication.
 * @property {string} [redirectUri]
 * @property {string} [postLogoutRedirectUri]
 * @property {string} [scope]                   Default "openid profile email offline_access" (offline_access only if supported).
 * @property {string} [tokenEndpointAuthMethod] Defaults based on the credentials supplied and what the OP supports.
 * @property {string} [idTokenSignedResponseAlg] Expected ID token `alg` (default RS256, per OIDC Registration §2).
 * @property {number} [clockToleranceSec]       Allowed clock skew for time-based claims (default 30).
 * @property {number} [httpTimeoutMs]           Per-request timeout (default 10000).
 * @property {number} [discoveryCacheTtlMs]     How long discovered metadata is cached (default 1h).
 * @property {typeof fetch} [fetch]             Custom fetch implementation.
 */

/**
 * OpenID Connect Relying Party client (Authorization Code flow + PKCE), configured from OP discovery metadata.
 *
 * Emits: "tokens" (TokenSet) whenever the token endpoint issues new tokens.
 */
export class OIDCClient extends EventEmitter {
  /** @type {Record<string, any>} */
  metadata;
  #jwks;
  #config;

  /** @param {OIDCClientConfig} config */
  constructor(config) {
    super();
    if (!config?.issuer && !config?.metadata?.issuer) throw new TypeError('issuer or metadata is required');
    if (!config.clientId) throw new TypeError('clientId is required');
    this.#config = {
      clockToleranceSec: 30,
      httpTimeoutMs: 10_000,
      idTokenSignedResponseAlg: 'RS256',
      ...config,
      issuer: config.issuer ?? config.metadata.issuer,
    };
  }

  /**
   * Creates a client and loads the provider's discovery document and JWKS location.
   * @param {OIDCClientConfig} config
   */
  static async discover(config) {
    const client = new OIDCClient(config);
    await client.init();
    return client;
  }

  /**
   * Creates a client from an already-obtained OpenID Provider metadata document (no discovery request).
   * The document is validated exactly as a discovered one would be.
   * @param {Record<string, any>} metadata
   * @param {Omit<OIDCClientConfig, 'issuer' | 'metadata'>} config
   */
  static async fromMetadata(metadata, config) {
    return OIDCClient.discover({ ...config, metadata });
  }

  /**
   * Registers a new client with the OP (OpenID Connect Dynamic Client Registration 1.0) and returns a
   * client configured with the registered credentials and ID token signing algorithm.
   *
   * @param {Record<string, any>} providerMetadata  Validated OP metadata (e.g. from discoverOpenIdProvider)
   * @param {Record<string, any>} clientMetadata    Registration request, e.g. { redirect_uris, id_token_signed_response_alg }
   * @param {Omit<OIDCClientConfig, 'issuer'|'metadata'|'clientId'|'clientSecret'> & { initialAccessToken?: string }} [config]
   * @returns {Promise<{ client: OIDCClient, registration: import('./registration.js').ClientRegistration }>}
   */
  static async register(providerMetadata, clientMetadata, { initialAccessToken, ...config } = {}) {
    validateOpenIdProviderMetadata(providerMetadata);
    const registration = await registerClient(providerMetadata, clientMetadata, {
      initialAccessToken,
      timeoutMs: config.httpTimeoutMs,
      fetch: config.fetch,
    });
    const client = await OIDCClient.fromMetadata(providerMetadata, {
      redirectUri: registration.redirect_uris?.[0] ?? clientMetadata.redirect_uris[0],
      postLogoutRedirectUri: registration.post_logout_redirect_uris?.[0] ?? clientMetadata.post_logout_redirect_uris?.[0],
      ...config,
      clientId: registration.client_id,
      clientSecret: registration.client_secret,
      // OIDC Registration §2: unregistered id_token_signed_response_alg means RS256.
      idTokenSignedResponseAlg: registration.id_token_signed_response_alg ?? clientMetadata.id_token_signed_response_alg ?? 'RS256',
      tokenEndpointAuthMethod: registration.token_endpoint_auth_method ?? clientMetadata.token_endpoint_auth_method ?? 'client_secret_basic',
    });
    return { client, registration };
  }

  get issuer() { return this.#config.issuer; }
  get clientId() { return this.#config.clientId; }
  get config() { return { ...this.#config, metadata: undefined, clientSecret: this.#config.clientSecret ? '***' : undefined, privateJwk: undefined }; }

  async init() {
    const c = this.#config;
    this.metadata = c.metadata
      ? validateOpenIdProviderMetadata(c.metadata, c.issuer)
      : await discoverOpenIdProvider(c.issuer, {
          timeoutMs: c.httpTimeoutMs,
          fetch: c.fetch,
          cacheTtlMs: c.discoveryCacheTtlMs,
        });
    this.#jwks = createRemoteJWKSet(new URL(this.metadata.jwks_uri), {
      timeoutDuration: c.httpTimeoutMs,
      ...(c.fetch ? { [customFetch]: c.fetch } : {}),
    });
    c.tokenEndpointAuthMethod ??= this.#defaultAuthMethod();
    if (!SUPPORTED_AUTH_METHODS.includes(c.tokenEndpointAuthMethod)) {
      throw new TypeError(`Unsupported tokenEndpointAuthMethod ${c.tokenEndpointAuthMethod}`);
    }
    if (!SUPPORTED_ID_TOKEN_ALGS.includes(c.idTokenSignedResponseAlg)) {
      throw new ValidationError(`ID token alg ${c.idTokenSignedResponseAlg} cannot be verified by this library (supported: ${SUPPORTED_ID_TOKEN_ALGS.join(', ')})`);
    }
    const algs = this.metadata.id_token_signing_alg_values_supported;
    if (!algs.includes(c.idTokenSignedResponseAlg)) {
      throw new ValidationError(`OP does not support ID token alg ${c.idTokenSignedResponseAlg} (supports ${algs.join(', ')})`);
    }
    if (!c.scope) {
      const offline = this.metadata.scopes_supported?.includes('offline_access') ? ' offline_access' : '';
      c.scope = `openid profile email${offline}`;
    }
    return this;
  }

  #defaultAuthMethod() {
    const supported = this.metadata.token_endpoint_auth_methods_supported ?? ['client_secret_basic'];
    const c = this.#config;
    if (c.privateJwk && supported.includes('private_key_jwt')) return 'private_key_jwt';
    if (c.clientSecret) return supported.includes('client_secret_basic') ? 'client_secret_basic' : 'client_secret_post';
    return 'none';
  }

  #requireMetadata() {
    if (!this.metadata) throw new OIDCClientError('Client not initialised; call init() or OIDCClient.discover()');
  }

  // ---------------------------------------------------------------------------
  // Authorization request
  // ---------------------------------------------------------------------------

  /**
   * Builds an Authorization Code + PKCE (S256) authorization request (OIDC Core §3.1.2.1).
   * Persist the returned `transaction` (e.g. in the user's server-side session) and pass it to `callback()`.
   *
   * @param {object} [opts]
   * @param {string} [opts.scope]
   * @param {string} [opts.redirectUri]
   * @param {string} [opts.prompt]
   * @param {number} [opts.maxAge]
   * @param {string} [opts.loginHint]
   * @param {string} [opts.acrValues]
   * @param {Record<string,string>} [opts.extraParams]
   * @returns {{ url: string, transaction: { state: string, nonce: string, codeVerifier: string, redirectUri: string, maxAge?: number, createdAt: number } }}
   */
  authorizationUrl(opts = {}) {
    this.#requireMetadata();
    const redirectUri = opts.redirectUri ?? this.#config.redirectUri;
    if (!redirectUri) throw new TypeError('redirectUri is required');

    const state = randomToken();
    const nonce = randomToken();
    const codeVerifier = generateCodeVerifier();

    const url = new URL(this.metadata.authorization_endpoint);
    const params = {
      response_type: 'code',
      client_id: this.#config.clientId,
      redirect_uri: redirectUri,
      scope: opts.scope ?? this.#config.scope,
      state,
      nonce,
      code_challenge: codeChallengeS256(codeVerifier),
      code_challenge_method: 'S256',
      prompt: opts.prompt,
      max_age: opts.maxAge,
      login_hint: opts.loginHint,
      acr_values: opts.acrValues,
      ...opts.extraParams,
    };
    // offline_access requires prompt=consent per OIDC Core §11 unless the caller chose otherwise.
    if (params.scope.split(' ').includes('offline_access') && params.prompt === undefined) {
      params.prompt = 'consent';
    }
    for (const [k, v] of Object.entries(params)) {
      if (v !== undefined && v !== null) url.searchParams.set(k, String(v));
    }
    return {
      url: url.href,
      transaction: { state, nonce, codeVerifier, redirectUri, maxAge: opts.maxAge, createdAt: Date.now() },
    };
  }

  /**
   * Completes the Authorization Code flow: validates the redirect, redeems the code, validates the ID token.
   *
   * @param {URLSearchParams|Record<string,string>|string} params Query parameters from the redirect (or the full redirect URL).
   * @param {ReturnType<OIDCClient['authorizationUrl']>['transaction']} transaction
   * @returns {Promise<TokenSet>}
   */
  async callback(params, transaction) {
    this.#requireMetadata();
    if (!transaction) throw new ValidationError('No authorization transaction found (session expired?)', { code: 'missing_transaction' });
    const p = toParams(params);

    // State must round-trip unchanged (CSRF protection).
    if (p.get('state') !== transaction.state) {
      throw new ValidationError('state mismatch', { code: 'state_mismatch' });
    }
    // RFC 9207 mix-up protection.
    const iss = p.get('iss');
    if (iss !== null && iss !== this.metadata.issuer) {
      throw new ValidationError(`iss mismatch in authorization response: ${iss}`, { code: 'issuer_mismatch' });
    }
    if (iss === null && this.metadata.authorization_response_iss_parameter_supported) {
      throw new ValidationError('iss missing from authorization response', { code: 'issuer_missing' });
    }
    if (p.get('error')) {
      throw new OAuthError({ error: p.get('error'), error_description: p.get('error_description') ?? undefined, error_uri: p.get('error_uri') ?? undefined });
    }
    const code = p.get('code');
    if (!code) throw new ValidationError('code missing from authorization response', { code: 'code_missing' });

    const tokens = await this.#tokenRequest({
      grant_type: 'authorization_code',
      code,
      redirect_uri: transaction.redirectUri,
      code_verifier: transaction.codeVerifier,
    });
    if (!tokens.id_token) throw new ValidationError('Token response did not include an id_token', { code: 'id_token_missing' });

    const claims = await this.validateIdToken(tokens.id_token, {
      nonce: transaction.nonce,
      maxAge: transaction.maxAge,
      accessToken: tokens.access_token,
    });
    const tokenSet = new TokenSet(tokens, claims);
    this.emit('tokens', tokenSet);
    return tokenSet;
  }

  // ---------------------------------------------------------------------------
  // Other grants
  // ---------------------------------------------------------------------------

  /**
   * Refresh Token grant (OIDC Core §12). Keeps the previous refresh token when the OP doesn't rotate it,
   * and validates any new ID token against the previous claims (§12.2).
   *
   * @param {TokenSet|string} tokenSetOrRefreshToken
   * @param {{ scope?: string }} [opts]
   * @returns {Promise<TokenSet>}
   */
  async refresh(tokenSetOrRefreshToken, { scope } = {}) {
    this.#requireMetadata();
    const previous = typeof tokenSetOrRefreshToken === 'string' ? undefined : TokenSet.from(tokenSetOrRefreshToken);
    const refreshToken = previous ? previous.refresh_token : tokenSetOrRefreshToken;
    if (!refreshToken) throw new OIDCClientError('No refresh_token available', { code: 'no_refresh_token' });

    const tokens = await this.#tokenRequest({ grant_type: 'refresh_token', refresh_token: refreshToken, scope });
    let claims = previous?.claims;
    if (tokens.id_token) {
      claims = await this.validateIdToken(tokens.id_token, {
        accessToken: tokens.access_token,
        previousClaims: previous?.claims,
      });
    }
    const merged = {
      ...tokens,
      refresh_token: tokens.refresh_token ?? refreshToken,
      id_token: tokens.id_token ?? previous?.id_token,
    };
    const tokenSet = new TokenSet(merged, claims);
    this.emit('tokens', tokenSet);
    return tokenSet;
  }

  /**
   * Client Credentials grant (RFC 6749 §4.4).
   * @param {{ scope?: string, resource?: string, audience?: string }} [opts]
   */
  async clientCredentials({ scope, resource, audience } = {}) {
    this.#requireMetadata();
    const tokens = await this.#tokenRequest({ grant_type: 'client_credentials', scope, resource, audience });
    return new TokenSet(tokens);
  }

  // ---------------------------------------------------------------------------
  // UserInfo / revocation / logout
  // ---------------------------------------------------------------------------

  /**
   * Calls the UserInfo endpoint (OIDC Core §5.3). When `expectedSub` is given (recommended),
   * the response `sub` must match it (§5.3.2).
   * @param {string} accessToken
   * @param {{ expectedSub?: string }} [opts]
   */
  async userinfo(accessToken, { expectedSub } = {}) {
    this.#requireMetadata();
    if (!this.metadata.userinfo_endpoint) throw new OIDCClientError('OP has no userinfo_endpoint');
    const res = await httpRequest(this.metadata.userinfo_endpoint, {
      ...this.#httpOpts(),
      headers: { authorization: `Bearer ${accessToken}`, accept: 'application/json, application/jwt' },
    });
    if (res.status === 401) {
      const www = res.headers.get('www-authenticate') ?? '';
      await res.body?.cancel();
      const error = /error="([^"]+)"/.exec(www)?.[1] ?? 'invalid_token';
      throw new OAuthError({ error, error_description: www, status: 401 });
    }
    let claims;
    if ((res.headers.get('content-type') ?? '').includes('application/jwt')) {
      const jwt = await res.text();
      ({ payload: claims } = await jwtVerify(jwt, this.#keyFor(decodeProtectedHeader(jwt).alg), {
        issuer: this.metadata.issuer,
        audience: this.#config.clientId,
        clockTolerance: this.#config.clockToleranceSec,
      }));
    } else {
      claims = await readJson(res);
    }
    if (expectedSub && claims.sub !== expectedSub) {
      throw new ValidationError('UserInfo sub does not match ID token sub', { code: 'sub_mismatch' });
    }
    return claims;
  }

  /**
   * Token revocation (RFC 7009). Silently succeeds if the OP has no revocation endpoint.
   * @param {string} token
   * @param {'access_token'|'refresh_token'} [hint]
   * @returns {Promise<boolean>} true if a revocation request was sent
   */
  async revoke(token, hint) {
    this.#requireMetadata();
    if (!this.metadata.revocation_endpoint || !token) return false;
    const body = new URLSearchParams({ token });
    if (hint) body.set('token_type_hint', hint);
    const headers = { 'content-type': 'application/x-www-form-urlencoded', accept: 'application/json' };
    await this.#authenticate(body, headers, this.metadata.revocation_endpoint);
    const res = await httpRequest(this.metadata.revocation_endpoint, { ...this.#httpOpts(), method: 'POST', headers, body });
    if (!res.ok) await readJson(res);
    else await res.body?.cancel();
    return true;
  }

  /**
   * Builds an RP-Initiated Logout 1.0 URL, or undefined if the OP has no end_session_endpoint.
   * @param {{ idTokenHint?: string, postLogoutRedirectUri?: string, state?: string, logoutHint?: string }} [opts]
   */
  endSessionUrl({ idTokenHint, postLogoutRedirectUri, state, logoutHint } = {}) {
    this.#requireMetadata();
    if (!this.metadata.end_session_endpoint) return undefined;
    const url = new URL(this.metadata.end_session_endpoint);
    const params = {
      id_token_hint: idTokenHint,
      post_logout_redirect_uri: postLogoutRedirectUri ?? this.#config.postLogoutRedirectUri,
      client_id: this.#config.clientId,
      state,
      logout_hint: logoutHint,
    };
    for (const [k, v] of Object.entries(params)) if (v) url.searchParams.set(k, v);
    return url.href;
  }

  // ---------------------------------------------------------------------------
  // ID Token validation (OIDC Core §3.1.3.7, §12.2)
  // ---------------------------------------------------------------------------

  /**
   * @param {string} idToken
   * @param {{ nonce?: string, maxAge?: number, accessToken?: string, previousClaims?: object }} [opts]
   * @returns {Promise<Record<string, any>>} the validated claims
   */
  async validateIdToken(idToken, { nonce, maxAge, accessToken, previousClaims } = {}) {
    this.#requireMetadata();
    const c = this.#config;
    const expectedAlg = c.idTokenSignedResponseAlg;

    let header;
    try {
      header = decodeProtectedHeader(idToken);
    } catch (err) {
      throw new ValidationError('ID token is not a valid JWS', { code: 'invalid_id_token', cause: err });
    }
    if (header.alg !== expectedAlg) {
      throw new ValidationError(`Unexpected ID token alg ${header.alg}; expected ${expectedAlg}`, { code: 'invalid_id_token' });
    }

    let claims;
    try {
      ({ payload: claims } = await jwtVerify(idToken, this.#keyFor(header.alg), {
        algorithms: [expectedAlg],
        issuer: this.metadata.issuer,
        audience: c.clientId,
        clockTolerance: c.clockToleranceSec,
        requiredClaims: ['iss', 'sub', 'aud', 'exp', 'iat'],
      }));
    } catch (err) {
      const msg = err instanceof joseErrors.JOSEError ? err.message : String(err);
      throw new ValidationError(`ID token validation failed: ${msg}`, { code: 'invalid_id_token', cause: err });
    }

    const aud = Array.isArray(claims.aud) ? claims.aud : [claims.aud];
    // §3.1.3.7 (3)/(4)/(5): multiple audiences require azp, and azp must be us when present.
    if (aud.length > 1 && !claims.azp) {
      throw new ValidationError('ID token has multiple audiences but no azp', { code: 'invalid_id_token' });
    }
    if (claims.azp !== undefined && claims.azp !== c.clientId) {
      throw new ValidationError('ID token azp does not match client_id', { code: 'invalid_id_token' });
    }
    if (nonce !== undefined && claims.nonce !== nonce) {
      throw new ValidationError('ID token nonce mismatch', { code: 'nonce_mismatch' });
    }
    if (maxAge !== undefined) {
      if (typeof claims.auth_time !== 'number') {
        throw new ValidationError('ID token missing auth_time although max_age was requested', { code: 'invalid_id_token' });
      }
      if (claims.auth_time + maxAge + c.clockToleranceSec < Math.floor(Date.now() / 1000)) {
        throw new ValidationError('auth_time is older than max_age; re-authentication required', { code: 'max_age_exceeded' });
      }
    }
    if (accessToken && claims.at_hash !== undefined && claims.at_hash !== tokenHash(accessToken, header)) {
      throw new ValidationError('ID token at_hash does not match access token', { code: 'invalid_id_token' });
    }
    if (previousClaims) {
      // §12.2: a refreshed ID token must describe the same authentication.
      for (const claim of ['iss', 'sub']) {
        if (claims[claim] !== previousClaims[claim]) {
          throw new ValidationError(`Refreshed ID token ${claim} changed`, { code: 'invalid_id_token' });
        }
      }
      if (previousClaims.auth_time !== undefined && claims.auth_time !== undefined && claims.auth_time !== previousClaims.auth_time) {
        throw new ValidationError('Refreshed ID token auth_time changed', { code: 'invalid_id_token' });
      }
    }
    return claims;
  }

  // ---------------------------------------------------------------------------
  // Internals
  // ---------------------------------------------------------------------------

  #keyFor(alg) {
    if (alg?.startsWith('HS')) {
      if (!this.#config.clientSecret) throw new ValidationError(`${alg} requires clientSecret`);
      return new TextEncoder().encode(this.#config.clientSecret);
    }
    return this.#jwks;
  }

  #httpOpts() {
    return { timeoutMs: this.#config.httpTimeoutMs, fetch: this.#config.fetch };
  }

  async #authenticate(body, headers, audience) {
    const c = this.#config;
    switch (c.tokenEndpointAuthMethod) {
      case 'client_secret_basic': {
        // RFC 6749 §2.3.1: credentials are form-urlencoded before base64 encoding.
        const enc = (s) => encodeURIComponent(s).replace(/%20/g, '+');
        headers.authorization = `Basic ${Buffer.from(`${enc(c.clientId)}:${enc(c.clientSecret)}`).toString('base64')}`;
        break;
      }
      case 'client_secret_post':
        body.set('client_id', c.clientId);
        body.set('client_secret', c.clientSecret);
        break;
      case 'private_key_jwt': {
        const alg = c.privateJwk.alg ?? 'RS256';
        const key = await importJWK(c.privateJwk, alg);
        const assertion = await new SignJWT({})
          .setProtectedHeader({ alg, kid: c.privateJwk.kid })
          .setIssuer(c.clientId)
          .setSubject(c.clientId)
          .setAudience(c.clientAssertionAudience ?? audience)
          .setJti(randomUUID())
          .setIssuedAt()
          .setExpirationTime('60s')
          .sign(key);
        body.set('client_id', c.clientId);
        body.set('client_assertion_type', 'urn:ietf:params:oauth:client-assertion-type:jwt-bearer');
        body.set('client_assertion', assertion);
        break;
      }
      case 'none':
        body.set('client_id', c.clientId);
        break;
    }
  }

  async #tokenRequest(params) {
    const endpoint = this.metadata.token_endpoint;
    const body = new URLSearchParams();
    for (const [k, v] of Object.entries(params)) if (v !== undefined && v !== null) body.set(k, v);
    const headers = { 'content-type': 'application/x-www-form-urlencoded', accept: 'application/json' };
    await this.#authenticate(body, headers, endpoint);

    const res = await httpRequest(endpoint, { ...this.#httpOpts(), method: 'POST', headers, body });
    const tokens = await readJson(res);
    if (!tokens?.access_token) throw new ValidationError('Token response missing access_token', { code: 'invalid_token_response' });
    if (!/^(bearer|dpop)$/i.test(tokens.token_type ?? '')) {
      throw new ValidationError(`Unsupported token_type ${tokens.token_type}`, { code: 'invalid_token_response' });
    }
    return tokens;
  }
}

function toParams(input) {
  if (input instanceof URLSearchParams) return input;
  if (typeof input === 'string') {
    return input.includes('?') ? new URL(input, 'http://localhost').searchParams : new URLSearchParams(input);
  }
  return new URLSearchParams(Object.entries(input ?? {}).filter(([, v]) => typeof v === 'string'));
}

/** at_hash / c_hash: left-most half of the hash of the ASCII value, base64url encoded (OIDC Core §3.1.3.6). */
function tokenHash(value, { alg, crv }) {
  let hash;
  if (alg === 'EdDSA' || alg === 'Ed25519') hash = crv === 'Ed448' ? 'shake256' : 'sha512';
  else hash = `sha${alg.slice(-3)}`;
  const digest = hash === 'shake256'
    ? createHash('shake256', { outputLength: 114 }).update(value).digest()
    : createHash(hash).update(value).digest();
  return digest.subarray(0, digest.length / 2).toString('base64url');
}
