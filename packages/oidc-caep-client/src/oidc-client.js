import { createRemoteJWKSet, customFetch, decodeProtectedHeader, errors as joseErrors, jwtVerify } from 'jose';
import { SUPPORTED_ID_TOKEN_ALGS } from './algs.js';
import { discoverOpenIdProvider, validateOpenIdProviderMetadata } from './discovery.js';
import { DPOP_ALGS, DPoPKey, DPoPNonceCache, MemoryKeyStore, wantsDpopNonce } from './dpop.js';
import { OAuthError, OIDCClientError, ValidationError } from './errors.js';
import { httpRequest, readJson } from './http.js';
import { codeChallengeS256, generateCodeVerifier, randomToken } from './pkce.js';
import { registerClient } from './registration.js';
import { TransactionStore } from './stores.js';
import { TokenSet } from './token-set.js';
import { base64url, digest, Emitter, isLoopback, timingSafeEqual } from './util.js';

/**
 * JWT `typ` values that mark a token as something other than an ID token. Presenting one of them as an
 * ID token is token confusion (RFC 8725 §3.11), so it is refused even when its signature verifies.
 */
const NOT_ID_TOKEN_TYPES = ['at+jwt', 'application/at+jwt', 'logout+jwt', 'secevent+jwt', 'dpop+jwt',
  'token-introspection+jwt', 'software-statement+jwt', 'jwt-bearer'];

/** Parameters that must never arrive at a code-flow redirect URI (tokens in the front channel). */
const FRONT_CHANNEL_TOKENS = ['access_token', 'id_token', 'refresh_token', 'token_type'];

/** Endpoints whose URLs must use TLS. */
const ENDPOINTS = ['issuer', 'authorization_endpoint', 'token_endpoint', 'jwks_uri', 'userinfo_endpoint',
  'revocation_endpoint', 'end_session_endpoint', 'pushed_authorization_request_endpoint', 'registration_endpoint'];

/**
 * @typedef {object} OIDCClientConfig
 * @property {string} [issuer]                  Issuer; metadata is loaded from `<issuer>/.well-known/openid-configuration`.
 * @property {Record<string, any>} [metadata]   A provider metadata document to use instead of discovery.
 * @property {string} clientId                  A PUBLIC client (token_endpoint_auth_method "none").
 * @property {string} [redirectUri]
 * @property {string} [postLogoutRedirectUri]
 * @property {string} [scope]                   Default "openid profile email offline_access" (offline_access only if supported).
 * @property {string|string[]} [resource]       RFC 8707 resource indicator(s): audience-restricts the tokens.
 * @property {string} [idTokenSignedResponseAlg] Expected ID token `alg` (default RS256).
 * @property {'auto'|'always'|'never'} [par]    Pushed Authorization Requests (RFC 9126). Default "auto": used when advertised.
 * @property {boolean|{ key?: DPoPKey, keyStore?: object, alg?: string }} [dpop]
 *           DPoP (RFC 9449). `true` generates a non-extractable key kept in memory; pass `keyStore`
 *           (e.g. `new IndexedDBKeyStore()`) to keep it across page loads.
 * @property {TransactionStore} [transactionStore] Where state/nonce/PKCE verifier wait for the callback (default sessionStorage).
 * @property {number} [transactionTtlSec]       How long an authorization request stays redeemable (default 600).
 * @property {number} [maxIdTokenAgeSec]        Reject ID tokens whose `iat` is older than this (default 600).
 * @property {boolean} [enforceAcr]             When acr_values were requested, require the ID token's `acr` to be one of them (default true).
 * @property {boolean} [requireAuthTime]        Require `auth_time` in every ID token (default false).
 * @property {boolean} [allowInsecureRequests]  Allow non-TLS endpoints and redirect URIs other than loopback (default false).
 * @property {number} [clockToleranceSec]       Allowed clock skew (default 30).
 * @property {number} [httpTimeoutMs]           Per-request timeout (default 10000).
 * @property {number} [discoveryCacheTtlMs]     How long discovered metadata is cached (default 1h).
 * @property {typeof fetch} [fetch]             Custom fetch implementation.
 */

/**
 * OpenID Connect Relying Party for a PUBLIC client (a browser app): Authorization Code + PKCE, with the
 * protections RFC 9700 (OAuth 2.0 Security Best Current Practice) and OpenID Connect call for.
 * It holds no client secret and supports no confidential-client authentication.
 *
 * Emits: "tokens" (TokenSet) whenever the token endpoint issues new tokens.
 */
export class OIDCClient extends Emitter {
  /** @type {Record<string, any>} */
  metadata;
  /** @type {DPoPKey|undefined} */
  dpopKey;
  #jwks;
  #config;
  #nonces = new DPoPNonceCache();
  #usedStates = new Map();
  #usePar = false;

  /** @param {OIDCClientConfig} config */
  constructor(config) {
    super();
    if (!config?.issuer && !config?.metadata?.issuer) throw new TypeError('issuer or metadata is required');
    if (!config.clientId) throw new TypeError('clientId is required');
    for (const secretOption of ['clientSecret', 'privateJwk', 'tokenEndpointAuthMethod']) {
      if (config[secretOption] !== undefined && !(secretOption === 'tokenEndpointAuthMethod' && config[secretOption] === 'none')) {
        throw new TypeError(`${secretOption} is not supported: this client is a public client (token_endpoint_auth_method "none")`);
      }
    }
    this.#config = {
      clockToleranceSec: 30,
      httpTimeoutMs: 10_000,
      idTokenSignedResponseAlg: 'RS256',
      par: 'auto',
      dpop: false,
      transactionTtlSec: 600,
      maxIdTokenAgeSec: 600,
      enforceAcr: true,
      requireAuthTime: false,
      allowInsecureRequests: false,
      ...config,
      issuer: config.issuer ?? config.metadata.issuer,
    };
    this.#config.transactionStore ??= new TransactionStore();
  }

  /** Creates a client and loads the provider's discovery document. */
  static async discover(config) {
    const client = new OIDCClient(config);
    await client.init();
    return client;
  }

  /** Creates a client from an already-obtained OpenID Provider metadata document (validated as if discovered). */
  static async fromMetadata(metadata, config) {
    return OIDCClient.discover({ ...config, metadata });
  }

  /**
   * Registers a new PUBLIC client (OpenID Connect Dynamic Client Registration 1.0) and returns a client
   * configured from the registration. `token_endpoint_auth_method` is always "none".
   */
  static async register(providerMetadata, clientMetadata, { initialAccessToken, ...config } = {}) {
    validateOpenIdProviderMetadata(providerMetadata);
    const request = { ...clientMetadata, token_endpoint_auth_method: 'none' };
    if (config.dpop && request.dpop_bound_access_tokens === undefined) request.dpop_bound_access_tokens = true;
    const registration = await registerClient(providerMetadata, request, {
      initialAccessToken,
      timeoutMs: config.httpTimeoutMs,
      fetch: config.fetch,
    });
    if (registration.client_secret) {
      // A confidential registration is not what was asked for, and this client would ignore the secret.
      throw new ValidationError('The OP registered a confidential client (it issued a client_secret); only public clients are supported', { code: 'registration_mismatch', response: registration });
    }
    const client = await OIDCClient.fromMetadata(providerMetadata, {
      redirectUri: registration.redirect_uris?.[0] ?? request.redirect_uris[0],
      postLogoutRedirectUri: registration.post_logout_redirect_uris?.[0] ?? request.post_logout_redirect_uris?.[0],
      ...config,
      clientId: registration.client_id,
      idTokenSignedResponseAlg: registration.id_token_signed_response_alg ?? request.id_token_signed_response_alg ?? 'RS256',
    });
    return { client, registration };
  }

  get issuer() { return this.#config.issuer; }
  get clientId() { return this.#config.clientId; }
  /** The effective settings, for display. */
  get config() {
    const { metadata, transactionStore, dpop, fetch: _f, ...rest } = this.#config;
    return { ...rest, tokenEndpointAuthMethod: 'none', dpop: !!this.dpopKey, par: this.#usePar };
  }
  /** Which security features are active, for display and audit. */
  get securityFeatures() {
    return {
      pkce: 'S256',
      state: 'random 256-bit, single use, expiring, issuer-bound, constant-time compared',
      nonce: true,
      issuerIdentification: this.metadata?.authorization_response_iss_parameter_supported ? 'required (RFC 9207)' : 'checked when present (RFC 9207)',
      par: this.#usePar,
      dpop: this.dpopKey ? { alg: this.dpopKey.alg, jkt: this.dpopKey.thumbprint } : false,
      resourceIndicators: this.#resources().length ? this.#resources() : false,
      tlsEnforced: !this.#config.allowInsecureRequests,
      idToken: `alg ${this.#config.idTokenSignedResponseAlg}, typ checked, iat ≤ ${this.#config.maxIdTokenAgeSec}s, at_hash, acr ${this.#config.enforceAcr ? 'enforced' : 'not enforced'}`,
    };
  }

  async init() {
    const c = this.#config;
    this.metadata = c.metadata
      ? validateOpenIdProviderMetadata(c.metadata, c.issuer)
      : await discoverOpenIdProvider(c.issuer, { timeoutMs: c.httpTimeoutMs, fetch: c.fetch, cacheTtlMs: c.discoveryCacheTtlMs });
    const m = this.metadata;

    // TLS for every endpoint and redirect URI (RFC 9700 §2.6, OIDC Core §16.17), loopback excepted.
    if (!c.allowInsecureRequests) {
      for (const key of ENDPOINTS) {
        if (m[key] && !secureUrl(m[key])) throw new ValidationError(`${key} must use https: ${m[key]}`, { code: 'insecure_endpoint' });
      }
      for (const [name, uri] of [['redirectUri', c.redirectUri], ['postLogoutRedirectUri', c.postLogoutRedirectUri]]) {
        if (uri && !secureUrl(uri)) throw new ValidationError(`${name} must use https (or loopback http): ${uri}`, { code: 'insecure_redirect_uri' });
      }
    }
    // PKCE downgrade protection (RFC 9700 §2.1.1): refuse an OP that says it does not do S256.
    if (Array.isArray(m.code_challenge_methods_supported) && !m.code_challenge_methods_supported.includes('S256')) {
      throw new ValidationError('The OP does not support PKCE with S256', { code: 'pkce_not_supported' });
    }
    // A public client authenticates with "none" only.
    const methods = m.token_endpoint_auth_methods_supported;
    if (Array.isArray(methods) && !methods.includes('none')) {
      throw new ValidationError('The OP does not accept public clients (token_endpoint_auth_method "none")', { code: 'public_client_not_supported' });
    }
    if (!SUPPORTED_ID_TOKEN_ALGS.includes(c.idTokenSignedResponseAlg)) {
      throw new ValidationError(`ID token alg ${c.idTokenSignedResponseAlg} cannot be verified by this library (supported: ${SUPPORTED_ID_TOKEN_ALGS.join(', ')})`);
    }
    if (!m.id_token_signing_alg_values_supported.includes(c.idTokenSignedResponseAlg)) {
      throw new ValidationError(`OP does not support ID token alg ${c.idTokenSignedResponseAlg}`);
    }

    // PAR (RFC 9126).
    const parEndpoint = m.pushed_authorization_request_endpoint;
    if (m.require_pushed_authorization_requests && !parEndpoint) {
      throw new ValidationError('The OP requires PAR but advertises no pushed_authorization_request_endpoint');
    }
    if (c.par === 'always' && !parEndpoint) throw new ValidationError('par: "always" but the OP has no pushed_authorization_request_endpoint');
    if (c.par === 'never' && m.require_pushed_authorization_requests) throw new ValidationError('The OP requires PAR (require_pushed_authorization_requests)');
    this.#usePar = !!parEndpoint && (c.par === 'always' || c.par === 'auto' || m.require_pushed_authorization_requests);

    // DPoP (RFC 9449).
    if (c.dpop) {
      const opts = typeof c.dpop === 'object' ? c.dpop : {};
      const offered = m.dpop_signing_alg_values_supported;
      const alg = opts.alg ?? (Array.isArray(offered) ? DPOP_ALGS.find((a) => offered.includes(a)) : 'ES256');
      if (!alg) throw new ValidationError(`The OP accepts no DPoP algorithm this library creates (${DPOP_ALGS.join(', ')})`, { code: 'dpop_not_supported' });
      this.dpopKey = opts.key ?? await DPoPKey.loadOrCreate(opts.keyStore ?? new MemoryKeyStore(), { alg });
    }

    this.#jwks = createRemoteJWKSet(new URL(m.jwks_uri), {
      timeoutDuration: c.httpTimeoutMs,
      ...(c.fetch ? { [customFetch]: c.fetch } : {}),
    });
    if (!c.scope) {
      const offline = m.scopes_supported?.includes('offline_access') ? ' offline_access' : '';
      c.scope = `openid profile email${offline}`;
    }
    c.transactionStore.sweep?.(c.transactionTtlSec * 1000);
    return this;
  }

  #requireMetadata() {
    if (!this.metadata) throw new OIDCClientError('Client not initialised; call init() or OIDCClient.discover()');
  }

  #resources() {
    const r = this.#config.resource;
    return r === undefined ? [] : [].concat(r);
  }

  // ---------------------------------------------------------------------------
  // Authorization request
  // ---------------------------------------------------------------------------

  /**
   * Starts an Authorization Code + PKCE (S256) sign-in. The transaction (state, nonce, code verifier)
   * is stored in the transaction store under its `state`, and `callback()` consumes it.
   * Uses PAR when enabled, and binds the authorization code to the DPoP key (`dpop_jkt`).
   *
   * @param {object} [opts]
   * @param {string} [opts.scope]
   * @param {string} [opts.redirectUri]
   * @param {string} [opts.prompt]
   * @param {number} [opts.maxAge]
   * @param {string} [opts.loginHint]
   * @param {string} [opts.acrValues]  Space-separated; with `enforceAcr`, the ID token's acr must be one of these.
   * @param {Record<string,string>} [opts.extraParams]
   * @returns {Promise<{ url: string, state: string }>}
   */
  async createAuthorizationRequest(opts = {}) {
    this.#requireMetadata();
    const c = this.#config;
    const redirectUri = opts.redirectUri ?? c.redirectUri;
    if (!redirectUri) throw new TypeError('redirectUri is required');
    if (!c.allowInsecureRequests && !secureUrl(redirectUri)) throw new ValidationError(`redirectUri must use https (or loopback http): ${redirectUri}`, { code: 'insecure_redirect_uri' });

    const state = randomToken();
    const nonce = randomToken();
    const codeVerifier = generateCodeVerifier();
    const params = {
      response_type: 'code',
      client_id: c.clientId,
      redirect_uri: redirectUri,
      scope: opts.scope ?? c.scope,
      state,
      nonce,
      code_challenge: await codeChallengeS256(codeVerifier),
      code_challenge_method: 'S256',
      prompt: opts.prompt,
      max_age: opts.maxAge,
      login_hint: opts.loginHint,
      acr_values: opts.acrValues,
      dpop_jkt: this.dpopKey?.thumbprint,
      ...opts.extraParams,
    };
    // offline_access requires prompt=consent per OIDC Core §11 unless the caller chose otherwise.
    if (params.scope.split(' ').includes('offline_access') && params.prompt === undefined) params.prompt = 'consent';

    const query = new URLSearchParams();
    for (const [k, v] of Object.entries(params)) if (v !== undefined && v !== null) query.set(k, String(v));
    for (const r of this.#resources()) query.append('resource', r);

    let url;
    if (this.#usePar) {
      const par = await this.#postForm(this.metadata.pushed_authorization_request_endpoint, query);
      if (!par?.request_uri) throw new ValidationError('PAR response has no request_uri', { code: 'invalid_par_response' });
      url = new URL(this.metadata.authorization_endpoint);
      url.searchParams.set('client_id', c.clientId);
      url.searchParams.set('request_uri', par.request_uri);
    } else {
      url = new URL(this.metadata.authorization_endpoint);
      for (const [k, v] of query) url.searchParams.append(k, v);
    }

    c.transactionStore.set(state, {
      state,
      nonce,
      codeVerifier,
      redirectUri,
      maxAge: opts.maxAge,
      acrValues: opts.acrValues,
      issuer: this.metadata.issuer,
      clientId: c.clientId,
      createdAt: Date.now(),
    });
    return { url: url.href, state };
  }

  /**
   * Completes the sign-in from the redirect: consumes the stored transaction for the returned `state`
   * (single use), checks it, redeems the code with the PKCE verifier (and a DPoP proof) and validates
   * the ID token.
   *
   * @param {URLSearchParams|Record<string,string>|string} response The redirect URL, or its query parameters.
   * @returns {Promise<TokenSet>}
   */
  async callback(response) {
    this.#requireMetadata();
    const c = this.#config;
    const p = toParams(response);

    // Front-channel token injection: a code-flow redirect never carries tokens (RFC 9700 §4.5, §2.1.2).
    const injected = FRONT_CHANNEL_TOKENS.filter((k) => p.has(k));
    if (injected.length) throw new ValidationError(`Authorization response carries ${injected.join(', ')}; tokens never arrive in the front channel`, { code: 'front_channel_token' });
    // Parameter pollution: every response parameter appears at most once (RFC 6749 §3.1).
    for (const k of new Set(p.keys())) {
      if (p.getAll(k).length > 1) throw new ValidationError(`Authorization response repeats "${k}"`, { code: 'duplicate_parameter' });
    }

    // STATE: look up and REMOVE the transaction (single use), then check it thoroughly.
    const returned = p.get('state');
    if (!returned) throw new ValidationError('state missing from authorization response', { code: 'state_missing' });
    const transaction = c.transactionStore.take(returned);
    if (!transaction) {
      throw new ValidationError(this.#usedStates.has(returned)
        ? 'This authorization response was already used (state replayed)'
        : 'No sign-in in progress for this state (unknown, already used, or from another browser tab/session)', { code: this.#usedStates.has(returned) ? 'state_reused' : 'state_mismatch' });
    }
    this.#rememberState(returned);
    if (!(await timingSafeEqual(returned, transaction.state))) throw new ValidationError('state mismatch', { code: 'state_mismatch' });
    if (Date.now() - transaction.createdAt > c.transactionTtlSec * 1000) {
      throw new ValidationError(`The sign-in took longer than ${c.transactionTtlSec}s; start again`, { code: 'transaction_expired' });
    }
    // The transaction belongs to this OP and this client (mix-up defence when several are configured).
    if (transaction.issuer !== this.metadata.issuer || transaction.clientId !== c.clientId) {
      throw new ValidationError('This sign-in was started with a different identity provider or client', { code: 'issuer_mismatch' });
    }

    // RFC 9207 issuer identification.
    const iss = p.get('iss');
    if (iss !== null && iss !== this.metadata.issuer) throw new ValidationError(`iss mismatch in authorization response: ${iss}`, { code: 'issuer_mismatch' });
    if (iss === null && this.metadata.authorization_response_iss_parameter_supported) {
      throw new ValidationError('iss missing from authorization response', { code: 'issuer_missing' });
    }
    if (p.get('error')) {
      throw new OAuthError({ error: p.get('error'), error_description: p.get('error_description') ?? undefined, error_uri: p.get('error_uri') ?? undefined });
    }
    const code = p.get('code');
    if (!code) throw new ValidationError('code missing from authorization response', { code: 'code_missing' });

    const body = new URLSearchParams({
      grant_type: 'authorization_code',
      code,
      redirect_uri: transaction.redirectUri,
      code_verifier: transaction.codeVerifier,
    });
    for (const r of this.#resources()) body.append('resource', r);
    const tokens = await this.#tokenRequest(body);
    if (!tokens.id_token) throw new ValidationError('Token response did not include an id_token', { code: 'id_token_missing' });

    const claims = await this.validateIdToken(tokens.id_token, {
      nonce: transaction.nonce,
      maxAge: transaction.maxAge,
      acrValues: transaction.acrValues,
      accessToken: tokens.access_token,
    });
    const tokenSet = new TokenSet(tokens, claims);
    this.emit('tokens', tokenSet);
    return tokenSet;
  }

  #rememberState(state) {
    const now = Date.now();
    this.#usedStates.set(state, now);
    const cutoff = now - this.#config.transactionTtlSec * 1000;
    for (const [s, at] of this.#usedStates) {
      if (at >= cutoff && this.#usedStates.size <= 1000) break;
      this.#usedStates.delete(s);
    }
  }

  // ---------------------------------------------------------------------------
  // Refresh
  // ---------------------------------------------------------------------------

  /**
   * Refresh Token grant (OIDC Core §12). Keeps the previous refresh token when the OP doesn't rotate it,
   * validates any new ID token against the previous claims (§12.2), and sends a DPoP proof with the same
   * key when the tokens are DPoP-bound.
   *
   * @param {TokenSet|string} tokenSetOrRefreshToken
   * @param {{ scope?: string }} [opts]
   */
  async refresh(tokenSetOrRefreshToken, { scope } = {}) {
    this.#requireMetadata();
    const previous = typeof tokenSetOrRefreshToken === 'string' ? undefined : TokenSet.from(tokenSetOrRefreshToken);
    const refreshToken = previous ? previous.refresh_token : tokenSetOrRefreshToken;
    if (!refreshToken) throw new OIDCClientError('No refresh_token available', { code: 'no_refresh_token' });
    const body = new URLSearchParams({ grant_type: 'refresh_token', refresh_token: refreshToken });
    if (scope) body.set('scope', scope);
    for (const r of this.#resources()) body.append('resource', r);

    const tokens = await this.#tokenRequest(body);
    let claims = previous?.claims;
    if (tokens.id_token) {
      claims = await this.validateIdToken(tokens.id_token, { accessToken: tokens.access_token, previousClaims: previous?.claims });
    }
    const tokenSet = new TokenSet({
      ...tokens,
      refresh_token: tokens.refresh_token ?? refreshToken,
      id_token: tokens.id_token ?? previous?.id_token,
    }, claims);
    this.emit('tokens', tokenSet);
    return tokenSet;
  }

  // ---------------------------------------------------------------------------
  // Calling protected resources (UserInfo, SSF, APIs)
  // ---------------------------------------------------------------------------

  /**
   * The Authorization (and DPoP) headers for a request to a resource server with an access token.
   * A DPoP-bound token (token_type "DPoP") gets a fresh proof bound to this method, URL and token.
   *
   * @param {TokenSet|{access_token: string, token_type?: string}|string} token
   * @param {{ method?: string, url: string, nonce?: string }} request
   */
  async resourceHeaders(token, { method = 'GET', url, nonce }) {
    const { access_token: accessToken, token_type: type } = typeof token === 'string' ? { access_token: token, token_type: 'Bearer' } : token;
    if (/^dpop$/i.test(type ?? '')) {
      if (!this.dpopKey) throw new OIDCClientError('A DPoP-bound token needs the DPoP key it was issued to', { code: 'dpop_key_missing' });
      return {
        authorization: `DPoP ${accessToken}`,
        dpop: await this.dpopKey.proof({ method, url, accessToken, nonce: nonce ?? this.#nonces.get(url) }),
      };
    }
    return { authorization: `Bearer ${accessToken}` };
  }

  /**
   * fetch() against a protected resource with an access token, retrying once when the resource server
   * asks for a DPoP nonce (RFC 9449 §9).
   *
   * @param {TokenSet|{access_token: string, token_type?: string}|string} token
   * @param {string} url
   * @param {RequestInit} [init]
   */
  async fetchResource(token, url, init = {}) {
    const method = init.method ?? 'GET';
    const send = async (nonce) => httpRequest(url, {
      ...this.#httpOpts(),
      ...init,
      headers: { ...init.headers, ...(await this.resourceHeaders(token, { method, url, nonce })) },
    });
    let res = await send();
    const nonce = this.#nonces.update(url, res);
    if (wantsDpopNonce(res)) {
      await res.body?.cancel();
      res = await send(nonce);
      this.#nonces.update(url, res);
    }
    return res;
  }

  /**
   * Calls the UserInfo endpoint (OIDC Core §5.3). Pass `expectedSub` (the ID token's `sub`): the
   * response must be about the same person (§5.3.2).
   * @param {TokenSet|{access_token: string, token_type?: string}|string} token
   * @param {{ expectedSub?: string }} [opts]
   */
  async userinfo(token, { expectedSub } = {}) {
    this.#requireMetadata();
    if (!this.metadata.userinfo_endpoint) throw new OIDCClientError('OP has no userinfo_endpoint');
    const res = await this.fetchResource(token, this.metadata.userinfo_endpoint, { headers: { accept: 'application/json, application/jwt' } });
    if (res.status === 401) {
      const www = res.headers.get('www-authenticate') ?? '';
      await res.body?.cancel();
      throw new OAuthError({ error: /error="([^"]+)"/.exec(www)?.[1] ?? 'invalid_token', error_description: www, status: 401 });
    }
    let claims;
    if ((res.headers.get('content-type') ?? '').includes('application/jwt')) {
      const jwt = await res.text();
      ({ payload: claims } = await jwtVerify(jwt, this.#jwks, {
        issuer: this.metadata.issuer,
        audience: this.#config.clientId,
        clockTolerance: this.#config.clockToleranceSec,
      }));
    } else {
      claims = await readJson(res);
    }
    if (expectedSub && claims.sub !== expectedSub) throw new ValidationError('UserInfo sub does not match ID token sub', { code: 'sub_mismatch' });
    return claims;
  }

  /**
   * Token revocation (RFC 7009), as a public client. Resolves false when the OP has no revocation endpoint.
   * @param {string} token
   * @param {'access_token'|'refresh_token'} [hint]
   */
  async revoke(token, hint) {
    this.#requireMetadata();
    if (!this.metadata.revocation_endpoint || !token) return false;
    const body = new URLSearchParams({ token, client_id: this.#config.clientId });
    if (hint) body.set('token_type_hint', hint);
    const res = await httpRequest(this.metadata.revocation_endpoint, {
      ...this.#httpOpts(),
      method: 'POST',
      headers: { 'content-type': 'application/x-www-form-urlencoded', accept: 'application/json' },
      body,
    });
    if (!res.ok) await readJson(res);
    else await res.body?.cancel();
    return true;
  }

  // ---------------------------------------------------------------------------
  // Logout
  // ---------------------------------------------------------------------------

  /**
   * Builds an RP-Initiated Logout 1.0 request with a fresh `state`, stored for
   * `validateEndSessionCallback()`. Resolves undefined when the OP has no end_session_endpoint.
   * @param {{ idTokenHint?: string, postLogoutRedirectUri?: string, logoutHint?: string }} [opts]
   * @returns {Promise<{ url: string, state: string }|undefined>}
   */
  async createEndSessionRequest({ idTokenHint, postLogoutRedirectUri, logoutHint } = {}) {
    this.#requireMetadata();
    if (!this.metadata.end_session_endpoint) return undefined;
    const state = randomToken();
    const redirect = postLogoutRedirectUri ?? this.#config.postLogoutRedirectUri;
    const url = new URL(this.metadata.end_session_endpoint);
    const params = { id_token_hint: idTokenHint, post_logout_redirect_uri: redirect, client_id: this.#config.clientId, logout_hint: logoutHint, state: redirect ? state : undefined };
    for (const [k, v] of Object.entries(params)) if (v) url.searchParams.set(k, v);
    if (redirect) this.#config.transactionStore.set(`logout:${state}`, { state, createdAt: Date.now() });
    return { url: url.href, state };
  }

  /**
   * Checks the `state` the OP returned to the post-logout redirect URI. Throws when it is missing,
   * unknown, reused or expired.
   * @param {URLSearchParams|Record<string,string>|string} response
   */
  async validateEndSessionCallback(response) {
    const returned = toParams(response).get('state');
    if (!returned) throw new ValidationError('state missing from logout response', { code: 'state_missing' });
    const held = this.#config.transactionStore.take(`logout:${returned}`);
    if (!held || !(await timingSafeEqual(returned, held.state))) throw new ValidationError('Unknown or already-used logout state', { code: 'state_mismatch' });
    if (Date.now() - held.createdAt > this.#config.transactionTtlSec * 1000) throw new ValidationError('The logout took too long', { code: 'transaction_expired' });
    return true;
  }

  // ---------------------------------------------------------------------------
  // ID Token validation (OIDC Core §3.1.3.7, §12.2; RFC 8725)
  // ---------------------------------------------------------------------------

  /**
   * @param {string} idToken
   * @param {{ nonce?: string, maxAge?: number, acrValues?: string, accessToken?: string, previousClaims?: object }} [opts]
   * @returns {Promise<Record<string, any>>} the validated claims
   */
  async validateIdToken(idToken, { nonce, maxAge, acrValues, accessToken, previousClaims } = {}) {
    this.#requireMetadata();
    const c = this.#config;
    const expectedAlg = c.idTokenSignedResponseAlg;

    let header;
    try {
      header = decodeProtectedHeader(idToken);
    } catch (err) {
      throw new ValidationError('ID token is not a valid JWS', { code: 'invalid_id_token', cause: err });
    }
    if (header.alg !== expectedAlg) throw new ValidationError(`Unexpected ID token alg ${header.alg}; expected ${expectedAlg}`, { code: 'invalid_id_token' });
    if (header.typ && NOT_ID_TOKEN_TYPES.includes(String(header.typ).toLowerCase())) {
      throw new ValidationError(`A "${header.typ}" token is not an ID token`, { code: 'invalid_id_token' });
    }
    if (header.crit) throw new ValidationError('ID token has critical header parameters this client does not understand', { code: 'invalid_id_token' });

    let claims;
    try {
      ({ payload: claims } = await jwtVerify(idToken, this.#jwks, {
        algorithms: [expectedAlg],
        issuer: this.metadata.issuer,
        audience: c.clientId,
        clockTolerance: c.clockToleranceSec,
        maxTokenAge: c.maxIdTokenAgeSec > 0 ? c.maxIdTokenAgeSec : undefined,
        requiredClaims: ['iss', 'sub', 'aud', 'exp', 'iat'],
      }));
    } catch (err) {
      const msg = err instanceof joseErrors.JOSEError ? err.message : String(err);
      throw new ValidationError(`ID token validation failed: ${msg}`, { code: 'invalid_id_token', cause: err });
    }

    const aud = Array.isArray(claims.aud) ? claims.aud : [claims.aud];
    if (aud.length > 1 && !claims.azp) throw new ValidationError('ID token has multiple audiences but no azp', { code: 'invalid_id_token' });
    if (claims.azp !== undefined && claims.azp !== c.clientId) throw new ValidationError('ID token azp does not match client_id', { code: 'invalid_id_token' });
    if (nonce !== undefined && !(await timingSafeEqual(String(claims.nonce ?? ''), nonce))) {
      throw new ValidationError('ID token nonce mismatch', { code: 'nonce_mismatch' });
    }
    if ((maxAge !== undefined || c.requireAuthTime) && typeof claims.auth_time !== 'number') {
      throw new ValidationError('ID token has no auth_time', { code: 'invalid_id_token' });
    }
    if (maxAge !== undefined && claims.auth_time + maxAge + c.clockToleranceSec < Math.floor(Date.now() / 1000)) {
      throw new ValidationError('auth_time is older than max_age; re-authentication required', { code: 'max_age_exceeded' });
    }
    if (acrValues && c.enforceAcr) {
      const wanted = acrValues.split(' ').filter(Boolean);
      if (!wanted.includes(claims.acr)) {
        throw new ValidationError(`ID token acr "${claims.acr ?? '(none)'}" is not one of the requested acr_values (${acrValues})`, { code: 'acr_mismatch' });
      }
    }
    if (accessToken && claims.at_hash !== undefined && claims.at_hash !== await tokenHash(accessToken, header)) {
      throw new ValidationError('ID token at_hash does not match access token', { code: 'invalid_id_token' });
    }
    if (previousClaims) {
      for (const claim of ['iss', 'sub']) {
        if (claims[claim] !== previousClaims[claim]) throw new ValidationError(`Refreshed ID token ${claim} changed`, { code: 'invalid_id_token' });
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

  #httpOpts() {
    return { timeoutMs: this.#config.httpTimeoutMs, fetch: this.#config.fetch };
  }

  /**
   * POSTs a form to an authorization-server endpoint as this public client, with a DPoP proof when
   * enabled, retrying once when the AS demands a DPoP nonce (RFC 9449 §8).
   */
  async #postForm(endpoint, form) {
    form.set('client_id', this.#config.clientId);
    const send = async (nonce) => {
      const headers = { 'content-type': 'application/x-www-form-urlencoded', accept: 'application/json' };
      if (this.dpopKey) headers.dpop = await this.dpopKey.proof({ method: 'POST', url: endpoint, nonce: nonce ?? this.#nonces.get(endpoint) });
      return httpRequest(endpoint, { ...this.#httpOpts(), method: 'POST', headers, body: form });
    };
    let res = await send();
    let nonce = this.#nonces.update(endpoint, res);
    if (this.dpopKey && res.status === 400 && nonce) {
      const text = await res.clone().text();
      if (/"error"\s*:\s*"use_dpop_nonce"/.test(text)) {
        await res.body?.cancel();
        res = await send(nonce);
        nonce = this.#nonces.update(endpoint, res);
      }
    }
    return readJson(res);
  }

  async #tokenRequest(form) {
    const tokens = await this.#postForm(this.metadata.token_endpoint, form);
    if (!tokens?.access_token) throw new ValidationError('Token response missing access_token', { code: 'invalid_token_response' });
    if (!/^(bearer|dpop)$/i.test(tokens.token_type ?? '')) throw new ValidationError(`Unsupported token_type ${tokens.token_type}`, { code: 'invalid_token_response' });
    if (/^dpop$/i.test(tokens.token_type) && !this.dpopKey) throw new ValidationError('The OP issued a DPoP-bound token but DPoP is not enabled', { code: 'invalid_token_response' });
    if (tokens.expires_in !== undefined && !(Number.isFinite(Number(tokens.expires_in)) && Number(tokens.expires_in) >= 0)) {
      throw new ValidationError(`Invalid expires_in ${tokens.expires_in}`, { code: 'invalid_token_response' });
    }
    return tokens;
  }
}

function secureUrl(value) {
  try {
    const u = new URL(value);
    return u.protocol === 'https:' || (u.protocol === 'http:' && isLoopback(u.href));
  } catch {
    return false;
  }
}

function toParams(input) {
  if (input instanceof URLSearchParams) return input;
  if (typeof input === 'string') {
    if (/^[a-z][a-z0-9+.-]*:/i.test(input) || input.startsWith('/')) {
      const u = new URL(input, 'http://localhost');
      // A fragment response is not a code-flow response; include it so injected tokens are caught.
      const all = new URLSearchParams(u.search);
      if (u.hash.length > 1) for (const [k, v] of new URLSearchParams(u.hash.slice(1))) all.append(k, v);
      return all;
    }
    return new URLSearchParams(input.replace(/^[?#]/, ''));
  }
  return new URLSearchParams(Object.entries(input ?? {}).filter(([, v]) => typeof v === 'string'));
}

/** at_hash: left-most half of the hash of the ASCII value, base64url encoded (OIDC Core §3.1.3.6). */
async function tokenHash(value, { alg }) {
  const bits = (alg === 'EdDSA' || alg === 'Ed25519') ? '512' : alg.slice(-3);
  const d = await digest(value, `SHA-${bits}`);
  return base64url(d.subarray(0, d.length / 2));
}
