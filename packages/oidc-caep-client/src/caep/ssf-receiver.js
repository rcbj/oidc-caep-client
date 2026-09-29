import { timingSafeEqual } from 'node:crypto';
import { createRemoteJWKSet, customFetch, decodeProtectedHeader, errors as joseErrors, jwtVerify } from 'jose';
import { ASYMMETRIC_JWS_ALGS } from '../algs.js';
import { discoverSSFTransmitter } from '../discovery.js';
import { OAuthError, SETValidationError, SSFError } from '../errors.js';
import { httpRequest, readJson } from '../http.js';
import { randomToken } from '../pkce.js';
import { CAEP, DELIVERY, eventName, SSF } from './constants.js';


/**
 * Named handler slots. Each maps to one event type URI and gets a matching `on<Name>(handler)` method.
 */
const NAMED_HANDLERS = {
  sessionRevoked: CAEP.SESSION_REVOKED,
  tokenClaimsChange: CAEP.TOKEN_CLAIMS_CHANGE,
  credentialChange: CAEP.CREDENTIAL_CHANGE,
  assuranceLevelChange: CAEP.ASSURANCE_LEVEL_CHANGE,
  deviceComplianceChange: CAEP.DEVICE_COMPLIANCE_CHANGE,
  sessionEstablished: CAEP.SESSION_ESTABLISHED,
  sessionPresented: CAEP.SESSION_PRESENTED,
  riskLevelChange: CAEP.RISK_LEVEL_CHANGE,
  verification: SSF.VERIFICATION,
  streamUpdated: SSF.STREAM_UPDATED,
};

/**
 * @typedef {object} SecurityEvent  What every handler receives.
 * @property {string} type              Event type URI.
 * @property {string} name              Short name, e.g. "session-revoked".
 * @property {Record<string, any>} payload  The event-specific object from the SET `events` claim.
 * @property {object|undefined} subject RFC 9493 subject identifier (`sub_id`, or legacy `subject` inside the event).
 * @property {number|undefined} eventTimestamp  CAEP `event_timestamp` (seconds), falling back to SET `toe`/`iat`.
 * @property {string|undefined} initiatingEntity  "admin" | "user" | "policy" | "system"
 * @property {Record<string,string>|undefined} reasonAdmin
 * @property {Record<string,string>|undefined} reasonUser
 * @property {string} jti
 * @property {string} iss
 * @property {string|string[]} aud
 * @property {number} iat
 * @property {string|undefined} txn
 * @property {Record<string, any>} set  All validated SET claims.
 * @property {string} raw               The SET as received (compact JWS).
 */

/**
 * @callback SecurityEventHandler
 * @param {SecurityEvent} event
 * @returns {void|Promise<void>}
 */

/**
 * @typedef {object} SSFReceiverConfig
 * @property {string} transmitterIssuer  SSF transmitter issuer; metadata is loaded from its `/.well-known/ssf-configuration`.
 * @property {'push'|'poll'} [deliveryMethod]  Default "push".
 * @property {string} [pushEndpointUrl]  Public URL of your push endpoint (required for push).
 * @property {string|string[]} [audience]  Expected SET `aud`. Defaults to the `aud` in the stream configuration.
 * @property {string[]} [eventsRequested]  Default: all CAEP event types.
 * @property {() => Promise<string>|string} [accessToken]  Bearer token for the transmitter management API.
 * @property {string} [streamId]        Use an existing stream instead of creating one.
 * @property {string} [pushAuthorizationHeader]  Expected Authorization header on push requests. Generated when a stream is created.
 * @property {string} [description]
 * @property {number} [pollIntervalMs]  Default 5000.
 * @property {number} [maxEvents]       Max SETs per poll. Default 25.
 * @property {number} [clockToleranceSec] Default 60.
 * @property {number} [maxSetAgeSec]    Reject SETs whose `iat` is older than this (seconds). Default 3600; 0 disables.
 * @property {boolean} [requireTyp]     Require the `typ: secevent+jwt` header (SSF §4.1.9). Default true.
 * @property {number} [jtiCacheSize]    Replay-protection window size. Default 10000.
 * @property {number} [httpTimeoutMs]
 * @property {typeof fetch} [fetch]
 * @property {Partial<Record<keyof typeof NAMED_HANDLERS, SecurityEventHandler>>} [handlers]
 */

/**
 * OpenID Shared Signals Framework 1.0 receiver with first-class CAEP handlers.
 *
 * Register a handler per CAEP event:
 *   receiver.onSessionRevoked(async (evt) => { ... })
 *           .onCredentialChange(async (evt) => { ... });
 * or pass them as `handlers: { sessionRevoked, credentialChange, ... }`.
 * Any other event type (e.g. RISC) can be handled with `onEvent(uri, handler)`.
 */
export class SSFReceiver {
  /** @type {Record<string, any>} Transmitter metadata. */
  metadata;
  /** @type {Record<string, any>} Current stream configuration. */
  stream;

  #cfg;
  #jwks;
  #handlers = new Map();
  #anyHandlers = new Set();
  #unhandledHandlers = new Set();
  #errorHandlers = new Set();
  #seenJtis = new Map();
  #pendingVerifications = new Map();
  #pollTimer;
  #polling = false;
  #pendingAcks = [];
  #pendingErrs = {};

  /** @param {SSFReceiverConfig} config */
  constructor(config) {
    if (!config?.transmitterIssuer) throw new TypeError('transmitterIssuer is required');
    this.#cfg = {
      deliveryMethod: 'push',
      eventsRequested: Object.values(CAEP),
      pollIntervalMs: 5000,
      maxEvents: 25,
      clockToleranceSec: 60,
      maxSetAgeSec: 3600,
      requireTyp: true,
      jtiCacheSize: 10_000,
      httpTimeoutMs: 10_000,
      description: 'oidc-caep-client receiver',
      ...config,
    };
    if (!['push', 'poll'].includes(this.#cfg.deliveryMethod)) throw new TypeError('deliveryMethod must be "push" or "poll"');
    if (this.#cfg.deliveryMethod === 'push' && !this.#cfg.pushEndpointUrl) {
      throw new TypeError('pushEndpointUrl is required for push delivery');
    }
    for (const [name, fn] of Object.entries(this.#cfg.handlers ?? {})) {
      if (name === 'any') this.onAnyEvent(fn);
      else if (name === 'unhandled') this.onUnhandledEvent(fn);
      else if (name === 'error') this.onError(fn);
      else if (NAMED_HANDLERS[name]) this.onEvent(NAMED_HANDLERS[name], fn);
      else throw new TypeError(`Unknown handler "${name}"`);
    }
  }

  // ---------------------------------------------------------------------------
  // Handler registration — one per CAEP event, plus generic hooks
  // ---------------------------------------------------------------------------

  /** CAEP session-revoked: the session(s) for the subject were revoked; terminate local sessions. */
  onSessionRevoked(handler) { return this.onEvent(CAEP.SESSION_REVOKED, handler); }
  /** CAEP token-claims-change: claims in previously issued tokens changed (payload.claims). */
  onTokenClaimsChange(handler) { return this.onEvent(CAEP.TOKEN_CLAIMS_CHANGE, handler); }
  /** CAEP credential-change: a credential was created/revoked/updated/deleted (payload.credential_type, change_type). */
  onCredentialChange(handler) { return this.onEvent(CAEP.CREDENTIAL_CHANGE, handler); }
  /** CAEP assurance-level-change: authentication assurance changed (payload.current_level, previous_level, change_direction). */
  onAssuranceLevelChange(handler) { return this.onEvent(CAEP.ASSURANCE_LEVEL_CHANGE, handler); }
  /** CAEP device-compliance-change: device compliance changed (payload.current_status: "compliant" | "not-compliant"). */
  onDeviceComplianceChange(handler) { return this.onEvent(CAEP.DEVICE_COMPLIANCE_CHANGE, handler); }
  /** CAEP session-established: a new session was established (payload.acr, amr, fp_ua, ext_id). */
  onSessionEstablished(handler) { return this.onEvent(CAEP.SESSION_ESTABLISHED, handler); }
  /** CAEP session-presented: a session was presented to a service (payload.fp_ua, ext_id). */
  onSessionPresented(handler) { return this.onEvent(CAEP.SESSION_PRESENTED, handler); }
  /** CAEP risk-level-change: the risk level of a principal changed (payload.current_level, previous_level, risk_reason, principal). */
  onRiskLevelChange(handler) { return this.onEvent(CAEP.RISK_LEVEL_CHANGE, handler); }
  /** SSF verification event (payload.state). */
  onVerification(handler) { return this.onEvent(SSF.VERIFICATION, handler); }
  /** SSF stream-updated event (payload.status, payload.reason). */
  onStreamUpdated(handler) { return this.onEvent(SSF.STREAM_UPDATED, handler); }

  /**
   * Registers a handler for any event type URI (CAEP, RISC, or custom).
   * @param {string} eventType
   * @param {SecurityEventHandler} handler
   */
  onEvent(eventType, handler) {
    assertFn(handler);
    if (!this.#handlers.has(eventType)) this.#handlers.set(eventType, new Set());
    this.#handlers.get(eventType).add(handler);
    return this;
  }

  /** Called for every accepted event, after type-specific handlers. */
  onAnyEvent(handler) { assertFn(handler); this.#anyHandlers.add(handler); return this; }
  /** Called for events with no type-specific handler. */
  onUnhandledEvent(handler) { assertFn(handler); this.#unhandledHandlers.add(handler); return this; }
  /** Called with (error, context) when a SET is rejected, a handler throws, or polling fails. */
  onError(handler) { assertFn(handler); this.#errorHandlers.add(handler); return this; }

  /** Removes a handler previously registered with onEvent / on<Name>. */
  off(eventType, handler) {
    this.#handlers.get(eventType)?.delete(handler);
    return this;
  }

  // ---------------------------------------------------------------------------
  // Lifecycle
  // ---------------------------------------------------------------------------

  /** Loads transmitter metadata from its well-known SSF configuration endpoint. */
  async discover() {
    const c = this.#cfg;
    this.metadata = await discoverSSFTransmitter(c.transmitterIssuer, { timeoutMs: c.httpTimeoutMs, fetch: c.fetch });
    this.#jwks = createRemoteJWKSet(new URL(this.metadata.jwks_uri), {
      timeoutDuration: c.httpTimeoutMs,
      ...(c.fetch ? { [customFetch]: c.fetch } : {}),
    });
    const method = c.deliveryMethod === 'push' ? DELIVERY.PUSH : DELIVERY.POLL;
    const supported = this.metadata.delivery_methods_supported;
    if (supported && !supported.includes(method)) {
      throw new SSFError(`Transmitter does not support ${c.deliveryMethod} delivery (${method})`);
    }
    return this.metadata;
  }

  /**
   * Discovers the transmitter, creates (or reuses) a stream, and starts polling when using poll delivery.
   * If the transmitter already has a stream for this receiver (HTTP 409), that stream is reused and
   * re-pointed at this receiver's delivery settings.
   */
  async start() {
    if (!this.metadata) await this.discover();
    if (this.#cfg.streamId) {
      this.stream = await this.getStream(this.#cfg.streamId);
    } else if (this.metadata.configuration_endpoint) {
      try {
        this.stream = await this.createStream();
      } catch (err) {
        if (err.status !== 409) throw err;
        const existing = await this.listStreams();
        if (!existing.length) throw err;
        this.stream = existing[0];
        this.stream = await this.updateStream({ delivery: this.#deliveryRequest(), events_requested: this.#cfg.eventsRequested });
      }
    } else {
      throw new SSFError('Transmitter has no configuration_endpoint and no streamId was supplied');
    }
    if (this.#cfg.deliveryMethod === 'poll') this.#startPolling();
    return this.stream;
  }

  /**
   * Stops polling and optionally deletes the stream at the transmitter.
   * @param {{ deleteStream?: boolean }} [opts]
   */
  async stop({ deleteStream = false } = {}) {
    this.#polling = false;
    clearTimeout(this.#pollTimer);
    if (deleteStream && this.stream?.stream_id) {
      await this.deleteStream().catch((err) => this.#emitError(err, { phase: 'stop' }));
    }
  }

  // ---------------------------------------------------------------------------
  // Stream management API (SSF 1.0 §8.1)
  // ---------------------------------------------------------------------------

  /** Creates a stream using this receiver's delivery settings and requested events. */
  async createStream(extra = {}) {
    const body = {
      delivery: this.#deliveryRequest(),
      events_requested: this.#cfg.eventsRequested,
      description: this.#cfg.description,
      ...extra,
    };
    this.stream = await this.#mgmt('POST', this.#endpoint('configuration_endpoint'), body);
    return this.stream;
  }

  /** @returns {Promise<object[]>} All streams the transmitter has for this receiver. */
  async listStreams() {
    const result = await this.#mgmt('GET', this.#endpoint('configuration_endpoint'));
    return Array.isArray(result) ? result : result ? [result] : [];
  }

  async getStream(streamId = this.stream?.stream_id) {
    const url = new URL(this.#endpoint('configuration_endpoint'));
    url.searchParams.set('stream_id', streamId);
    this.stream = await this.#mgmt('GET', url);
    return this.stream;
  }

  /** PATCH the stream configuration. */
  async updateStream(changes) {
    this.stream = await this.#mgmt('PATCH', this.#endpoint('configuration_endpoint'), { stream_id: this.#streamId(), ...changes });
    return this.stream;
  }

  /** PUT (replace) the stream configuration. */
  async replaceStream(config) {
    this.stream = await this.#mgmt('PUT', this.#endpoint('configuration_endpoint'), { ...config, stream_id: this.#streamId() });
    return this.stream;
  }

  async deleteStream() {
    const url = new URL(this.#endpoint('configuration_endpoint'));
    url.searchParams.set('stream_id', this.#streamId());
    await this.#mgmt('DELETE', url);
    this.stream = undefined;
  }

  /** @returns {Promise<{ stream_id: string, status: 'enabled'|'paused'|'disabled', reason?: string }>} */
  async getStatus() {
    const url = new URL(this.#endpoint('status_endpoint'));
    url.searchParams.set('stream_id', this.#streamId());
    return this.#mgmt('GET', url);
  }

  /** @param {'enabled'|'paused'|'disabled'} status */
  async updateStatus(status, reason) {
    return this.#mgmt('POST', this.#endpoint('status_endpoint'), { stream_id: this.#streamId(), status, reason });
  }

  /**
   * Asks the transmitter to include events about a subject in this stream.
   * @param {object} subject RFC 9493 subject identifier, e.g. Subject.issSub(iss, sub)
   * @param {{ verified?: boolean }} [opts]
   */
  async addSubject(subject, { verified } = {}) {
    await this.#mgmt('POST', this.#endpoint('add_subject_endpoint'), { stream_id: this.#streamId(), subject, verified });
  }

  /** @param {object} subject */
  async removeSubject(subject) {
    await this.#mgmt('POST', this.#endpoint('remove_subject_endpoint'), { stream_id: this.#streamId(), subject });
  }

  /**
   * Requests a verification event (SSF §8.1.4) and resolves when it is received.
   * @param {{ timeoutMs?: number, state?: string }} [opts]
   * @returns {Promise<SecurityEvent>}
   */
  async requestVerification({ timeoutMs = 15_000, state = randomToken(16) } = {}) {
    const received = new Promise((resolve, reject) => {
      const timer = setTimeout(() => {
        this.#pendingVerifications.delete(state);
        reject(new SSFError(`Verification event not received within ${timeoutMs}ms`, { code: 'verification_timeout' }));
      }, timeoutMs);
      this.#pendingVerifications.set(state, (evt) => { clearTimeout(timer); resolve(evt); });
    });
    try {
      await this.#mgmt('POST', this.#endpoint('verification_endpoint'), { stream_id: this.#streamId(), state });
    } catch (err) {
      this.#pendingVerifications.get(state)?.(undefined);
      this.#pendingVerifications.delete(state);
      throw err;
    }
    if (this.#cfg.deliveryMethod === 'poll') this.pollNow();
    return received;
  }

  // ---------------------------------------------------------------------------
  // Delivery
  // ---------------------------------------------------------------------------

  /**
   * RFC 8935 push endpoint as a Node/Express/Connect-compatible `(req, res)` handler.
   * Works with or without a body parser; mount it on the path given as `pushEndpointUrl`.
   * Responds 202 once the SET is validated; handlers run asynchronously afterwards.
   */
  pushHandler() {
    return async (req, res) => {
      const reply = (status, body) => {
        res.statusCode = status;
        if (body) {
          res.setHeader('content-type', 'application/json');
          res.end(JSON.stringify(body));
        } else {
          res.end();
        }
      };
      if (req.method !== 'POST') return reply(405);
      try {
        this.#checkPushAuthorization(req.headers.authorization);
        const token = await readRawBody(req);
        const events = await this.validateSet(token);
        reply(202);
        this.#dispatchAll(events);
      } catch (err) {
        const code = err instanceof SETValidationError ? err.code : 'invalid_request';
        this.#emitError(err, { phase: 'push' });
        reply(code === 'authentication_failed' ? 401 : code === 'access_denied' ? 403 : 400, { err: code, description: err.message });
      }
    };
  }

  /**
   * Validates a SET and runs its handlers. Use this if you receive SETs through your own transport.
   * @param {string} token Compact JWS SET
   * @returns {Promise<SecurityEvent[]>} the dispatched events (empty for a replayed jti)
   */
  async receiveSet(token) {
    const events = await this.validateSet(token);
    await this.#dispatchAll(events);
    return events;
  }

  /**
   * Validates a SET (RFC 8417 / SSF 1.0 §4) without dispatching it.
   * Duplicate `jti`s return an empty array.
   * @param {string} token
   * @returns {Promise<SecurityEvent[]>}
   */
  async validateSet(token) {
    if (!this.#jwks) await this.discover();
    const c = this.#cfg;
    if (typeof token !== 'string' || token.split('.').length !== 3) {
      throw new SETValidationError('Body is not a compact-serialised JWS', 'invalid_request');
    }
    let header;
    try {
      header = decodeProtectedHeader(token);
    } catch (err) {
      throw new SETValidationError('Malformed JWS header', 'invalid_request', err);
    }
    if (!ASYMMETRIC_JWS_ALGS.includes(header.alg)) {
      throw new SETValidationError(
        `SET is signed with "${header.alg}", which this receiver cannot verify (supported: ${ASYMMETRIC_JWS_ALGS.join(', ')})`,
        'invalid_key',
      );
    }
    if (c.requireTyp && header.typ?.toLowerCase().replace(/^application\//, '') !== 'secevent+jwt') {
      throw new SETValidationError(`Unexpected typ "${header.typ}"; expected secevent+jwt`, 'invalid_request');
    }

    // Fail closed: SSF 1.0 requires the transmitter to supply the stream's `aud`, so a missing one is not
    // a reason to accept SETs addressed to anybody.
    const audience = c.audience ?? this.stream?.aud;
    if (audience === undefined || audience === null || (Array.isArray(audience) && !audience.length)) {
      throw new SETValidationError(
        'No expected SET audience: the stream configuration has no "aud" and no `audience` option was set',
        'invalid_audience',
      );
    }
    let claims;
    try {
      ({ payload: claims } = await jwtVerify(token, this.#jwks, {
        // Bounds `iat` both ways: not older than maxSetAgeSec, not in the future (beyond clockTolerance).
        ...(c.maxSetAgeSec > 0 ? { maxTokenAge: c.maxSetAgeSec } : {}),
        algorithms: ASYMMETRIC_JWS_ALGS,
        issuer: this.metadata.issuer,
        audience,
        clockTolerance: c.clockToleranceSec,
        requiredClaims: ['iss', 'jti', 'iat', 'events'],
      }));
    } catch (err) {
      throw mapJoseError(err);
    }

    if (!claims.events || typeof claims.events !== 'object' || Array.isArray(claims.events) || !Object.keys(claims.events).length) {
      throw new SETValidationError('SET "events" claim must be a non-empty object', 'invalid_request');
    }
    if (this.stream?.stream_id && claims.sub_id?.format === 'opaque' && claims.events[SSF.VERIFICATION] && claims.sub_id.id !== this.stream.stream_id) {
      throw new SETValidationError('Verification event is for a different stream', 'invalid_request');
    }
    if (this.#seenJtis.has(claims.jti)) return [];
    this.#rememberJti(claims.jti);

    return Object.entries(claims.events).map(([type, payload]) => toSecurityEvent(type, payload ?? {}, claims, token));
  }

  /** Triggers an immediate poll (poll delivery only). */
  pollNow() {
    if (!this.#polling) return;
    clearTimeout(this.#pollTimer);
    this.#pollTimer = setTimeout(() => this.#pollLoop(), 0);
  }

  /**
   * Performs one RFC 8936 poll request, acknowledging previously processed SETs.
   * @returns {Promise<{ received: number, moreAvailable: boolean }>}
   */
  async poll() {
    const endpoint = this.stream?.delivery?.endpoint_url;
    if (!endpoint) throw new SSFError('Stream has no poll endpoint_url');
    const ack = this.#pendingAcks.splice(0);
    const setErrs = this.#pendingErrs;
    this.#pendingErrs = {};
    let result;
    try {
      result = await this.#mgmt('POST', endpoint, {
        maxEvents: this.#cfg.maxEvents,
        returnImmediately: true,
        ack,
        ...(Object.keys(setErrs).length ? { setErrs } : {}),
      });
    } catch (err) {
      // Put the acknowledgements back so they're retried on the next poll.
      this.#pendingAcks.unshift(...ack);
      Object.assign(this.#pendingErrs, setErrs);
      throw err;
    }
    const sets = Object.entries(result?.sets ?? {});
    for (const [jti, token] of sets) {
      try {
        const events = await this.validateSet(token);
        this.#pendingAcks.push(jti);
        await this.#dispatchAll(events);
      } catch (err) {
        const code = err instanceof SETValidationError ? err.code : 'invalid_request';
        this.#pendingErrs[jti] = { err: code, description: err.message };
        this.#emitError(err, { phase: 'poll', jti });
      }
    }
    return { received: sets.length, moreAvailable: !!result?.moreAvailable };
  }

  // ---------------------------------------------------------------------------
  // Internals
  // ---------------------------------------------------------------------------

  #deliveryRequest() {
    const c = this.#cfg;
    if (c.deliveryMethod === 'poll') return { method: DELIVERY.POLL };
    c.pushAuthorizationHeader ??= `Bearer ${randomToken(32)}`;
    return { method: DELIVERY.PUSH, endpoint_url: c.pushEndpointUrl, authorization_header: c.pushAuthorizationHeader };
  }

  #checkPushAuthorization(header) {
    const expected = this.#cfg.pushAuthorizationHeader;
    if (!expected) return;
    const a = Buffer.from(header ?? '');
    const b = Buffer.from(expected);
    if (a.length !== b.length || !timingSafeEqual(a, b)) {
      throw new SETValidationError('Missing or invalid Authorization header', 'authentication_failed');
    }
  }

  #startPolling() {
    this.#polling = true;
    this.pollNow();
  }

  async #pollLoop() {
    if (!this.#polling) return;
    let delay = this.#cfg.pollIntervalMs;
    try {
      const { moreAvailable } = await this.poll();
      if (moreAvailable) delay = 0;
    } catch (err) {
      this.#emitError(err, { phase: 'poll' });
    }
    if (this.#polling) {
      this.#pollTimer = setTimeout(() => this.#pollLoop(), delay);
      this.#pollTimer.unref?.();
    }
  }

  async #dispatchAll(events) {
    for (const evt of events) await this.#dispatch(evt);
  }

  async #dispatch(evt) {
    if (evt.type === SSF.VERIFICATION && evt.payload.state) {
      this.#pendingVerifications.get(evt.payload.state)?.(evt);
      this.#pendingVerifications.delete(evt.payload.state);
    }
    if (evt.type === SSF.STREAM_UPDATED && this.stream) {
      this.stream = { ...this.stream, status: evt.payload.status };
    }
    const specific = this.#handlers.get(evt.type);
    const handlers = specific?.size ? [...specific] : [...this.#unhandledHandlers];
    for (const h of [...handlers, ...this.#anyHandlers]) {
      try {
        await h(evt);
      } catch (err) {
        this.#emitError(err, { phase: 'handler', event: evt });
      }
    }
  }

  #emitError(err, context) {
    if (!this.#errorHandlers.size) return;
    for (const h of this.#errorHandlers) {
      try {
        h(err, context);
      } catch { /* never let an error handler break delivery */ }
    }
  }

  #rememberJti(jti) {
    this.#seenJtis.set(jti, Date.now());
    if (this.#seenJtis.size > this.#cfg.jtiCacheSize) {
      this.#seenJtis.delete(this.#seenJtis.keys().next().value);
    }
  }

  #endpoint(name) {
    if (!this.metadata) throw new SSFError('Receiver not initialised; call discover() or start()');
    const url = this.metadata[name];
    if (!url) throw new SSFError(`Transmitter does not advertise ${name}`);
    return url;
  }

  #streamId() {
    const id = this.stream?.stream_id ?? this.#cfg.streamId;
    if (!id) throw new SSFError('No stream; call start() or createStream() first');
    return id;
  }

  async #mgmt(method, url, body) {
    const headers = { accept: 'application/json' };
    if (this.#cfg.accessToken) headers.authorization = `Bearer ${await this.#cfg.accessToken()}`;
    if (body !== undefined) headers['content-type'] = 'application/json';
    const res = await httpRequest(url, {
      method,
      headers,
      body: body === undefined ? undefined : JSON.stringify(body),
      timeoutMs: this.#cfg.httpTimeoutMs,
      fetch: this.#cfg.fetch,
    });
    try {
      return await readJson(res, SSFError);
    } catch (err) {
      if (err instanceof OAuthError) throw new SSFError(err.message, { code: err.error, status: err.status, cause: err });
      throw err;
    }
  }
}

function toSecurityEvent(type, payload, set, raw) {
  return {
    type,
    name: eventName(type),
    payload,
    subject: set.sub_id ?? payload.subject,
    eventTimestamp: payload.event_timestamp ?? set.toe ?? set.iat,
    initiatingEntity: payload.initiating_entity,
    reasonAdmin: payload.reason_admin,
    reasonUser: payload.reason_user,
    jti: set.jti,
    iss: set.iss,
    aud: set.aud,
    iat: set.iat,
    txn: set.txn,
    set,
    raw,
  };
}

function mapJoseError(err) {
  if (err instanceof joseErrors.JWTExpired && err.claim === 'iat') {
    return new SETValidationError(`SET is too old: ${err.message}`, 'invalid_request', err);
  }
  if (err instanceof joseErrors.JWTClaimValidationFailed) {
    if (err.claim === 'iat') return new SETValidationError(`SET iat is not acceptable: ${err.message}`, 'invalid_request', err);
    if (err.claim === 'iss') return new SETValidationError(err.message, 'invalid_issuer', err);
    if (err.claim === 'aud') return new SETValidationError(err.message, 'invalid_audience', err);
    return new SETValidationError(err.message, 'invalid_request', err);
  }
  if (err instanceof joseErrors.JWSSignatureVerificationFailed || err instanceof joseErrors.JWKSNoMatchingKey || err instanceof joseErrors.JOSEAlgNotAllowed) {
    return new SETValidationError(err.message, 'invalid_key', err);
  }
  return new SETValidationError(err.message ?? String(err), 'invalid_request', err);
}

async function readRawBody(req) {
  if (typeof req.body === 'string') return req.body.trim();
  if (Buffer.isBuffer(req.body)) return req.body.toString('utf8').trim();
  let data = '';
  for await (const chunk of req) {
    data += chunk;
    if (data.length > 1_000_000) throw new SETValidationError('SET too large', 'invalid_request');
  }
  return data.trim();
}

function assertFn(fn) {
  if (typeof fn !== 'function') throw new TypeError('handler must be a function');
}
