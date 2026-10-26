import { createRemoteJWKSet, customFetch, decodeProtectedHeader, errors as joseErrors, jwtVerify } from 'jose';
import { ASYMMETRIC_JWS_ALGS } from '../algs.js';
import { discoverSSFTransmitter } from '../discovery.js';
import { OAuthError, SETValidationError, SSFError } from '../errors.js';
import { httpRequest, readJson } from '../http.js';
import { wantsDpopNonce } from '../dpop.js';
import { isSecureUrl, randomToken } from '../util.js';
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
 * @property {Record<string, any>|undefined} subject RFC 9493 subject identifier (`sub_id`, or legacy `subject` inside the event).
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
 * @returns {unknown} Anything; a promise is awaited before the SET is acknowledged.
 */

/**
 * @typedef {object} SSFErrorContext  Where an error came from.
 * @property {'poll'|'handler'|'hook'|'stop'|'error'} phase  `poll`: polling or validating a SET; `handler`: a
 *           handler threw; `hook`: `onEventReceived` threw; `stop`: sending the last acknowledgements failed.
 * @property {string} [jti]          The SET concerned, when there is one.
 * @property {SecurityEvent} [event] The event whose handler threw.
 * @property {boolean} [willRetry]   The SET was left for the transmitter to send again.
 */

/**
 * @callback SSFErrorHandler
 * @param {Error & { code?: string }} error
 * @param {SSFErrorContext} context
 * @returns {void}
 */

/**
 * The default `onEventReceived` hook: prints one line per accepted event to the console, naming the
 * event and its `jti` only. The payload and subject can carry personal data (email, phone, session id,
 * IP address), and a console is read by extensions and error reporters, so they are left out.
 * Call it from your own hook to keep the line.
 * @param {SecurityEvent} event
 * @returns {void}
 */
export function logEventReceived(event) {
  console.log(`[oidc-caep-client] CAEP event received: ${event.name} (jti ${event.jti})`);
}

/** SSF transmitter metadata members that are URLs, all of which must use TLS. */
const SSF_URL_MEMBERS = ['jwks_uri', 'configuration_endpoint', 'status_endpoint', 'add_subject_endpoint',
  'remove_subject_endpoint', 'verification_endpoint'];

/**
 * @typedef {object} SSFReceiverConfig
 * @property {string} transmitterIssuer  SSF transmitter issuer; metadata is loaded from its `/.well-known/ssf-configuration`.
 * Delivery is RFC 8936 POLL: a browser cannot receive a push. (SETs obtained any other way can still be
 * handed to `receiveSet()`.)
 * @property {string|string[]} [audience]  Expected SET `aud`. Defaults to the `aud` in the stream configuration.
 * @property {string[]} [eventsRequested]  Default: all CAEP event types.
 * @property {() => Promise<string>|string} [accessToken]  Bearer token for the transmitter's management and poll endpoints.
 * @property {(req: { method: string, url: string, nonce?: string }) => Promise<Record<string,string>>} [authorizationHeaders]
 *           Alternative to `accessToken`: returns the Authorization (and DPoP) headers for one request, e.g.
 *           `(r) => oidcClient.resourceHeaders(tokenSet, r)` for a DPoP-bound token.
 * @property {string} [streamId]        Use an existing stream instead of creating one.
 * @property {string} [description]
 * @property {number} [pollIntervalMs]  Default 5000.
 * @property {number} [maxEvents]       Max SETs per poll. Default 25.
 * @property {number} [clockToleranceSec] Default 60.
 * @property {number} [maxSetAgeSec]    Reject SETs whose `iat` is older than this (seconds). Default 0: no limit.
 *           A polled SET waits at the transmitter until it is read, so an age limit would throw away the
 *           signals a stopped receiver catches up on. A replay is caught by its `jti` whatever its age.
 * @property {number} [maxDeliveryAttempts] How many times a SET whose handlers throw is left for the
 *           transmitter to send again before it is acknowledged anyway (`onError` gets `handler_failed`).
 *           Default 5. A SET that can't be checked for a reason that may pass (a network error, a signing
 *           key not yet in the JWKS) is never reported as an error: it is left for redelivery until it can.
 * @property {boolean} [allowInsecureRequests] Allow non-TLS SSF URLs other than loopback. Default false.
 * @property {string[]} [trustedPollOrigins] Origins besides the transmitter's issuer and
 *           configuration_endpoint that the stream's poll endpoint_url may be at. The poll request carries
 *           the person's access token, so it is refused anywhere else.
 * @property {boolean} [requireTyp]     Require the `typ: secevent+jwt` header (SSF §4.1.9). Default true.
 * @property {number} [jtiCacheSize]    Replay-protection window size. Default 10000.
 * @property {number} [httpTimeoutMs]
 * @property {typeof fetch} [fetch]
 * @property {Partial<Record<keyof typeof NAMED_HANDLERS, SecurityEventHandler>>} [handlers]
 * @property {SecurityEventHandler|null} [onEventReceived]  Your logic for every accepted event: called
 *           once per event, before the typed handlers, and awaited. Default `logEventReceived`, which
 *           prints the event to the console. `null` turns it off. A throw goes to `onError` with
 *           `phase: 'hook'`, and the typed handlers still run.
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
  /** The poll request in flight, if any: polls never overlap (see poll()). */
  #pollInFlight;
  /** pollNow() was called while a poll was in flight: poll again as soon as it finishes. */
  #pollAgain = false;
  /** The jtis whose handlers are running now; a redelivery of one of them is left alone. */
  #inFlight = new Set();
  #pendingAcks = [];
  #pendingErrs = {};
  #attempts = new Map();

  /** @param {SSFReceiverConfig} config */
  constructor(config) {
    if (!config?.transmitterIssuer) throw new TypeError('transmitterIssuer is required');
    this.#cfg = {
      eventsRequested: Object.values(CAEP),
      pollIntervalMs: 5000,
      maxEvents: 25,
      clockToleranceSec: 60,
      maxSetAgeSec: 0,
      maxDeliveryAttempts: 5,
      allowInsecureRequests: false,
      requireTyp: true,
      jtiCacheSize: 10_000,
      httpTimeoutMs: 10_000,
      description: 'oidc-caep-client receiver',
      onEventReceived: logEventReceived,
      ...config,
    };
    if (this.#cfg.onEventReceived != null) assertFn(this.#cfg.onEventReceived);
    if (this.#cfg.deliveryMethod && this.#cfg.deliveryMethod !== 'poll') {
      throw new TypeError('Only poll delivery (RFC 8936) is supported: a browser cannot receive a push');
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

  /**
   * CAEP session-revoked: the session(s) for the subject were revoked; terminate local sessions.
   * @param {SecurityEventHandler} handler
   * @returns {this}
   */
  onSessionRevoked(handler) { return this.onEvent(CAEP.SESSION_REVOKED, handler); }
  /**
   * CAEP token-claims-change: claims in previously issued tokens changed (payload.claims).
   * @param {SecurityEventHandler} handler
   * @returns {this}
   */
  onTokenClaimsChange(handler) { return this.onEvent(CAEP.TOKEN_CLAIMS_CHANGE, handler); }
  /**
   * CAEP credential-change: a credential was created/revoked/updated/deleted (payload.credential_type, change_type).
   * @param {SecurityEventHandler} handler
   * @returns {this}
   */
  onCredentialChange(handler) { return this.onEvent(CAEP.CREDENTIAL_CHANGE, handler); }
  /**
   * CAEP assurance-level-change: authentication assurance changed (payload.current_level, previous_level, change_direction).
   * @param {SecurityEventHandler} handler
   * @returns {this}
   */
  onAssuranceLevelChange(handler) { return this.onEvent(CAEP.ASSURANCE_LEVEL_CHANGE, handler); }
  /**
   * CAEP device-compliance-change: device compliance changed (payload.current_status: "compliant" | "not-compliant").
   * @param {SecurityEventHandler} handler
   * @returns {this}
   */
  onDeviceComplianceChange(handler) { return this.onEvent(CAEP.DEVICE_COMPLIANCE_CHANGE, handler); }
  /**
   * CAEP session-established: a new session was established (payload.acr, amr, fp_ua, ext_id).
   * @param {SecurityEventHandler} handler
   * @returns {this}
   */
  onSessionEstablished(handler) { return this.onEvent(CAEP.SESSION_ESTABLISHED, handler); }
  /**
   * CAEP session-presented: a session was presented to a service (payload.fp_ua, ext_id).
   * @param {SecurityEventHandler} handler
   * @returns {this}
   */
  onSessionPresented(handler) { return this.onEvent(CAEP.SESSION_PRESENTED, handler); }
  /**
   * CAEP risk-level-change: the risk level of a principal changed (payload.current_level, previous_level, risk_reason, principal).
   * @param {SecurityEventHandler} handler
   * @returns {this}
   */
  onRiskLevelChange(handler) { return this.onEvent(CAEP.RISK_LEVEL_CHANGE, handler); }
  /**
   * SSF verification event (payload.state).
   * @param {SecurityEventHandler} handler
   * @returns {this}
   */
  onVerification(handler) { return this.onEvent(SSF.VERIFICATION, handler); }
  /**
   * SSF stream-updated event (payload.status, payload.reason).
   * @param {SecurityEventHandler} handler
   * @returns {this}
   */
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

  /**
   * Called for every accepted event, after type-specific handlers.
   * @param {SecurityEventHandler} handler
   * @returns {this}
   */
  onAnyEvent(handler) { assertFn(handler); this.#anyHandlers.add(handler); return this; }
  /**
   * Called for events with no type-specific handler.
   * @param {SecurityEventHandler} handler
   * @returns {this}
   */
  onUnhandledEvent(handler) { assertFn(handler); this.#unhandledHandlers.add(handler); return this; }
  /**
   * Called with (error, context) when a SET is rejected, a handler throws, or polling fails.
   * @param {SSFErrorHandler} handler
   * @returns {this}
   */
  onError(handler) { assertFn(handler); this.#errorHandlers.add(handler); return this; }

  /**
   * Removes a handler previously registered with onEvent / on<Name>.
   * @param {string} eventType
   * @param {SecurityEventHandler} handler
   * @returns {this}
   */
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
    // TLS for every SSF URL (RFC 9700 §2.6), loopback excepted: they receive the person's access token,
    // and the JWKS is what every SET is trusted by.
    if (!c.allowInsecureRequests && !isSecureUrl(c.transmitterIssuer)) {
      throw new SSFError(`transmitterIssuer must use https: ${c.transmitterIssuer}`, { code: 'insecure_endpoint' });
    }
    const metadata = await discoverSSFTransmitter(c.transmitterIssuer, { timeoutMs: c.httpTimeoutMs, fetch: c.fetch });
    if (!c.allowInsecureRequests) {
      for (const key of SSF_URL_MEMBERS) {
        if (metadata[key] && !isSecureUrl(metadata[key])) {
          throw new SSFError(`SSF metadata ${key} must use https: ${metadata[key]}`, { code: 'insecure_endpoint' });
        }
      }
    }
    this.metadata = metadata;
    this.#jwks = createRemoteJWKSet(new URL(this.metadata.jwks_uri), {
      timeoutDuration: c.httpTimeoutMs,
      ...(c.fetch ? { [customFetch]: c.fetch } : {}),
    });
    const supported = this.metadata.delivery_methods_supported;
    if (supported && !supported.includes(DELIVERY.POLL)) {
      throw new SSFError(`Transmitter does not support poll delivery (${DELIVERY.POLL})`);
    }
    return this.metadata;
  }

  /**
   * Discovers the transmitter, creates (or reuses) a stream, and starts polling when using poll delivery.
   * If the transmitter already has a stream for this receiver (HTTP 409), that stream is reused and
   * re-pointed at this receiver's delivery settings.
   *
   * With `catchUp`, the SETs already queued on the stream are polled and dispatched before this resolves,
   * e.g. so that a session revoked while the receiver was stopped is acted on before the session is used.
   * @param {{ catchUp?: boolean }} [opts]
   */
  async start({ catchUp = false } = {}) {
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
    for (let more = catchUp; more;) ({ moreAvailable: more } = await this.poll());
    this.#startPolling();
    return this.stream;
  }

  /**
   * Stops polling and optionally deletes the stream at the transmitter.
   * @param {{ deleteStream?: boolean }} [opts]
   */
  async stop({ deleteStream = false } = {}) {
    this.#polling = false;
    clearTimeout(this.#pollTimer);
    // A poll still running may finish handling SETs; their acknowledgements go in the flush below.
    await this.#pollInFlight?.catch(() => {});
    await this.#flushAcks();
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
    this.pollNow();
    return received;
  }

  // ---------------------------------------------------------------------------
  // Delivery
  // ---------------------------------------------------------------------------

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
        // An age limit only when one is configured (see maxSetAgeSec); the future is checked below either way.
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

    if (typeof claims.iat !== 'number' || claims.iat > Date.now() / 1000 + c.clockToleranceSec) {
      throw new SETValidationError('SET iat is missing or in the future', 'invalid_request');
    }
    if (!claims.events || typeof claims.events !== 'object' || Array.isArray(claims.events)) {
      throw new SETValidationError('SET "events" claim must be an object', 'invalid_request');
    }
    // SSF 1.0 §4.1.8: the events claim contains exactly one event.
    const types = Object.keys(claims.events);
    if (types.length !== 1) {
      throw new SETValidationError(`SET "events" claim must contain exactly one event, not ${types.length}`, 'invalid_request');
    }
    // A stream event (verification, stream-updated) is about a stream, named by an opaque sub_id. One that
    // names another stream, or something else, is not about this one.
    if ((types[0] === SSF.VERIFICATION || types[0] === SSF.STREAM_UPDATED) && claims.sub_id !== undefined) {
      const ours = this.stream?.stream_id ?? c.streamId;
      if (claims.sub_id?.format !== 'opaque' || (ours && claims.sub_id.id !== ours)) {
        throw new SETValidationError(`${eventName(types[0])} event is not about this stream`, 'invalid_request');
      }
    }
    if (this.#seenJtis.has(claims.jti)) return [];
    this.#rememberJti(claims.jti);

    return Object.entries(claims.events).map(([type, payload]) => toSecurityEvent(type, payload ?? {}, claims, token));
  }

  /** Triggers an immediate poll (poll delivery only). */
  pollNow() {
    if (!this.#polling) return;
    // During a poll the loop's timer has already fired, so clearing it would not stop that loop: a new
    // timer here would start a second one. Ask the running loop to poll again instead.
    if (this.#pollInFlight) {
      this.#pollAgain = true;
      return;
    }
    this.#scheduleLoop(0);
  }

  #scheduleLoop(delay) {
    clearTimeout(this.#pollTimer);
    this.#pollTimer = setTimeout(() => this.#pollLoop(), delay);
    this.#pollTimer.unref?.();
  }

  /**
   * Performs one RFC 8936 poll request, acknowledging previously processed SETs.
   * @returns {Promise<{ received: number, moreAvailable: boolean }>}
   */
  poll() {
    // One poll at a time. Two overlapping polls both receive a SET that is not acknowledged yet, and the
    // second would see it as a replay while the first is still handling it. A call during a poll shares it.
    if (!this.#pollInFlight) {
      this.#pollInFlight = this.#pollOnce().finally(() => { this.#pollInFlight = undefined; });
    }
    return this.#pollInFlight;
  }

  async #pollOnce() {
    const endpoint = this.#pollEndpoint();
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
    for (const [jti, token] of sets) await this.#receivePolled(jti, token);
    return { received: sets.length, moreAvailable: !!result?.moreAvailable };
  }

  /**
   * One polled SET. RFC 8936 §2.4: an acknowledged SET, and one reported in `setErrs`, are never sent again.
   * So a SET is acknowledged only once its handlers have run without throwing, and reported only when it is
   * definitely invalid. One whose handlers threw is left for the transmitter to send again, up to
   * `maxDeliveryAttempts` times; one that couldn't be checked for a reason that may pass is left until it can.
   */
  async #receivePolled(jti, token) {
    // Being handled right now (a poll from another receiver instance, or one shared by poll() callers):
    // neither acknowledged nor reported, so the transmitter keeps it until that handling finishes.
    if (this.#inFlight.has(jti)) return;
    this.#inFlight.add(jti);
    try {
      await this.#receivePolledOnce(jti, token);
    } finally {
      this.#inFlight.delete(jti);
    }
  }

  async #receivePolledOnce(jti, token) {
    let events;
    try {
      events = await this.validateSet(token);
    } catch (err) {
      // May pass later (the JWKS unreachable, a rotated key the cached set lacks; jose waits 30 s before
      // fetching the set again): never reported, however often, so the transmitter keeps sending it.
      if (err.retryable) {
        this.#emitError(err, { phase: 'poll', jti, willRetry: true });
        return;
      }
      this.#attempts.delete(jti);
      const code = err instanceof SETValidationError ? err.code : 'invalid_request';
      this.#pendingErrs[jti] = { err: code, description: err.message };
      this.#emitError(err, { phase: 'poll', jti });
      return;
    }
    const handled = await this.#dispatchAll(events);
    if (!handled && this.#attempt(jti) < this.#cfg.maxDeliveryAttempts) {
      // Let the redelivery through the replay check: it is the same SET, not handled yet.
      for (const evt of events) this.#seenJtis.delete(evt.jti);
      return;
    }
    if (!handled) {
      this.#emitError(new SSFError(`Gave up on SET ${jti} after ${this.#cfg.maxDeliveryAttempts} attempts; its handlers kept throwing`,
        { code: 'handler_failed' }), { phase: 'handler', jti });
    }
    this.#attempts.delete(jti);
    // Once: two overlapping polls (a pollNow() beside the loop) can both receive a SET before either acks it.
    if (!this.#pendingAcks.includes(jti)) this.#pendingAcks.push(jti);
  }

  /** Counts one more attempt at a SET, returning the count. Bounded like the jti cache. */
  #attempt(jti) {
    const n = (this.#attempts.get(jti) ?? 0) + 1;
    this.#attempts.set(jti, n);
    if (this.#attempts.size > this.#cfg.jtiCacheSize) this.#attempts.delete(this.#attempts.keys().next().value);
    return n;
  }

  /**
   * The poll endpoint, which receives the person's access token on every request. It comes from the stream
   * configuration, not the transmitter's metadata, so it must use TLS and share an origin with the
   * transmitter's own endpoints: a stream re-pointed elsewhere must not be handed the token.
   */
  #pollEndpoint() {
    const endpoint = this.stream?.delivery?.endpoint_url;
    if (!endpoint) throw new SSFError('Stream has no poll endpoint_url');
    if (!this.#cfg.allowInsecureRequests && !isSecureUrl(endpoint)) {
      throw new SSFError(`Poll endpoint_url must use https: ${endpoint}`, { code: 'insecure_endpoint' });
    }
    const origin = new URL(endpoint).origin;
    const trusted = [this.metadata?.issuer, this.metadata?.configuration_endpoint, ...(this.#cfg.trustedPollOrigins ?? [])]
      .filter(Boolean).map((u) => new URL(u).origin);
    if (!trusted.includes(origin)) {
      throw new SSFError(`Poll endpoint_url ${endpoint} is not at the transmitter's origin (${trusted.join(', ')}); not sending the access token there`,
        { code: 'untrusted_endpoint' });
    }
    return endpoint;
  }

  /** Sends the acknowledgements and errors still owed, so a stopped receiver is not sent them again. */
  async #flushAcks() {
    if (!this.#pendingAcks.length && !Object.keys(this.#pendingErrs).length) return;
    if (!this.stream?.delivery?.endpoint_url || !this.metadata) return;
    const ack = this.#pendingAcks.splice(0);
    const setErrs = this.#pendingErrs;
    this.#pendingErrs = {};
    try {
      await this.#mgmt('POST', this.#pollEndpoint(), {
        maxEvents: 0,
        returnImmediately: true,
        ack,
        ...(Object.keys(setErrs).length ? { setErrs } : {}),
      });
    } catch (err) {
      this.#pendingAcks.unshift(...ack);
      Object.assign(this.#pendingErrs, setErrs);
      this.#emitError(err, { phase: 'stop' });
    }
  }

  // ---------------------------------------------------------------------------
  // Internals
  // ---------------------------------------------------------------------------

  #deliveryRequest() {
    return { method: DELIVERY.POLL };
  }

  #startPolling() {
    this.#polling = true;
    this.pollNow();
  }

  async #pollLoop() {
    if (!this.#polling) return;
    this.#pollAgain = false;
    let delay = this.#cfg.pollIntervalMs;
    try {
      const { moreAvailable } = await this.poll();
      if (moreAvailable) delay = 0;
    } catch (err) {
      this.#emitError(err, { phase: 'poll' });
    }
    if (this.#pollAgain) delay = 0;
    if (this.#polling) this.#scheduleLoop(delay);
  }

  /** @returns {Promise<boolean>} false when a handler threw */
  async #dispatchAll(events) {
    let ok = true;
    for (const evt of events) ok = (await this.#dispatch(evt)) && ok;
    return ok;
  }

  async #dispatch(evt) {
    if (evt.type === SSF.VERIFICATION && evt.payload.state) {
      this.#pendingVerifications.get(evt.payload.state)?.(evt);
      this.#pendingVerifications.delete(evt.payload.state);
    }
    // validateSet() refused a stream event that names another stream; one with no sub_id is the stream's.
    if (evt.type === SSF.STREAM_UPDATED && this.stream) {
      this.stream = { ...this.stream, status: evt.payload.status };
    }
    if (this.#cfg.onEventReceived) {
      try {
        await this.#cfg.onEventReceived(evt);
      } catch (err) {
        this.#emitError(err, { phase: 'hook', event: evt });
      }
    }
    const specific = this.#handlers.get(evt.type);
    const handlers = specific?.size ? [...specific] : [...this.#unhandledHandlers];
    let ok = true;
    for (const h of [...handlers, ...this.#anyHandlers]) {
      try {
        await h(evt);
      } catch (err) {
        ok = false;
        this.#emitError(err, { phase: 'handler', event: evt });
      }
    }
    return ok;
  }

  #emitError(err, context) {
    if (!this.#errorHandlers.size) {
      // Never silent: a security event that could not be handled must leave a trace.
      console.error(`[oidc-caep-client] ${context?.phase ?? 'error'}: ${err?.message ?? err}`);
      return;
    }
    for (const h of this.#errorHandlers) {
      try {
        // An async handler's rejection is caught too: never let an error handler break delivery.
        Promise.resolve(h(err, context)).catch(() => {});
      } catch { /* a synchronous throw, likewise */ }
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
    const href = String(url);
    const send = async (nonce) => {
      const headers = { accept: 'application/json' };
      if (this.#cfg.authorizationHeaders) {
        Object.assign(headers, await this.#cfg.authorizationHeaders({ method, url: href, nonce }));
      } else if (this.#cfg.accessToken) {
        headers.authorization = `Bearer ${await this.#cfg.accessToken()}`;
      }
      if (body !== undefined) headers['content-type'] = 'application/json';
      return httpRequest(href, {
        method,
        headers,
        body: body === undefined ? undefined : JSON.stringify(body),
        timeoutMs: this.#cfg.httpTimeoutMs,
        fetch: this.#cfg.fetch,
      });
    };
    let res = await send();
    // A resource server may demand a DPoP nonce (RFC 9449 §9): retry once with it.
    if (this.#cfg.authorizationHeaders && wantsDpopNonce(res)) {
      const nonce = res.headers.get('dpop-nonce');
      await res.body?.cancel();
      res = await send(nonce);
    }
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

/** jose errors that say the SET itself is bad. Anything else (fetching the JWKS, a key it doesn't hold yet) may pass. */
const DEFINITE_JOSE_ERRORS = [joseErrors.JWTClaimValidationFailed, joseErrors.JWTExpired, joseErrors.JWSSignatureVerificationFailed,
  joseErrors.JOSEAlgNotAllowed, joseErrors.JWSInvalid, joseErrors.JWTInvalid, joseErrors.JOSENotSupported];

function mapJoseError(err) {
  const mapped = mapDefiniteJoseError(err);
  if (mapped) return mapped;
  // A network error or timeout fetching the JWKS, a JWKS that couldn't be read, or a kid it doesn't hold yet
  // (a rotation the cached set hasn't caught up with): the SET may verify on a later attempt.
  const code = err instanceof joseErrors.JWKSNoMatchingKey ? 'invalid_key' : 'invalid_request';
  return Object.assign(new SETValidationError(err?.message ?? String(err), code, err), { retryable: true });
}

function mapDefiniteJoseError(err) {
  if (!DEFINITE_JOSE_ERRORS.some((E) => err instanceof E)) return undefined;
  if (err instanceof joseErrors.JWTExpired && err.claim === 'iat') {
    return new SETValidationError(`SET is too old: ${err.message}`, 'invalid_request', err);
  }
  if (err instanceof joseErrors.JWTClaimValidationFailed) {
    if (err.claim === 'iat') return new SETValidationError(`SET iat is not acceptable: ${err.message}`, 'invalid_request', err);
    if (err.claim === 'iss') return new SETValidationError(err.message, 'invalid_issuer', err);
    if (err.claim === 'aud') return new SETValidationError(err.message, 'invalid_audience', err);
    return new SETValidationError(err.message, 'invalid_request', err);
  }
  if (err instanceof joseErrors.JWSSignatureVerificationFailed || err instanceof joseErrors.JOSEAlgNotAllowed) {
    return new SETValidationError(err.message, 'invalid_key', err);
  }
  return new SETValidationError(err.message ?? String(err), 'invalid_request', err);
}

function assertFn(fn) {
  if (typeof fn !== 'function') throw new TypeError('handler must be a function');
}
