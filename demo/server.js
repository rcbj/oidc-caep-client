/**
 * CAEP demo: a Backend-for-Frontend (BFF) that uses oidc-caep-client to
 *   1. sign users in with OIDC (Authorization Code + PKCE) against any OpenID Connect Core 1.0 provider,
 *   2. cache their tokens server-side and refresh them automatically,
 *   3. subscribe to CAEP events over the Shared Signals Framework and react to them,
 * and serves a small SPA that shows all of this live over Server-Sent Events.
 *
 * The identity provider is configured at runtime from the SPA's configuration screen: an OpenID Provider
 * metadata document (pasted, or fetched from a discovery URL), a client_id and an optional client_secret.
 */
import { randomBytes } from 'node:crypto';
import { fileURLToPath } from 'node:url';
import express from 'express';
import { decodeJwt, decodeProtectedHeader } from 'jose';
import {
  CAEP, deleteClientRegistration, discoverOpenIdProvider, SUPPORTED_ID_TOKEN_ALGS, discoverSSFTransmitter, OIDCClient, oidcDiscoveryUrl, SSFReceiver, Subject, subjectMatches, TokenManager,
} from 'oidc-caep-client';

/** Environment variable, treating empty strings (as passed by docker compose) as unset. */
const env = (name) => process.env[name] || undefined;

const PORT = Number(env('PORT') ?? 3000);
const PUBLIC_URL = (env('PUBLIC_URL') ?? `http://localhost:${PORT}`).replace(/\/+$/, '');
const REFRESH_SKEW_SEC = Number(env('TOKEN_REFRESH_SKEW_SEC') ?? 60);
const SECURE_COOKIE = PUBLIC_URL.startsWith('https://');
const IS_LOCAL = /^https?:\/\/(localhost|127\.|\[::1\])/.test(PUBLIC_URL);

/** URLs the IdP administrator registers for this client. */
const URLS = {
  redirectUri: `${PUBLIC_URL}/callback`,
  postLogoutRedirectUri: `${PUBLIC_URL}/`,
  pushEndpointUrl: `${PUBLIC_URL}/caep/events`,
};

const app = express();
app.disable('x-powered-by');

// -----------------------------------------------------------------------------
// Sessions (in-memory, cookie-referenced) and live updates (SSE)
// -----------------------------------------------------------------------------

/** @type {Map<string, { id: string, transaction?: object, user?: Record<string, any>, stepUpRequired?: string, refreshCount: number, lastRefresh?: number, endedReason?: string }>} */
const sessions = new Map();
const sseClients = new Set();
const eventLog = [];

function getSession(req, res) {
  const sid = /(?:^|;\s*)demo_sid=([\w-]+)/.exec(req.headers.cookie ?? '')?.[1];
  let s = sid && sessions.get(sid);
  if (!s) {
    s = { id: randomBytes(24).toString('base64url'), refreshCount: 0 };
    sessions.set(s.id, s);
    res.setHeader('set-cookie', `demo_sid=${s.id}; Path=/; HttpOnly; SameSite=Lax${SECURE_COOKIE ? '; Secure' : ''}`);
  }
  return s;
}

/** Sends an SSE message to one session's browser tabs, or to everyone when sid is null. */
function push(sid, event, data) {
  const msg = `event: ${event}\ndata: ${JSON.stringify(data)}\n\n`;
  for (const c of sseClients) if (!sid || c.sid === sid) c.res.write(msg);
}

function sessionView(s) {
  const tokens = s.tokens;
  return {
    authenticated: !!s.user,
    user: s.user,
    endedReason: s.endedReason,
    stepUpRequired: s.stepUpRequired,
    token: tokens && {
      expires_at: tokens.expires_at,
      issued_at: tokens.issued_at,
      has_refresh_token: !!tokens.refresh_token,
      refresh_count: s.refreshCount,
      last_refresh: s.lastRefresh,
      skew_sec: REFRESH_SKEW_SEC,
    },
  };
}

async function publishSession(s) {
  s.tokens = await tokens?.get(s.id);
  push(s.id, 'session', sessionView(s));
}


// -----------------------------------------------------------------------------
// Runtime configuration (set from the SPA, or pre-seeded from environment variables)
// -----------------------------------------------------------------------------

/**
 * @typedef {object} DemoConfig
 * @property {Record<string, any>} metadata  OpenID Provider metadata document
 * @property {string} clientId
 * @property {string} [clientSecret]
 * @property {string} [tokenEndpointAuthMethod]  undefined = choose automatically
 * @property {string} [scope]
 * @property {{ enabled: boolean, transmitterIssuer?: string, delivery: 'push'|'poll', managementScope?: string, managementToken?: string, subjectFormat: 'iss_sub'|'email' }} caep
 */

/** @type {DemoConfig|undefined} */ let config;
/** @type {OIDCClient|undefined} */ let client;
/** @type {TokenManager|undefined} */ let tokens;
/** @type {SSFReceiver|undefined} */ let receiver;
let ssfState = { status: 'not-configured' };
let caepGeneration = 0;

/** Short CAEP event names the UI offers; the first five are requested by default. */
const CAEP_EVENT_NAMES = Object.values(CAEP).map((uri) => uri.split('/').pop());
const DEFAULT_CAEP_EVENTS = ['session-revoked', 'credential-change', 'token-claims-change', 'assurance-level-change', 'device-compliance-change'];

const describe = (err) => {
  const json = err.response && typeof err.response === 'object' ? JSON.stringify(err.response) : '';
  const detail = json && !err.message.includes(json) ? ` ${json}` : '';
  const status = err.status && !err.userError && !err.message.includes(String(err.status)) ? ` (HTTP ${err.status})` : '';
  return `${err.message}${status}${detail}`.slice(0, 500);
};

function broadcastStatus() {
  push(null, 'status', {});
}

/** Parses the metadata field: a JSON object or a JSON string. */
function parseMetadata(value) {
  if (value && typeof value === 'object') return value;
  try {
    return JSON.parse(String(value ?? ''));
  } catch (err) {
    throw Object.assign(new Error(`Metadata is not valid JSON: ${err.message}`), { status: 400, userError: true });
  }
}

/**
 * Validates and applies a new configuration. The previous client, sessions and CAEP stream are torn down
 * only after the new configuration has been accepted.
 */
async function applyConfig(input) {
  const metadata = parseMetadata(input.metadata);
  const dynamic = input.registration?.mode === 'dynamic';
  const authMethod = input.tokenEndpointAuthMethod || undefined;
  const idTokenAlg = input.idTokenSignedResponseAlg || undefined;
  const scope = input.scope?.trim() || undefined;
  const caep = {
    enabled: input.caep?.enabled !== false,
    // Stored only when it differs from the OIDC issuer, so the default follows the metadata.
    transmitterIssuer: (input.caep?.transmitterIssuer?.trim() || undefined) === metadata.issuer ? undefined : input.caep?.transmitterIssuer?.trim() || undefined,
    delivery: input.caep?.delivery === 'push' ? 'push' : 'poll',
    managementScope: input.caep?.managementScope?.trim() || undefined,
    managementToken: input.caep?.managementToken?.trim() || (input.caep?.keepManagementToken ? config?.caep.managementToken : undefined),
    subjectFormat: input.caep?.subjectFormat === 'email' ? 'email' : 'iss_sub',
    // How the SSF management API (and poll endpoint) is authorised: the signed-in user's access token,
    // a client credentials token, or a pasted static token.
    // Name signed-in users as stream subjects, so only events about them are delivered.
    onlySignedInUsers: input.caep?.onlySignedInUsers !== false,
    maxSetAgeSec: Number.isFinite(Number(input.caep?.maxSetAgeSec)) && input.caep?.maxSetAgeSec !== '' && input.caep?.maxSetAgeSec !== undefined
      ? Math.max(0, Math.floor(Number(input.caep.maxSetAgeSec))) : 3600,
    managementAuth: ['user', 'client_credentials', 'token'].includes(input.caep?.managementAuth) ? input.caep.managementAuth : 'user',
    events: Array.isArray(input.caep?.events)
      ? input.caep.events.filter((e) => CAEP_EVENT_NAMES.includes(e))
      : DEFAULT_CAEP_EVENTS,
  };
  if (caep.enabled && caep.managementAuth === 'token' && !caep.managementToken) throw Object.assign(new Error('Paste the management API bearer token, or choose another credential'), { status: 400, userError: true });
  if (caep.enabled && !caep.events.length) throw Object.assign(new Error('Select at least one CAEP event to request'), { status: 400, userError: true });

  const clientOptions = {
    redirectUri: URLS.redirectUri,
    postLogoutRedirectUri: URLS.postLogoutRedirectUri,
    scope,
  };

  let nextClient;
  let clientId;
  let clientSecret;
  let registration;
  if (dynamic) {
    // OpenID Connect Dynamic Client Registration: the ID token signing alg is fixed at registration time,
    // and OIDCClient.register rejects the result if the OP registers a different one.
    const request = registrationRequest(metadata, { idTokenAlg: idTokenAlg ?? pickIdTokenAlg(metadata), authMethod, scope, caep, clientName: input.registration.clientName });
    const softwareStatement = input.registration.softwareStatement?.trim();
    if (softwareStatement) request.software_statement = softwareStatement;
    ({ client: nextClient, registration } = await OIDCClient.register(metadata, request, {
      ...clientOptions,
      initialAccessToken: input.registration.initialAccessToken?.trim() || undefined,
    }));
    const { software_statement: _ss, ...requested } = request;
    registration = { ...registration, registered_at: Date.now(), requested };
    clientId = registration.client_id;
    clientSecret = registration.client_secret;
    console.log(`[dcr] registered client ${clientId} (id_token_signed_response_alg=${nextClient.config.idTokenSignedResponseAlg}, auth=${nextClient.config.tokenEndpointAuthMethod})`);
  } else {
    clientId = String(input.clientId ?? '').trim();
    if (!clientId) throw Object.assign(new Error('client_id is required'), { status: 400, userError: true });
    clientSecret = input.clientSecret ? String(input.clientSecret) : input.keepSecret ? config?.clientSecret : undefined;
    // Keep the registration record when continuing to use a dynamically registered client.
    if (config?.registration?.client_id === clientId) registration = config.registration;
    // OIDCClient validates the metadata document (required fields, response_type=code, ID token alg, auth method).
    nextClient = await OIDCClient.fromMetadata(metadata, {
      ...clientOptions,
      clientId,
      clientSecret,
      tokenEndpointAuthMethod: authMethod,
      idTokenSignedResponseAlg: idTokenAlg ?? registration?.id_token_signed_response_alg ?? pickIdTokenAlg(metadata),
    });
  }

  const previousRegistration = config?.registration;
  await teardown('The application was reconfigured. Please sign in again.');

  // A dynamically registered client that is being replaced is deleted at the OP (RFC 7592), best effort.
  if (previousRegistration && previousRegistration.client_id !== clientId && previousRegistration.registration_client_uri) {
    deleteClientRegistration(previousRegistration)
      .then(() => console.log(`[dcr] deleted previous client ${previousRegistration.client_id}`))
      .catch((err) => console.warn(`[dcr] could not delete previous client ${previousRegistration.client_id}: ${describe(err)}`));
  }

  config = {
    metadata,
    clientId,
    clientSecret,
    tokenEndpointAuthMethod: dynamic ? undefined : authMethod,
    idTokenSignedResponseAlg: dynamic ? nextClient.config.idTokenSignedResponseAlg : idTokenAlg,
    scope,
    caep,
    registration,
  };
  client = nextClient;
  tokens = new TokenManager(client, { refreshSkewSec: REFRESH_SKEW_SEC });
  tokens.on('refreshed', async (sid, ts) => {
    const s = sessions.get(sid);
    if (!s) return;
    s.user = ts.claims;
    s.refreshCount += 1;
    s.lastRefresh = Date.now();
    console.log(`[tokens] refreshed session ${sid.slice(0, 6)}… (#${s.refreshCount}), expires in ${ts.expiresIn()}s`);
    await publishSession(s);
  });
  tokens.on('refresh_error', (sid, err) => console.warn(`[tokens] refresh failed for ${sid.slice(0, 6)}…: ${err.message}`));
  tokens.on('expired', (sid) => {
    const s = sessions.get(sid);
    if (s?.user) endSession(s, 'Your tokens could not be renewed (refresh token rejected by the IdP).');
  });

  console.log(`[oidc] configured for ${metadata.issuer}; client ${clientId}; auth ${client.config.tokenEndpointAuthMethod}; scope "${client.config.scope}"`);
  broadcastStatus();
  connectCaep();
}

/**
 * Builds an OIDC Dynamic Client Registration request for this app, using only values the OP advertises.
 */
function registrationRequest(metadata, { idTokenAlg, authMethod, scope, caep, clientName }) {
  const grantsSupported = metadata.grant_types_supported ?? ['authorization_code', 'implicit'];
  const wantsOffline = (metadata.scopes_supported ?? []).includes('offline_access');
  const needsClientCredentials = caep.enabled && caep.managementAuth === 'client_credentials';
  const grantTypes = ['authorization_code', 'refresh_token', ...(needsClientCredentials ? ['client_credentials'] : [])]
    .filter((g) => grantsSupported.includes(g));
  const authMethods = metadata.token_endpoint_auth_methods_supported ?? ['client_secret_basic'];
  const scopes = new Set((scope ?? `openid profile email${wantsOffline ? ' offline_access' : ''}`).split(/\s+/).filter(Boolean));
  if (needsClientCredentials && caep.managementScope) for (const sc of caep.managementScope.split(/\s+/)) scopes.add(sc);
  return {
    application_type: 'web',
    client_name: clientName?.trim() || 'oidc-caep-client demo',
    redirect_uris: [URLS.redirectUri],
    post_logout_redirect_uris: [URLS.postLogoutRedirectUri],
    response_types: ['code'],
    grant_types: grantTypes,
    token_endpoint_auth_method: authMethod ?? (authMethods.includes('client_secret_basic') ? 'client_secret_basic' : 'client_secret_post'),
    id_token_signed_response_alg: idTokenAlg,
    scope: [...scopes].join(' '),
  };
}

/** RS256 is the OIDC default; otherwise the first advertised asymmetric alg this library can verify. */
function pickIdTokenAlg(metadata) {
  const algs = metadata.id_token_signing_alg_values_supported ?? [];
  if (algs.includes('RS256')) return 'RS256';
  return algs.find((a) => SUPPORTED_ID_TOKEN_ALGS.includes(a) && !a.startsWith('HS')) ?? 'RS256';
}

async function teardown(reason) {
  caepGeneration++;
  const oldReceiver = receiver;
  receiver = undefined;
  // Delete the stream first: with managementAuth=user it is authorised by a session about to end.
  if (oldReceiver) await oldReceiver.stop({ deleteStream: true });
  for (const s of sessions.values()) if (s.user) await endSession(s, reason);
  tokens?.close();
  ssfTokenSid = undefined;
  ssfState = { status: 'not-configured' };
}

const activeSessions = () => [...sessions.values()].filter((s) => s.user);

/** The session whose access token currently authorises the SSF stream (managementAuth = user). */
let ssfTokenSid;

/**
 * Returns a fresh access token of a signed-in user for the SSF management and poll endpoints, preferring
 * the session that created the stream. Tokens are refreshed by the TokenManager as needed.
 */
async function userAccessToken() {
  const order = [ssfTokenSid, ...activeSessions().map((s) => s.id)].filter(Boolean);
  for (const sid of new Set(order)) {
    if (!sessions.get(sid)?.user) continue;
    try {
      const at = await tokens.getAccessToken(sid);
      ssfTokenSid = sid;
      return at;
    } catch {
      // try the next signed-in user
    }
  }
  throw Object.assign(new Error('No signed-in user access token is available for the SSF stream'), { code: 'no_user_token' });
}

/** Creates the SSF stream for the current configuration (in the background; status is shown in the UI). */
async function connectCaep() {
  const gen = ++caepGeneration;
  if (receiver) {
    const old = receiver;
    receiver = undefined;
    await old.stop({ deleteStream: true });
  }
  if (!config?.caep.enabled) {
    ssfState = { status: 'disabled' };
    return broadcastStatus();
  }
  const c = config.caep;
  const transmitterIssuer = c.transmitterIssuer ?? config.metadata.issuer;
  ssfState = { status: 'connecting', transmitter: transmitterIssuer };
  broadcastStatus();

  let accessToken;
  if (c.managementAuth === 'token') {
    accessToken = () => c.managementToken;
  } else if (c.managementAuth === 'client_credentials') {
    if (client.config.tokenEndpointAuthMethod === 'none') {
      ssfState = { status: 'error', transmitter: transmitterIssuer, error: 'The client credentials grant needs a confidential client (a client_secret). Use the signed-in user\'s access token instead.' };
      return broadcastStatus();
    }
    accessToken = () => tokens.getClientCredentialsToken({ scope: c.managementScope });
  } else {
    // The signed-in user's access token (kept fresh by the TokenManager) authorises the stream.
    if (!activeSessions().length) {
      ssfState = { status: 'waiting-for-user', transmitter: transmitterIssuer, info: 'Sign in: the stream is created with your access token.' };
      return broadcastStatus();
    }
    accessToken = userAccessToken;
  }

  const r = new SSFReceiver({
    transmitterIssuer,
    deliveryMethod: c.delivery,
    pushEndpointUrl: URLS.pushEndpointUrl,
    eventsRequested: c.events.map((name) => Object.values(CAEP).find((uri) => uri.endsWith(`/${name}`))),
    description: `oidc-caep-client demo @ ${PUBLIC_URL}`,
    accessToken,
    pollIntervalMs: 5000,
    maxSetAgeSec: c.maxSetAgeSec,
    handlers: caepHandlers,
  });
  try {
    await r.start();
  } catch (err) {
    if (gen !== caepGeneration) return;
    console.warn(`[caep] could not start stream: ${describe(err)}`);
    ssfState = { status: 'error', transmitter: transmitterIssuer, error: describe(err) };
    return broadcastStatus();
  }
  if (gen !== caepGeneration) {
    await r.stop({ deleteStream: true });
    return;
  }
  receiver = r;
  trackedSubjects.clear();
  ssfState = {
    status: 'connected',
    transmitter: transmitterIssuer,
    streamStatus: r.stream.status ?? 'enabled',
    authorizedBy: c.managementAuth === 'user' ? `access token of ${sessions.get(ssfTokenSid)?.user?.email ?? sessions.get(ssfTokenSid)?.user?.sub ?? 'signed-in user'}` : c.managementAuth === 'client_credentials' ? 'client credentials token' : 'static bearer token',
  };
  console.log(`[caep] stream ${r.stream.stream_id} (${c.delivery}) delivering ${r.stream.events_delivered?.length ?? 0} event types`);
  broadcastStatus();
  r.requestVerification({ timeoutMs: 30_000 }).catch((err) => console.warn(`[caep] verification: ${err.message}`));
  // Register subjects for anyone already signed in.
  for (const s of sessions.values()) if (s.user) trackSubject(s.user);
}

// -----------------------------------------------------------------------------
// CAEP: one handler per event type, each deciding what this app does about it
// -----------------------------------------------------------------------------

function sessionsFor(evt) {
  return [...sessions.values()].filter((s) => s.user && subjectMatches(evt.subject, {
    iss: s.user.iss, sub: s.user.sub, email: s.user.email, sid: s.user.sid,
  }));
}

async function endSession(s, reason) {
  const user = s.user;
  s.user = undefined;
  s.stepUpRequired = undefined;
  s.endedReason = reason;
  await tokens.delete(s.id);
  await publishSession(s);
  if (user) untrackSubject(user);
}

/**
 * Wraps a CAEP handler: finds the local sessions the event is about, runs the app's policy,
 * then records and broadcasts what was done.
 * @param {(evt: import('oidc-caep-client').SecurityEvent, affected: object[]) => Promise<string>|string} policy
 */
function handle(policy) {
  return async (evt) => {
    const affected = sessionsFor(evt);
    let action;
    try {
      action = await policy(evt, affected);
    } catch (err) {
      action = `Handler failed: ${err.message}`;
    }
    const entry = {
      at: Date.now(),
      name: evt.name,
      type: evt.type,
      jti: evt.jti,
      subject: evt.subject,
      payload: evt.payload,
      affected: affected.length,
      action,
    };
    eventLog.unshift(entry);
    eventLog.length = Math.min(eventLog.length, 100);
    console.log(`[caep] ${evt.name} → ${action}`);
    push(null, 'caep', entry);
  };
}

const none = (affected) => (affected.length ? null : 'No active local session for this subject.');

const caepHandlers = {
  sessionRevoked: handle(async (evt, affected) => {
    for (const s of affected) {
      await endSession(s, evt.reasonUser?.en ?? 'Your session was revoked by the identity provider.');
    }
    return none(affected) ?? `Terminated ${affected.length} session(s) and discarded cached tokens.`;
  }),

  tokenClaimsChange: handle(async (evt, affected) => {
    for (const s of affected) {
      try {
        await tokens.refresh(s.id);
      } catch {
        await endSession(s, 'Your session ended because updated claims could not be retrieved.');
      }
    }
    const claims = Object.entries(evt.payload.claims ?? {}).map(([k, v]) => `${k}=${JSON.stringify(v)}`).join(', ');
    return none(affected) ?? `Refreshed tokens to pick up new claims (${claims}).`;
  }),

  credentialChange: handle(async (evt, affected) => {
    const { credential_type: type, change_type: change } = evt.payload;
    const what = type ? `${type} credential` : 'credential';
    const how = change ? `${change}d` : 'changed';
    if (['revoke', 'delete'].includes(change)) {
      for (const s of affected) await endSession(s, `Your ${what} was ${how}; please sign in again.`);
      return none(affected) ?? `Credential ${how} → terminated ${affected.length} session(s).`;
    }
    for (const s of affected) push(s.id, 'notice', { level: 'info', text: `Your ${what} was ${how} at the identity provider.` });
    return none(affected) ?? `Credential ${how} → user notified; session kept.`;
  }),

  assuranceLevelChange: handle(async (evt, affected) => {
    const { current_level: current, previous_level: previous, change_direction: dir } = evt.payload;
    for (const s of affected) {
      s.stepUpRequired = dir === 'decrease' ? `Assurance dropped from ${previous} to ${current}.` : undefined;
      await publishSession(s);
    }
    return none(affected) ?? (dir === 'decrease'
      ? `Assurance ${previous} → ${current}: step-up authentication required.`
      : `Assurance ${previous} → ${current}: step-up requirement cleared.`);
  }),

  deviceComplianceChange: handle(async (evt, affected) => {
    const { current_status: status } = evt.payload;
    if (status === 'not-compliant') {
      for (const s of affected) await endSession(s, 'Your device is no longer compliant with security policy.');
      return none(affected) ?? `Device not-compliant → terminated ${affected.length} session(s).`;
    }
    for (const s of affected) push(s.id, 'notice', { level: 'info', text: 'Your device is compliant again.' });
    return none(affected) ?? 'Device compliant → no action needed.';
  }),

  riskLevelChange: handle(async (evt, affected) => {
    const { current_level: level, risk_reason: why } = evt.payload;
    for (const s of affected) {
      if (level === 'HIGH') await endSession(s, `Sign-in blocked: high risk detected (${why}).`);
      else {
        s.stepUpRequired = level === 'MEDIUM' ? `Risk level raised to MEDIUM (${why}).` : undefined;
        await publishSession(s);
      }
    }
    const act = { HIGH: `terminated ${affected.length} session(s)`, MEDIUM: 'step-up required', LOW: 'step-up cleared' }[level] ?? 'no action';
    return none(affected) ?? `Risk ${level} → ${act}.`;
  }),

  sessionEstablished: handle((evt, affected) => `Informational: new session at IdP (acr=${evt.payload.acr ?? 'n/a'}). ${affected.length} local session(s) for subject.`),

  sessionPresented: handle((_evt, affected) => `Informational: session presented to another service. ${affected.length} local session(s) for subject.`),

  verification: handle((evt) => `Stream verified (state=${evt.payload.state ?? 'none'}).`),

  streamUpdated: handle((evt) => {
    ssfState = { ...ssfState, streamStatus: evt.payload.status };
    return `Transmitter changed stream status to "${evt.payload.status}"${evt.payload.reason ? ` (${evt.payload.reason})` : ''}.`;
  }),

  unhandled: handle((evt) => `No handler registered for ${evt.type}.`),

  error: (err, ctx) => {
    console.warn(`[caep] ${ctx.phase} error: ${describe(err)}`);
    if (ctx.phase === 'poll' && (err.code === 'no_user_token' || err.cause?.code === 'no_user_token') && receiver) {
      // Nobody is signed in any more: stop polling; the stream is replaced at the next sign-in.
      receiver.stop();
      ssfState = { ...ssfState, status: 'waiting-for-user', info: 'Polling paused: no signed-in user token. Sign in to resume.' };
      broadcastStatus();
    } else if (ctx.phase === 'poll') {
      ssfState = { ...ssfState, error: `Last poll failed at ${new Date().toLocaleTimeString()}: ${describe(err)}` };
      broadcastStatus();
    }
  },
};

// Subject add/remove calls are chained so a quick logout → login can't reorder them at the transmitter.
let subjectOps = Promise.resolve();
function enqueueSubjectOp(label, op) {
  subjectOps = subjectOps.then(op).catch((err) => console.warn(`[caep] ${label} failed: ${describe(err)}`));
  return subjectOps;
}

function subjectFor(user) {
  return config?.caep.subjectFormat === 'email' && user.email ? Subject.email(user.email) : Subject.issSub(user.iss, user.sub);
}

/** Subjects this app has added to the current stream, by JSON key. Reset when a stream is (re)created. */
const trackedSubjects = new Set();

/**
 * Adds a signed-in user to the stream's subject list, so the transmitter sends events about them.
 *
 * This is done even when the transmitter advertises default_subjects=ALL: there, an EMPTY list means
 * "every subject in the realm", and naming subjects narrows the stream to them.
 */
function trackSubject(user) {
  const r = receiver;
  if (!r?.stream || !r.metadata.add_subject_endpoint || !config?.caep.onlySignedInUsers) return Promise.resolve();
  const subject = subjectFor(user);
  return enqueueSubjectOp('addSubject', async () => {
    await r.addSubject(subject);
    trackedSubjects.add(JSON.stringify(subject));
    console.log(`[caep] subject added: ${JSON.stringify(subject)}`);
    broadcastStatus();
  });
}

function untrackSubject(user) {
  const r = receiver;
  if (!r?.stream || !r.metadata.remove_subject_endpoint || !config?.caep.onlySignedInUsers) return Promise.resolve();
  const subject = subjectFor(user);
  const key = JSON.stringify(subject);
  return enqueueSubjectOp('removeSubject', async () => {
    const stillActive = [...sessions.values()].some((s) => s.user?.sub === user.sub);
    if (stillActive || !trackedSubjects.has(key)) return;
    // Under default_subjects=ALL, removing the LAST subject would empty the list and silently widen the
    // stream back to every subject in the realm. Keep it instead.
    if (r.metadata.default_subjects === 'ALL' && trackedSubjects.size === 1) {
      console.log(`[caep] kept last subject ${key}: an empty list means ALL subjects on this transmitter`);
      return;
    }
    await r.removeSubject(subject);
    trackedSubjects.delete(key);
    console.log(`[caep] subject removed: ${key}`);
    broadcastStatus();
  });
}

// -----------------------------------------------------------------------------
// Routes
// -----------------------------------------------------------------------------

const ready = (_req, res, next) => (client ? next() : res.redirect('/?error=' + encodeURIComponent('Configure the identity provider first.')));

// Browsers can't add custom headers to cross-site form posts, so requiring one blocks CSRF.
const csrf = (req, res, next) => (req.method === 'GET' || req.headers['x-demo-csrf'] === '1' ? next() : res.status(403).json({ error: 'csrf' }));

app.post('/caep/events', (req, res) => {
  if (!receiver) return res.status(503).end();
  return receiver.pushHandler()(req, res);
});

app.get('/login', ready, (req, res) => {
  const s = getSession(req, res);
  const { url, transaction } = client.authorizationUrl(req.query.stepup ? { prompt: 'login' } : {});
  s.transaction = transaction;
  res.redirect(url);
});

app.get('/callback', ready, async (req, res) => {
  const s = getSession(req, res);
  try {
    const ts = await client.callback(req.query, s.transaction);
    await tokens.set(s.id, ts);
    Object.assign(s, { user: ts.claims, signInTokens: ts.toJSON(), transaction: undefined, endedReason: undefined, stepUpRequired: undefined, refreshCount: 0, lastRefresh: undefined });
    await trackSubject(ts.claims);
    // With managementAuth=user the stream is created (or resumed) with the first signed-in user's token.
    if (config.caep.enabled && config.caep.managementAuth === 'user' && ssfState.status !== 'connected' && ssfState.status !== 'connecting') {
      ssfTokenSid = s.id;
      connectCaep();
    }
    res.redirect('/');
  } catch (err) {
    console.warn(`[oidc] callback failed: ${describe(err)}`);
    res.redirect(`/?error=${encodeURIComponent(err.message)}`);
  }
});

app.post('/logout', csrf, async (req, res) => {
  const s = getSession(req, res);
  const ts = client && (await tokens.get(s.id));
  const user = s.user;
  const lastUser = activeSessions().length === 1 && activeSessions()[0] === s;
  if (lastUser && receiver && config?.caep.managementAuth === 'user') {
    // The stream is authorised by this user's token: delete it while the token is still valid.
    const r = receiver;
    receiver = undefined;
    await r.stop({ deleteStream: true });
    ssfState = { status: 'waiting-for-user', transmitter: ssfState.transmitter, info: 'Stream deleted at sign-out. Sign in to create it again.' };
    broadcastStatus();
  }
  s.user = undefined;
  s.endedReason = undefined;
  if (ts) await tokens.delete(s.id, { revoke: true });
  if (user) untrackSubject(user);
  res.json({ redirect: (ts && client.endSessionUrl({ idTokenHint: ts.id_token })) || '/' });
});

const api = express.Router();
api.use(express.json({ limit: '256kb' }));
api.use(csrf);

function configView() {
  return {
    configured: !!client,
    urls: URLS,
    isLocal: IS_LOCAL,
    caepEvents: CAEP_EVENT_NAMES,
    supportedIdTokenAlgs: SUPPORTED_ID_TOKEN_ALGS,
    defaultCaepEvents: DEFAULT_CAEP_EVENTS,
    current: config && {
      metadata: config.metadata,
      issuer: config.metadata.issuer,
      clientId: config.clientId,
      hasClientSecret: !!config.clientSecret,
      tokenEndpointAuthMethod: config.tokenEndpointAuthMethod ?? '',
      effectiveAuthMethod: client?.config.tokenEndpointAuthMethod,
      idTokenSignedResponseAlg: config.idTokenSignedResponseAlg ?? '',
      effectiveIdTokenAlg: client?.config.idTokenSignedResponseAlg,
      scope: config.scope ?? '',
      effectiveScope: client?.config.scope,
      caep: { ...config.caep, managementToken: undefined, hasManagementToken: !!config.caep.managementToken },
      registration: config.registration && {
        client_id: config.registration.client_id,
        client_name: config.registration.client_name,
        id_token_signed_response_alg: config.registration.id_token_signed_response_alg ?? config.registration.requested.id_token_signed_response_alg,
        token_endpoint_auth_method: config.registration.token_endpoint_auth_method,
        grant_types: config.registration.grant_types ?? config.registration.requested.grant_types,
        scope: config.registration.scope ?? config.registration.requested.scope,
        client_secret_expires_at: config.registration.client_secret_expires_at,
        registered_at: config.registration.registered_at,
        manageable: !!config.registration.registration_client_uri,
      },
    },
  };
}

api.get('/session', async (req, res) => {
  const s = getSession(req, res);
  s.tokens = await tokens?.get(s.id);
  res.json({
    ...sessionView(s),
    config: configView(),
    ssf: {
      ...ssfState,
      stream_id: receiver?.stream?.stream_id,
      delivery: receiver?.stream?.delivery?.method,
      events_delivered: receiver?.stream?.events_delivered ?? [],
      default_subjects: receiver?.metadata?.default_subjects,
      aud: receiver?.stream?.aud,
      subjects: [...trackedSubjects].map((k) => JSON.parse(k)),
      only_signed_in_users: config?.caep.onlySignedInUsers,
      max_set_age_sec: config?.caep.maxSetAgeSec,
    },
  });
});

/**
 * Fetches a metadata document server-side (avoids CORS). Accepts an issuer or a full discovery URL,
 * and also reports whether the issuer publishes SSF transmitter metadata.
 */
api.post('/config/discover', async (req, res) => {
  const input = String(req.body?.url ?? '').trim();
  let url;
  try {
    url = new URL(input);
  } catch {
    return res.status(400).json({ error: 'Enter an issuer URL or a .well-known/openid-configuration URL.' });
  }
  if (!['http:', 'https:'].includes(url.protocol)) return res.status(400).json({ error: 'Only http(s) URLs are supported.' });
  const suffix = '/.well-known/openid-configuration';
  const issuer = url.pathname.endsWith(suffix) ? `${url.origin}${url.pathname.slice(0, -suffix.length)}` : input.replace(/\/+$/, '');
  try {
    // Try the issuer as typed and without a trailing slash; the document's issuer must match exactly.
    let metadata;
    try {
      metadata = await discoverOpenIdProvider(issuer);
    } catch (err) {
      if (err.code !== 'issuer_mismatch') throw err;
      metadata = await discoverOpenIdProvider(`${issuer}/`);
    }
    let ssf;
    try {
      const t = await discoverSSFTransmitter(metadata.issuer, { timeoutMs: 5000 });
      ssf = { found: true, delivery_methods_supported: t.delivery_methods_supported, default_subjects: t.default_subjects };
    } catch (err) {
      ssf = { found: false, error: err.message };
    }
    res.json({ metadata, discoveryUrl: oidcDiscoveryUrl(metadata.issuer), ssf });
  } catch (err) {
    res.status(400).json({ error: describe(err) });
  }
});

api.get('/config', (_req, res) => res.json(configView()));

api.post('/config', async (req, res) => {
  try {
    await applyConfig(req.body ?? {});
    res.json(configView());
  } catch (err) {
    res.status(err.status ?? 400).json({ error: describe(err) });
  }
});

api.post('/ssf/connect', async (_req, res) => {
  if (!client) return res.status(409).json({ error: 'not_configured' });
  await connectCaep();
  res.json(ssfState);
});

/** A token for display: raw value plus, for a JWT, its decoded (unverified) header and claims. */
function tokenView(value) {
  if (!value) return undefined;
  try {
    return { raw: value, jwt: true, header: decodeProtectedHeader(value), payload: decodeJwt(value) };
  } catch {
    return { raw: value, jwt: false };
  }
}

function tokenSetView(ts) {
  if (!ts) return undefined;
  return {
    token_type: ts.token_type,
    scope: ts.scope,
    expires_at: ts.expires_at,
    issued_at: ts.issued_at,
    access_token: tokenView(ts.access_token),
    refresh_token: tokenView(ts.refresh_token),
    id_token: tokenView(ts.id_token),
  };
}

// Debugging aid: shows the signed-in user's own tokens. (A production BFF would never send these to the browser.)
api.get('/tokens', async (req, res) => {
  const s = getSession(req, res);
  if (!s.user) return res.status(401).json({ error: 'not_authenticated' });
  res.json({
    signIn: tokenSetView(s.signInTokens),
    current: tokenSetView(await tokens.get(s.id)),
    refreshCount: s.refreshCount,
    usedForSsf: config?.caep.managementAuth === 'user' && ssfTokenSid === s.id && ssfState.status === 'connected',
  });
});

api.get('/userinfo', async (req, res) => {
  const s = getSession(req, res);
  if (!s.user) return res.status(401).json({ error: 'not_authenticated' });
  try {
    // getAccessToken transparently refreshes if the cached token is (nearly) expired.
    const at = await tokens.getAccessToken(s.id);
    res.json(await client.userinfo(at, { expectedSub: s.user.sub }));
  } catch (err) {
    res.status(502).json({ error: err.code ?? 'error', message: err.message });
  }
});

api.post('/refresh', async (req, res) => {
  const s = getSession(req, res);
  if (!s.user) return res.status(401).json({ error: 'not_authenticated' });
  try {
    await tokens.refresh(s.id);
    res.json(sessionView(s));
  } catch (err) {
    res.status(502).json({ error: err.code ?? 'error', message: err.message });
  }
});

api.post('/ssf/verify', async (_req, res) => {
  if (!receiver?.stream) return res.status(503).json({ error: 'no_stream' });
  try {
    const evt = await receiver.requestVerification({ timeoutMs: 15_000 });
    res.json({ ok: true, jti: evt.jti });
  } catch (err) {
    res.status(502).json({ error: err.code ?? 'error', message: describe(err) });
  }
});

api.get('/events', (req, res) => {
  const s = getSession(req, res);
  res.writeHead(200, { 'content-type': 'text/event-stream', 'cache-control': 'no-cache', connection: 'keep-alive' });
  res.write(`event: history\ndata: ${JSON.stringify(eventLog)}\n\n`);
  const c = { res, sid: s.id };
  sseClients.add(c);
  const ping = setInterval(() => res.write(': ping\n\n'), 25_000);
  req.on('close', () => {
    clearInterval(ping);
    sseClients.delete(c);
  });
});

app.use('/api', api);
app.use(express.static(fileURLToPath(new URL('./public', import.meta.url)), { index: 'index.html' }));

// -----------------------------------------------------------------------------
// Startup / shutdown
// -----------------------------------------------------------------------------

const server = app.listen(PORT, async () => {
  console.log(`Demo listening on ${PUBLIC_URL}`);
  console.log(`  redirect_uri:             ${URLS.redirectUri}`);
  console.log(`  post_logout_redirect_uri: ${URLS.postLogoutRedirectUri}`);
  console.log(`  CAEP push endpoint:       ${URLS.pushEndpointUrl}`);

  // Optional pre-configuration from the environment; otherwise configure from the UI.
  const issuer = env('OIDC_ISSUER');
  const clientId = env('OIDC_CLIENT_ID');
  if (!issuer || !clientId) {
    console.log('No OIDC_ISSUER/OIDC_CLIENT_ID set — open the app to configure the identity provider.');
    return;
  }
  try {
    await applyConfig({
      metadata: await discoverOpenIdProvider(issuer),
      clientId,
      clientSecret: env('OIDC_CLIENT_SECRET'),
      tokenEndpointAuthMethod: env('OIDC_TOKEN_ENDPOINT_AUTH_METHOD'),
      idTokenSignedResponseAlg: env('OIDC_ID_TOKEN_ALG'),
      scope: env('OIDC_SCOPE'),
      caep: {
        enabled: env('SSF_DISABLED') !== 'true',
        transmitterIssuer: env('SSF_TRANSMITTER_ISSUER'),
        delivery: env('SSF_DELIVERY') ?? (IS_LOCAL ? 'poll' : 'push'),
        managementScope: env('SSF_SCOPE'),
        managementToken: env('SSF_ACCESS_TOKEN'),
        managementAuth: env('SSF_MANAGEMENT_AUTH') ?? (env('SSF_ACCESS_TOKEN') ? 'token' : 'user'),
        subjectFormat: env('SSF_SUBJECT_FORMAT'),
        events: env('SSF_EVENTS')?.split(',').map((e) => e.trim()),
        maxSetAgeSec: env('SSF_MAX_SET_AGE_SEC'),
        onlySignedInUsers: env('SSF_ALL_SUBJECTS') !== 'true',
      },
    });
  } catch (err) {
    console.warn(`[oidc] configuration from environment failed: ${describe(err)}`);
  }
});

async function shutdown() {
  console.log('Shutting down…');
  for (const c of sseClients) c.res.end();
  tokens?.close();
  await receiver?.stop({ deleteStream: true });
  server.close(() => process.exit(0));
  setTimeout(() => process.exit(0), 3000).unref();
}
process.on('SIGTERM', shutdown);
process.on('SIGINT', shutdown);
