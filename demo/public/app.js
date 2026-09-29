// CAEP demo SPA. The OIDC client runs HERE, in the browser, as a public client: Authorization Code + PKCE,
// state/nonce, PAR, DPoP with a non-extractable key, RFC 9207, token caching with auto-refresh, and a
// CAEP (Shared Signals) stream polled with the signed-in user's access token.
import { decodeJwt, decodeProtectedHeader } from 'jose';
import {
  CAEP, discoverSSFTransmitter, IndexedDBKeyStore, MemoryKeyStore, MemoryTokenStore, OIDCClient, oidcDiscoveryUrl,
  SSFReceiver, Subject, subjectMatches, SUPPORTED_ID_TOKEN_ALGS, TokenManager, validateOpenIdProviderMetadata, WebStorageTokenStore,
} from 'oidc-caep-client';

const $ = (id) => document.getElementById(id);
const ORIGIN = location.origin;
const URLS = { redirectUri: `${ORIGIN}/callback`, postLogoutRedirectUri: `${ORIGIN}/` };
const KEY = 'user';
const CAEP_EVENT_NAMES = Object.values(CAEP).map((u) => u.split('/').pop());
const DEFAULT_CAEP_EVENTS = ['session-revoked', 'credential-change', 'token-claims-change', 'assurance-level-change', 'device-compliance-change'];
const CONFIG_KEY = 'oidc-caep-demo.config';
const FORM_STORE_KEY = 'oidc-caep-demo.config-form';
const STREAM_KEY = 'oidc-caep-demo.stream-id';
const LOG_KEY = 'oidc-caep-demo.event-log';
const SIGNIN_KEY = 'signin';
const NOT_STORED = new Set(['initial-token']);

/** @type {OIDCClient|undefined} */ let client;
/** @type {TokenManager|undefined} */ let tokens;
/** @type {SSFReceiver|undefined} */ let receiver;
let config;
let tokenStore;
const ui = { user: undefined, refreshCount: 0, lastRefresh: undefined, stepUp: undefined, ended: undefined, notices: [], error: undefined };
let ssfState = { status: 'not-configured' };

// ---------------------------------------------------------------------------
// Small helpers
// ---------------------------------------------------------------------------

const store = {
  get(key, storage = localStorage) {
    try { return JSON.parse(storage.getItem(key) ?? 'null'); } catch { return null; }
  },
  set(key, value, storage = localStorage) {
    try { storage.setItem(key, JSON.stringify(value)); } catch { /* storage unavailable */ }
  },
  del(key, storage = localStorage) {
    try { storage.removeItem(key); } catch { /* storage unavailable */ }
  },
};

function el(tag, attrs = {}, ...children) {
  const node = document.createElement(tag);
  for (const [k, v] of Object.entries(attrs)) {
    if (k.startsWith('on')) node.addEventListener(k.slice(2), v);
    else node.setAttribute(k, v);
  }
  node.append(...children.filter((c) => c !== '' && c !== undefined && c !== null));
  return node;
}

async function withBusy(button, fn) {
  button.disabled = true;
  try { await fn(); } finally { button.disabled = false; }
}

const describe = (err) => {
  const json = err?.response && typeof err.response === 'object' ? JSON.stringify(err.response) : '';
  const detail = json && !err.message.includes(json) ? ` ${json}` : '';
  const status = err?.status && !err.message.includes(String(err.status)) ? ` (HTTP ${err.status})` : '';
  const msg = /Failed to fetch|NetworkError|Load failed/i.test(err?.message ?? '')
    ? `${err.message}: the IdP refused the request from this origin (CORS), or is unreachable`
    : err?.message ?? String(err);
  return `${msg}${status}${detail}`.slice(0, 600);
};

// ---------------------------------------------------------------------------
// Configuration → client
// ---------------------------------------------------------------------------

async function applyConfig(cfg, { register, startup } = {}) {
  // Reconfiguring deletes the old stream; at start-up the remembered stream is kept for reuse.
  if (!startup) await stopCaep({ deleteStream: true });
  tokens?.close();
  const metadata = typeof cfg.metadata === 'string' ? JSON.parse(cfg.metadata) : cfg.metadata;
  validateOpenIdProviderMetadata(metadata);
  const common = {
    redirectUri: URLS.redirectUri,
    postLogoutRedirectUri: URLS.postLogoutRedirectUri,
    scope: cfg.scope || undefined,
    resource: cfg.resource || undefined,
    par: cfg.par ?? 'auto',
    dpop: cfg.dpop ? { keyStore: typeof indexedDB === 'undefined' ? new MemoryKeyStore() : new IndexedDBKeyStore() } : false,
    idTokenSignedResponseAlg: cfg.idTokenAlg || pickIdTokenAlg(metadata),
  };
  if (register) {
    const { client: registered, registration } = await OIDCClient.register(metadata, register.request, { ...common, initialAccessToken: register.initialAccessToken });
    client = registered;
    cfg = { ...cfg, clientId: registration.client_id, idTokenAlg: client.config.idTokenSignedResponseAlg, registeredAt: Date.now() };
  } else {
    if (!cfg.clientId) throw new Error('client_id is required');
    client = await OIDCClient.fromMetadata(metadata, { ...common, clientId: cfg.clientId });
  }
  config = { ...cfg, metadata };
  store.set(CONFIG_KEY, config);

  tokenStore = config.tokenStorage === 'session' ? new WebStorageTokenStore() : new MemoryTokenStore();
  tokens = new TokenManager(client, { store: tokenStore, refreshSkewSec: 60 });
  tokens.on('refreshed', (_key, ts) => {
    ui.user = ts.claims;
    ui.refreshCount += 1;
    ui.lastRefresh = Date.now();
    render();
  });
  tokens.on('expired', () => endLocalSession('Your tokens could not be renewed (the refresh token was rejected).'));
  return client;
}

function pickIdTokenAlg(metadata) {
  const algs = metadata.id_token_signing_alg_values_supported ?? [];
  if (algs.includes('RS256')) return 'RS256';
  return algs.find((a) => SUPPORTED_ID_TOKEN_ALGS.includes(a)) ?? 'RS256';
}

// ---------------------------------------------------------------------------
// Sign-in, callback, sign-out
// ---------------------------------------------------------------------------

async function signIn({ stepUp } = {}) {
  if (!client) return;
  try {
    const { url } = await client.createAuthorizationRequest({
      prompt: stepUp ? 'login' : undefined,
      acrValues: config.acrValues || undefined,
    });
    location.assign(url);
  } catch (err) {
    ui.error = `Could not start sign-in: ${describe(err)}`;
    render();
  }
}

async function completeCallback() {
  try {
    const ts = await client.callback(location.href);
    await tokens.set(KEY, ts);
    await tokenStore.set(SIGNIN_KEY, ts.toJSON());
    Object.assign(ui, { user: ts.claims, ended: undefined, stepUp: undefined, refreshCount: 0, lastRefresh: undefined, error: undefined });
  } catch (err) {
    ui.error = `Sign-in failed: ${describe(err)}`;
  } finally {
    history.replaceState(null, '', '/');
  }
}

async function signOut() {
  const ts = await tokens?.get(KEY);
  await signOutLocally();
  ui.ended = undefined;
  const logout = ts && await client.createEndSessionRequest({ idTokenHint: ts.id_token }).catch(() => undefined);
  if (logout) location.assign(logout.url);
  else render();
}

async function signOutLocally() {
  await stopCaep({ deleteStream: true });
  await tokens?.delete(KEY, { revoke: true }).catch(() => {});
  await tokenStore?.delete(SIGNIN_KEY);
  ui.user = undefined;
}

async function endLocalSession(reason) {
  if (!ui.user) return;
  ui.user = undefined;
  ui.stepUp = undefined;
  ui.ended = reason;
  await stopCaep({ deleteStream: true });
  await tokens.delete(KEY).catch(() => {});
  await tokenStore.delete(SIGNIN_KEY);
  render();
}

// ---------------------------------------------------------------------------
// CAEP: a stream authorised by the signed-in user's (DPoP-bound) access token, polled from here
// ---------------------------------------------------------------------------

function subjectFor(user) {
  return config.caep.subjectFormat === 'email' && user.email ? Subject.email(user.email) : Subject.issSub(user.iss, user.sub);
}

async function startCaep() {
  if (!config?.caep?.enabled || !ui.user || receiver) return;
  const c = config.caep;
  const transmitterIssuer = c.transmitterIssuer || config.metadata.issuer;
  ssfState = { status: 'connecting', transmitter: transmitterIssuer };
  render();
  const make = (streamId) => new SSFReceiver({
    transmitterIssuer,
    streamId,
    // Every management and poll call carries the user's access token, with a DPoP proof when bound.
    authorizationHeaders: async (req) => client.resourceHeaders(await tokens.getTokenSet(KEY), req),
    eventsRequested: c.events.map((n) => Object.values(CAEP).find((u) => u.endsWith(`/${n}`))),
    description: `oidc-caep-client in-browser demo @ ${ORIGIN}`,
    pollIntervalMs: 5000,
    maxSetAgeSec: c.maxSetAgeSec,
    handlers: caepHandlers,
  });
  try {
    const held = store.get(STREAM_KEY, sessionStorage);
    let r = make(held ?? undefined);
    try {
      await r.start();
    } catch (err) {
      if (!held) throw err;
      // The remembered stream is gone (deleted, or not ours any more): create a new one.
      await r.stop();
      r = make();
      await r.start();
    }
    receiver = r;
    store.set(STREAM_KEY, r.stream.stream_id, sessionStorage);
    if (c.onlyUser && r.metadata.add_subject_endpoint) {
      await r.addSubject(subjectFor(ui.user)).catch((err) => log({ name: 'subject', action: `Could not add the subject: ${describe(err)}` }));
    }
    ssfState = { status: 'connected', transmitter: transmitterIssuer, streamStatus: r.stream.status ?? 'enabled' };
    r.requestVerification({ timeoutMs: 30_000 }).catch(() => {});
  } catch (err) {
    ssfState = { status: 'error', transmitter: transmitterIssuer, error: describe(err) };
  }
  render();
}

async function stopCaep({ deleteStream } = {}) {
  const r = receiver;
  receiver = undefined;
  if (r) await r.stop({ deleteStream }).catch(() => {});
  if (deleteStream) store.del(STREAM_KEY, sessionStorage);
  ssfState = { status: config?.caep?.enabled ? 'waiting-for-user' : 'disabled', transmitter: ssfState.transmitter };
}

const eventLog = store.get(LOG_KEY, sessionStorage) ?? [];

function log(entry) {
  // Poll delivery is at-least-once: a SET delivered but not yet acknowledged before a reload comes again.
  if (entry.jti && eventLog.some((e) => e.jti === entry.jti)) return;
  const full = { at: Date.now(), ...entry };
  eventLog.unshift(full);
  eventLog.length = Math.min(eventLog.length, 100);
  store.set(LOG_KEY, eventLog, sessionStorage);
  addLogEntry(full, true);
}

/** Wraps a policy: only events about the signed-in user (or about the stream itself) are acted on. */
function handle(policy) {
  return async (evt) => {
    if (evt.jti && eventLog.some((e) => e.jti === evt.jti)) return;
    const mine = ui.user && subjectMatches(evt.subject, { iss: ui.user.iss, sub: ui.user.sub, email: ui.user.email, sid: ui.user.sid });
    const aboutStream = !evt.subject || evt.subject.format === 'opaque' && evt.subject.id === receiver?.stream?.stream_id;
    let action;
    try {
      action = mine || aboutStream ? await policy(evt) : 'About another user; ignored.';
    } catch (err) {
      action = `Handler failed: ${describe(err)}`;
    }
    log({ name: evt.name, type: evt.type, jti: evt.jti, subject: evt.subject, payload: evt.payload, action });
    render();
  };
}

const caepHandlers = {
  sessionRevoked: handle(async (evt) => {
    await endLocalSession(evt.reasonUser?.en ?? 'Your session was revoked by the identity provider.');
    return 'Session ended; tokens discarded.';
  }),
  tokenClaimsChange: handle(async (evt) => {
    await tokens.refresh(KEY);
    return `Refreshed tokens for new claims (${Object.keys(evt.payload.claims ?? {}).join(', ') || 'unspecified'}).`;
  }),
  credentialChange: handle(async (evt) => {
    const { credential_type: type = 'credential', change_type: change } = evt.payload;
    if (['revoke', 'delete'].includes(change)) {
      await endLocalSession(`Your ${type} was ${change}d; please sign in again.`);
      return `Credential ${change}d: session ended.`;
    }
    ui.notices.unshift({ level: 'info', text: `Your ${type} was ${change ? `${change}d` : 'changed'} at the identity provider.` });
    return 'User notified; session kept.';
  }),
  assuranceLevelChange: handle((evt) => {
    const { current_level: current, previous_level: previous, change_direction: dir } = evt.payload;
    ui.stepUp = dir === 'decrease' ? `Assurance dropped from ${previous} to ${current}.` : undefined;
    return dir === 'decrease' ? 'Step-up authentication required.' : 'Step-up requirement cleared.';
  }),
  deviceComplianceChange: handle(async (evt) => {
    if (evt.payload.current_status === 'not-compliant') {
      await endLocalSession('Your device is no longer compliant with security policy.');
      return 'Device not compliant: session ended.';
    }
    return 'Device compliant: no action.';
  }),
  riskLevelChange: handle(async (evt) => {
    const { current_level: level, risk_reason: why } = evt.payload;
    if (level === 'HIGH') {
      await endLocalSession(`Signed out: high risk detected (${why ?? 'no reason given'}).`);
      return 'Risk HIGH: session ended.';
    }
    ui.stepUp = level === 'MEDIUM' ? `Risk raised to MEDIUM (${why ?? 'no reason given'}).` : undefined;
    return `Risk ${level}: ${level === 'MEDIUM' ? 'step-up required' : 'step-up cleared'}.`;
  }),
  sessionEstablished: handle((evt) => `Informational: new session at the IdP (acr=${evt.payload.acr ?? 'n/a'}).`),
  sessionPresented: handle(() => 'Informational: session presented to another service.'),
  verification: handle((evt) => `Stream verified (state=${evt.payload.state ?? 'none'}).`),
  streamUpdated: handle((evt) => {
    ssfState = { ...ssfState, streamStatus: evt.payload.status };
    return `Transmitter set the stream to "${evt.payload.status}".`;
  }),
  unhandled: handle((evt) => `No handler for ${evt.type}.`),
  error: (err, ctx) => {
    if (ctx.phase === 'poll') {
      ssfState = { ...ssfState, error: `Last poll failed at ${new Date().toLocaleTimeString()}: ${describe(err)}` };
      render();
    }
  },
};

// ---------------------------------------------------------------------------
// Rendering
// ---------------------------------------------------------------------------

async function render() {
  const configured = !!client;
  const authenticated = !!ui.user;
  $('signed-out').hidden = authenticated || !configured;
  $('session-card').hidden = !authenticated;
  $('token-card').hidden = !authenticated;
  $('tokens-card').hidden = !authenticated;
  $('security-card').hidden = !configured;

  $('who').replaceChildren(...(authenticated
    ? [
        el('span', { class: 'avatar', 'aria-hidden': 'true' }, String(ui.user.name ?? ui.user.email ?? ui.user.sub)[0].toUpperCase()),
        el('span', {}, ui.user.name ?? ui.user.email ?? ui.user.sub),
        el('button', { class: 'btn ghost', onclick: () => signOut() }, 'Sign out'),
      ]
    : configured ? [el('button', { class: 'btn primary', onclick: () => signIn() }, 'Sign in')] : []));

  if (authenticated) {
    const shown = ['sub', 'name', 'email', 'acr', 'amr', 'sid', 'iss', 'auth_time'];
    $('claims').replaceChildren(...shown.filter((k) => ui.user[k] !== undefined).flatMap((k) => [
      el('dt', {}, k),
      el('dd', {}, k === 'auth_time' ? new Date(ui.user[k] * 1000).toLocaleTimeString() : typeof ui.user[k] === 'object' ? JSON.stringify(ui.user[k]) : String(ui.user[k])),
    ]));
    const pill = $('session-pill');
    pill.textContent = ui.stepUp ? 'Step-up required' : 'Active';
    pill.className = `pill ${ui.stepUp ? 'warn' : 'ok'}`;
    $('refresh-count').textContent = `${ui.refreshCount} refreshes`;
  }

  if (configured) {
    const f = client.securityFeatures;
    const items = [
      ['Public client', 'no client secret; token_endpoint_auth_method none'],
      ['PKCE', f.pkce],
      ['state', f.state],
      ['nonce', 'random, checked against the ID token'],
      ['Issuer identification', f.issuerIdentification],
      ['Pushed Authorization Requests', f.par ? 'on: the request never passes through the browser URL' : 'off'],
      ['DPoP', f.dpop ? `on (${f.dpop.alg}, non-extractable key, jkt ${f.dpop.jkt.slice(0, 12)}…)` : 'off: bearer tokens'],
      ['ID token', f.idToken],
      ['TLS', f.tlsEnforced ? 'required for the IdP and redirect URIs (loopback excepted)' : 'not enforced'],
      ['Tokens stored in', config.tokenStorage === 'session' ? 'sessionStorage (this tab)' : 'memory only'],
      ['Resource indicators', f.resourceIndicators ? f.resourceIndicators.join(', ') : 'none'],
      ['Page', 'CSP (no inline script), Referrer-Policy no-referrer, framing denied'],
    ];
    $('security-list').replaceChildren(...items.map(([k, v]) => el('li', {}, el('strong', {}, k), el('span', { class: 'muted' }, ` ${v}`))));
  }

  renderConfig();
  renderStream();
  renderBanners();
  tick();
  await renderTokens();
}

function renderStream() {
  const status = ssfState.status === 'connected' ? ssfState.streamStatus ?? 'enabled' : ssfState.status;
  const pill = $('ssf-pill');
  pill.textContent = status;
  pill.className = `pill ${status === 'enabled' ? 'ok' : status === 'error' ? 'danger' : 'warn'}`;
  const s = receiver?.stream;
  $('ssf-info').replaceChildren(...[
    ['transmitter', ssfState.transmitter ?? '—'],
    ...(s ? [['stream_id', s.stream_id], ['delivery', 'poll (RFC 8936)'], ['SET audience', [].concat(s.aud ?? '—').join(', ')]] : []),
    ...(receiver?.metadata?.default_subjects ? [['default_subjects', receiver.metadata.default_subjects]] : []),
    ...(ssfState.status === 'waiting-for-user' ? [['note', 'Sign in: the stream is created with your access token.']] : []),
  ].flatMap(([k, v]) => [el('dt', {}, k), el('dd', {}, v)]));
  $('ssf-events').replaceChildren(...(s?.events_delivered ?? []).map((e) => el('span', { class: 'chip', title: e }, e.split('/').pop())));
  $('btn-verify').disabled = !s;
  $('btn-reconnect').disabled = !ui.user || !config?.caep?.enabled;
  $('ssf-error').hidden = !ssfState.error;
  $('ssf-error').textContent = ssfState.error ?? '';
  $('live').classList.toggle('on', !!s);
}

function renderBanners() {
  const items = [];
  const banner = (level, title, text, action) => el('div', { class: `banner ${level}`, role: level === 'danger' ? 'alert' : 'status' },
    el('div', {}, el('strong', {}, title), el('span', {}, text)), action ?? '');
  if (ui.error) items.push(banner('danger', 'Something went wrong', ui.error, el('button', { class: 'btn', onclick: () => { ui.error = undefined; render(); } }, 'Dismiss')));
  if (!ui.user && ui.ended) items.push(banner('danger', 'Your session was ended', ui.ended, el('button', { class: 'btn', onclick: () => signIn() }, 'Sign in again')));
  if (ui.user && ui.stepUp) items.push(banner('warn', 'Step-up authentication required', ui.stepUp, el('button', { class: 'btn', onclick: () => signIn({ stepUp: true }) }, 'Re-authenticate')));
  for (const n of ui.notices.slice(0, 3)) items.push(banner(n.level, 'Notice from the identity provider', n.text));
  $('banners').replaceChildren(...items);
}

async function tick() {
  const t = ui.user && await tokens?.get(KEY);
  if (!t?.expires_at) return;
  const now = Date.now() / 1000;
  const lifetime = Math.max(1, t.expires_at - (t.issued_at ?? now));
  const left = Math.max(0, t.expires_at - now);
  const skew = Math.min(60, lifetime / 2);
  const fmt = (s) => `${Math.floor(s / 60)}:${String(Math.floor(s % 60)).padStart(2, '0')}`;
  $('expires-in').textContent = fmt(left);
  $('refresh-in').textContent = t.refresh_token ? fmt(Math.max(0, left - skew)) : 'n/a';
  $('last-refresh').textContent = ui.lastRefresh ? `${Math.round((Date.now() - ui.lastRefresh) / 1000)}s ago` : 'never';
  $('meter-fill').style.width = `${(left / lifetime) * 100}%`;
  $('meter-skew').style.width = `${(skew / lifetime) * 100}%`;
}
setInterval(tick, 1000);

const SEVERITY = {
  'session-revoked': 'danger', 'credential-change': 'warn', 'device-compliance-change': 'warn', 'risk-level-change': 'warn',
  'assurance-level-change': 'warn', 'token-claims-change': 'info', 'session-established': 'ok', 'session-presented': 'ok',
  verification: 'ok', 'stream-updated': 'info',
};

function addLogEntry(entry, fresh) {
  const node = $('log-item').content.firstElementChild.cloneNode(true);
  const evt = node.querySelector('.evt');
  evt.textContent = entry.name;
  evt.className = `evt ${SEVERITY[entry.name] ?? 'info'}`;
  evt.title = entry.type ?? '';
  node.querySelector('time').textContent = new Date(entry.at).toLocaleTimeString();
  node.querySelector('.action').textContent = entry.action;
  node.querySelector('pre').textContent = JSON.stringify({ subject: entry.subject, payload: entry.payload, jti: entry.jti }, null, 2);
  if (fresh) node.classList.add('fresh');
  $('log').prepend(node);
  $('log-empty').hidden = true;
}

// --- Tokens card -------------------------------------------------------------

let tokenTab = 'signIn';

function tokenView(value) {
  if (!value) return undefined;
  try {
    return { raw: value, jwt: true, header: decodeProtectedHeader(value), payload: decodeJwt(value) };
  } catch {
    return { raw: value, jwt: false };
  }
}

async function renderTokens() {
  if (!ui.user || !tokens) return;
  const set = tokenTab === 'signIn' ? await tokenStore.get(SIGNIN_KEY) : await tokens.get(KEY);
  $('tokens-note').textContent = tokenTab === 'signIn'
    ? 'As returned by the token endpoint when you signed in.'
    : `As currently cached${ui.refreshCount ? ` (after ${ui.refreshCount} refresh${ui.refreshCount > 1 ? 'es' : ''})` : ' (no refresh yet)'}.`;
  if (!set) {
    $('tokens-body').replaceChildren(el('p', { class: 'muted small' }, 'Not available (tokens are kept in memory and this page was reloaded).'));
    return;
  }
  const meta = [set.token_type && `token_type ${set.token_type}`, set.scope && `scope "${set.scope}"`,
    set.expires_at && `expires ${new Date(set.expires_at * 1000).toLocaleTimeString()}`].filter(Boolean).join(' · ');
  $('tokens-body').replaceChildren(
    el('p', { class: 'tok-meta' }, meta),
    tokenBlock('OAuth2 access token', tokenView(set.access_token), /^dpop$/i.test(set.token_type ?? '') ? 'DPoP-bound' : ''),
    tokenBlock('OAuth2 refresh token', tokenView(set.refresh_token)),
    tokenBlock('OIDC ID token', tokenView(set.id_token)),
  );
}

function tokenBlock(title, tok, note = '') {
  if (!tok) return el('div', { class: 'tok' }, el('div', { class: 'tok-head' }, el('h3', {}, title)), el('p', { class: 'tok-meta' }, 'Not issued.'));
  const p = tok.payload ?? {};
  const facts = tok.jwt ? [
    p.aud !== undefined && `aud ${JSON.stringify(p.aud)}`,
    (p.scope ?? p.scp) !== undefined && `scope "${[].concat(p.scope ?? p.scp).join(' ')}"`,
    p.cnf?.jkt && `cnf.jkt ${p.cnf.jkt.slice(0, 12)}…`,
    p.exp && `exp ${new Date(p.exp * 1000).toLocaleTimeString()}`,
    tok.header?.alg && `alg ${tok.header.alg}`,
  ].filter(Boolean).join(' · ') : 'Opaque: not a JWT, so there is nothing to decode.';
  return el('div', { class: 'tok' },
    el('div', { class: 'tok-head' },
      el('h3', {}, title, el('span', { class: `pill ${tok.jwt ? 'ok' : ''}` }, tok.jwt ? 'JWT' : 'opaque'), note ? el('span', { class: 'pill warn' }, note) : ''),
      el('button', { class: 'copy', type: 'button', onclick: (e) => copy(tok.raw, e.currentTarget) }, 'Copy')),
    el('p', { class: 'tok-meta' }, facts),
    el('pre', { class: 'tok-raw' }, tok.raw),
    ...(tok.jwt ? [
      el('details', {}, el('summary', { class: 'muted small' }, 'Decoded header'), el('pre', {}, JSON.stringify(tok.header, null, 2))),
      Object.assign(el('details', {}, el('summary', { class: 'muted small' }, 'Decoded claims (not verified here)'), el('pre', {}, JSON.stringify(tok.payload, null, 2))), { open: true }),
    ] : []),
  );
}

for (const b of document.querySelectorAll('.seg-btn')) {
  b.addEventListener('click', () => {
    tokenTab = b.dataset.which;
    for (const x of document.querySelectorAll('.seg-btn')) {
      x.classList.toggle('on', x === b);
      x.setAttribute('aria-selected', String(x === b));
    }
    renderTokens();
  });
}

async function copy(text, button) {
  try {
    await navigator.clipboard.writeText(text);
    button.textContent = 'Copied';
  } catch {
    button.textContent = 'Copy failed';
  }
  setTimeout(() => { button.textContent = 'Copy'; }, 1500);
}

// ---------------------------------------------------------------------------
// Configuration form
// ---------------------------------------------------------------------------

let editing = false;
let formFilled = false;
let autoSsfIssuer = '';

function renderConfig() {
  const showForm = !client || editing;
  $('config-form').hidden = !showForm;
  $('config-summary').hidden = showForm;
  $('btn-cancel').hidden = !client;
  const pill = $('config-pill');
  pill.textContent = client ? 'Configured' : 'Not configured';
  pill.className = `pill ${client ? 'ok' : 'warn'}`;
  if (client) {
    $('config-summary-kv').replaceChildren(...[
      ['issuer', config.metadata.issuer],
      ['client_id', `${config.clientId}${config.registeredAt ? ' (registered dynamically)' : ''}`],
      ['client auth', 'none (public client)'],
      ['ID token alg', client.config.idTokenSignedResponseAlg],
      ['scope', client.config.scope],
      ['CAEP', config.caep.enabled ? `poll · ${config.caep.transmitterIssuer || `${config.metadata.issuer} (OIDC issuer)`}` : 'disabled'],
    ].flatMap(([k, v]) => [el('dt', {}, k), el('dd', {}, v ?? '—')]));
  }
  $('register-urls').replaceChildren(...[['redirect_uri', URLS.redirectUri], ['post_logout_redirect_uri', URLS.postLogoutRedirectUri]]
    .flatMap(([k, v]) => [el('dt', {}, k), el('dd', {}, el('span', {}, v), el('button', { class: 'copy', type: 'button', onclick: (e) => copy(v, e.currentTarget) }, 'Copy'))]));
  if (showForm && !formFilled) fillForm();
}

function fillForm() {
  formFilled = true;
  const cur = client ? config : undefined;
  $('metadata').value = cur ? JSON.stringify(cur.metadata, null, 2) : '';
  $('client-id').value = cur?.clientId ?? '';
  $('scope').value = cur?.scope ?? '';
  $('resource').value = cur?.resource ?? '';
  $('acr-values').value = cur?.acrValues ?? '';
  $('use-dpop').checked = cur ? !!cur.dpop : true;
  $('par-mode').value = cur?.par ?? 'auto';
  $('token-storage').value = cur?.tokenStorage ?? 'memory';
  $('caep-enabled').checked = cur ? cur.caep.enabled : true;
  $('ssf-issuer').value = cur?.caep.transmitterIssuer || cur?.metadata.issuer || '';
  autoSsfIssuer = cur && !cur.caep.transmitterIssuer ? cur.metadata.issuer : '';
  $('ssf-max-age').value = cur?.caep.maxSetAgeSec ?? 3600;
  $('ssf-subject').value = cur?.caep.subjectFormat ?? 'iss_sub';
  $('ssf-only-users').checked = cur ? cur.caep.onlyUser !== false : true;
  const selected = new Set(cur?.caep.events ?? DEFAULT_CAEP_EVENTS);
  $('ssf-events-pick').replaceChildren(...CAEP_EVENT_NAMES.map((name) => el('label', { class: 'check small' },
    Object.assign(el('input', { type: 'checkbox', value: name }), { checked: selected.has(name) }), name)));
  document.querySelector('input[name="reg-mode"][value="static"]').checked = true;
  $('client-name').value = '';
  $('initial-token').value = '';
  $('software-statement').value = '';
  $('config-error').hidden = true;
  summarizeMetadata();
  populateAlgs(cur?.idTokenAlg ?? '');
  if (!cur && restoreForm()) {
    summarizeMetadata();
    restoreForm();
  }
  updateFieldsets();
  updateMode();
}

function parsedMetadata() {
  try { return JSON.parse($('metadata').value); } catch { return undefined; }
}

function populateAlgs(selected = $('id-token-alg').value) {
  const advertised = [].concat(parsedMetadata()?.id_token_signing_alg_values_supported ?? []);
  const usable = advertised.filter((a) => SUPPORTED_ID_TOKEN_ALGS.includes(a));
  const skipped = advertised.filter((a) => a !== 'none' && !SUPPORTED_ID_TOKEN_ALGS.includes(a));
  $('id-token-alg').replaceChildren(
    el('option', { value: '' }, `Automatic (${usable.includes('RS256') ? 'RS256' : usable[0] ?? 'RS256'})`),
    ...usable.map((a) => el('option', { value: a }, a)),
  );
  $('id-token-alg').value = usable.includes(selected) ? selected : '';
  $('id-token-alg').title = skipped.length ? `Not verifiable by this library: ${skipped.join(', ')}` : '';
}

function summarizeMetadata() {
  const out = $('metadata-summary');
  const text = $('metadata').value.trim();
  out.className = 'hint';
  if (!text) {
    out.textContent = '';
    updateMode();
    return;
  }
  const m = parsedMetadata();
  if (!m) {
    out.textContent = 'Not valid JSON.';
    out.classList.add('bad');
    updateMode();
    return;
  }
  try {
    validateOpenIdProviderMetadata(m);
  } catch (err) {
    out.textContent = err.message;
    out.classList.add('bad');
    updateMode();
    return;
  }
  const facts = [
    `Issuer ${m.issuer}`,
    m.pushed_authorization_request_endpoint ? 'PAR' : null,
    m.dpop_signing_alg_values_supported ? 'DPoP' : null,
    m.authorization_response_iss_parameter_supported ? 'RFC 9207 iss' : null,
    Array.isArray(m.token_endpoint_auth_methods_supported) && !m.token_endpoint_auth_methods_supported.includes('none') ? '⚠ public clients not accepted' : null,
  ].filter(Boolean);
  out.textContent = facts.join(' · ');
  out.classList.add(facts.some((f) => f.startsWith('⚠')) ? 'bad' : 'ok');
  const ssfIssuer = $('ssf-issuer');
  if (!ssfIssuer.value.trim() || ssfIssuer.value.trim() === autoSsfIssuer) {
    ssfIssuer.value = m.issuer;
    autoSsfIssuer = m.issuer;
  }
  $('ssf-issuer-hint').textContent = ssfIssuer.value.trim() === m.issuer ? 'Same as the OIDC issuer.' : `Differs from the OIDC issuer (${m.issuer}).`;
  const ssfScopes = [].concat(m.scopes_supported ?? []).filter((sc) => /^ssf[:._-]/i.test(sc));
  if (!$('scope').value && ssfScopes.length) {
    const base = ['openid', 'profile', 'email', ...([].concat(m.scopes_supported ?? []).includes('offline_access') ? ['offline_access'] : [])];
    $('scope').value = [...base, ...ssfScopes].join(' ');
  }
  populateAlgs();
  updateMode();
}

const regMode = () => document.querySelector('input[name="reg-mode"]:checked').value;

function updateMode() {
  const m = parsedMetadata();
  const canRegister = !!m?.registration_endpoint;
  const dcr = document.querySelector('input[name="reg-mode"][value="dynamic"]');
  dcr.disabled = !canRegister;
  if (!canRegister && dcr.checked) document.querySelector('input[name="reg-mode"][value="static"]').checked = true;
  $('dcr-note').textContent = canRegister ? 'OpenID Connect Dynamic Client Registration (public client)' : m ? 'This IdP has no registration_endpoint' : 'Load the metadata first';
  const dynamic = regMode() === 'dynamic';
  $('static-fields').hidden = dynamic;
  $('dynamic-fields').hidden = !dynamic;
  $('alg-hint').textContent = dynamic
    ? 'Registered as id_token_signed_response_alg; the registration is refused if the IdP assigns another.'
    : 'Must match the algorithm your client is registered with.';
  $('btn-save').textContent = dynamic ? 'Register client & connect' : 'Save & connect';
}

function updateFieldsets() {
  document.querySelector('.caep').classList.toggle('off', !$('caep-enabled').checked);
  $('storage-hint').textContent = $('token-storage').value === 'session'
    ? ($('use-dpop').checked
      ? 'Tokens in sessionStorage are readable by script in this page, but DPoP-bound: useless without the non-extractable key.'
      : '⚠ Bearer tokens in sessionStorage can be read and replayed by any script injected into this page. Turn DPoP on.')
    : 'Nothing is written to storage; a reload means signing in again.';
}

async function fetchMetadata() {
  const out = $('fetch-result');
  out.className = 'hint';
  out.textContent = 'Fetching…';
  try {
    const input = $('discovery-url').value.trim();
    const url = new URL(input.includes('/.well-known/') ? input : oidcDiscoveryUrl(input.replace(/\/+$/, '')));
    const res = await fetch(url, { headers: { accept: 'application/json' } });
    if (!res.ok) throw new Error(`HTTP ${res.status} from ${url}`);
    const metadata = await res.json();
    validateOpenIdProviderMetadata(metadata);
    $('metadata').value = JSON.stringify(metadata, null, 2);
    summarizeMetadata();
    let ssf;
    try {
      ssf = await discoverSSFTransmitter(metadata.issuer);
    } catch {
      ssf = undefined;
    }
    out.textContent = ssf
      ? `Loaded ${url.href}. SSF transmitter found${ssf.default_subjects ? ` (default_subjects ${ssf.default_subjects})` : ''}.`
      : `Loaded ${url.href}. No SSF metadata at this issuer; set the transmitter issuer below, or turn off CAEP.`;
    out.classList.add(ssf ? 'ok' : 'bad');
    saveForm();
  } catch (err) {
    out.textContent = describe(err);
    out.classList.add('bad');
  }
}

async function saveConfig(e) {
  e.preventDefault();
  const err = $('config-error');
  err.hidden = true;
  const metadata = parsedMetadata();
  try {
    if (!metadata) throw new Error('The metadata document is not valid JSON.');
    const cfg = {
      metadata,
      clientId: $('client-id').value.trim(),
      idTokenAlg: $('id-token-alg').value,
      scope: $('scope').value.trim(),
      resource: $('resource').value.trim(),
      acrValues: $('acr-values').value.trim(),
      dpop: $('use-dpop').checked,
      par: $('par-mode').value,
      tokenStorage: $('token-storage').value,
      caep: {
        enabled: $('caep-enabled').checked,
        transmitterIssuer: $('ssf-issuer').value.trim() === metadata.issuer ? '' : $('ssf-issuer').value.trim(),
        maxSetAgeSec: Math.max(0, Number($('ssf-max-age').value) || 0),
        subjectFormat: $('ssf-subject').value,
        onlyUser: $('ssf-only-users').checked,
        events: [...document.querySelectorAll('#ssf-events-pick input:checked')].map((i) => i.value),
      },
    };
    if (cfg.caep.enabled && !cfg.caep.events.length) throw new Error('Select at least one CAEP event.');
    let register;
    if (regMode() === 'dynamic') {
      const request = {
        application_type: 'web',
        client_name: $('client-name').value.trim() || 'oidc-caep-client demo',
        redirect_uris: [URLS.redirectUri],
        post_logout_redirect_uris: [URLS.postLogoutRedirectUri],
        response_types: ['code'],
        grant_types: ['authorization_code', 'refresh_token'].filter((g) => (metadata.grant_types_supported ?? ['authorization_code']).includes(g)),
        id_token_signed_response_alg: cfg.idTokenAlg || pickIdTokenAlg(metadata),
        scope: cfg.scope || undefined,
      };
      const statement = $('software-statement').value.trim();
      if (statement) request.software_statement = statement;
      register = { request, initialAccessToken: $('initial-token').value.trim() || undefined };
    }
    // Reconfiguring ends the current session.
    if (ui.user) await signOutLocally();
    await applyConfig(cfg, { register });
    editing = false;
    formFilled = false;
    ssfState = { status: cfg.caep.enabled ? 'waiting-for-user' : 'disabled', transmitter: cfg.caep.transmitterIssuer || metadata.issuer };
    await render();
  } catch (e2) {
    err.textContent = describe(e2);
    err.hidden = false;
  }
}

// Remembered (unsaved) form values. The DCR initial access token is never stored.
function formFields() {
  return [...$('config-form').querySelectorAll('input, select, textarea')].filter((f) => f.type !== 'password' && !NOT_STORED.has(f.id));
}

function saveForm() {
  const values = {};
  for (const f of formFields()) {
    if (f.type === 'radio') {
      if (f.checked) values[`radio:${f.name}`] = f.value;
    } else if (f.type === 'checkbox') {
      if (f.id) values[f.id] = f.checked;
    } else if (f.id) {
      values[f.id] = f.value;
    }
  }
  values.events = [...document.querySelectorAll('#ssf-events-pick input:checked')].map((i) => i.value);
  store.set(FORM_STORE_KEY, values);
}

function restoreForm() {
  const values = store.get(FORM_STORE_KEY);
  if (!values || typeof values !== 'object') return false;
  for (const f of formFields()) {
    if (f.type === 'radio') {
      const want = values[`radio:${f.name}`];
      if (want !== undefined) f.checked = f.value === want && !f.disabled;
    } else if (f.type === 'checkbox') {
      if (f.id && typeof values[f.id] === 'boolean') f.checked = values[f.id];
    } else if (f.id && typeof values[f.id] === 'string') {
      if (f.tagName === 'SELECT' && ![...f.options].some((o) => o.value === values[f.id])) continue;
      f.value = values[f.id];
    }
  }
  if (Array.isArray(values.events)) {
    for (const box of document.querySelectorAll('#ssf-events-pick input')) box.checked = values.events.includes(box.value);
  }
  const issuer = parsedMetadata()?.issuer;
  if (issuer && $('ssf-issuer').value.trim() === issuer) autoSsfIssuer = issuer;
  return true;
}

$('config-form').addEventListener('submit', (e) => withBusy($('btn-save'), () => saveConfig(e)));
$('config-form').addEventListener('input', saveForm);
$('config-form').addEventListener('change', saveForm);
$('btn-fetch').addEventListener('click', (e) => withBusy(e.currentTarget, fetchMetadata));
$('discovery-url').addEventListener('keydown', (e) => {
  if (e.key === 'Enter') {
    e.preventDefault();
    $('btn-fetch').click();
  }
});
$('metadata').addEventListener('input', summarizeMetadata);
for (const id of ['caep-enabled', 'use-dpop', 'token-storage']) $(id).addEventListener('change', updateFieldsets);
for (const r of document.querySelectorAll('input[name="reg-mode"]')) r.addEventListener('change', updateMode);
$('btn-edit-config').addEventListener('click', () => { editing = true; formFilled = false; renderConfig(); });
$('btn-cancel').addEventListener('click', () => { editing = false; formFilled = false; renderConfig(); });
$('btn-signin-hero').addEventListener('click', () => signIn());

$('btn-userinfo').addEventListener('click', (e) => withBusy(e.currentTarget, async () => {
  const out = $('userinfo-out');
  out.hidden = false;
  try {
    const claims = await client.userinfo(await tokens.getTokenSet(KEY), { expectedSub: ui.user.sub });
    out.textContent = `GET userinfo → 200\n${JSON.stringify(claims, null, 2)}`;
  } catch (err) {
    out.textContent = `GET userinfo failed: ${describe(err)}`;
  }
}));
$('btn-refresh').addEventListener('click', (e) => withBusy(e.currentTarget, async () => {
  try {
    await tokens.refresh(KEY);
  } catch (err) {
    ui.error = `Refresh failed: ${describe(err)}`;
    render();
  }
}));
$('btn-verify').addEventListener('click', (e) => withBusy(e.currentTarget, async () => {
  try {
    await receiver.requestVerification({ timeoutMs: 15_000 });
  } catch (err) {
    ssfState = { ...ssfState, error: `Verification failed: ${describe(err)}` };
    render();
  }
}));
$('btn-reconnect').addEventListener('click', (e) => withBusy(e.currentTarget, async () => {
  await stopCaep({ deleteStream: true });
  await startCaep();
}));

// ---------------------------------------------------------------------------
// Start-up
// ---------------------------------------------------------------------------

async function start() {
  for (const entry of [...eventLog].reverse()) addLogEntry(entry, false);
  const saved = store.get(CONFIG_KEY);
  if (saved?.metadata && saved.clientId) {
    try {
      await applyConfig(saved, { startup: true });
    } catch (err) {
      ui.error = `Saved configuration could not be applied: ${describe(err)}`;
      client = undefined;
    }
  }
  if (client) {
    const params = new URLSearchParams(location.search);
    if (location.pathname === '/callback') {
      await completeCallback();
    } else if (params.has('state')) {
      // Back from RP-initiated logout: the state must be the one sent.
      try {
        await client.validateEndSessionCallback(location.href);
        ui.notices.unshift({ level: 'info', text: 'You are signed out of the identity provider.' });
      } catch (err) {
        ui.error = `Logout response rejected: ${describe(err)}`;
      }
      history.replaceState(null, '', '/');
    } else {
      const held = await tokens.get(KEY);
      if (held) {
        // Put restored tokens back through the cache so their auto-refresh is scheduled again.
        await tokens.set(KEY, held);
        ui.user = held.claims;
      }
    }
    ssfState = { status: config.caep.enabled ? 'waiting-for-user' : 'disabled', transmitter: config.caep.transmitterIssuer || config.metadata.issuer };
  } else if (location.pathname === '/callback') {
    ui.error = 'Returned from the identity provider, but this browser has no configuration for it.';
    history.replaceState(null, '', '/');
  }
  await render();
  if (ui.user) await startCaep();
}

start();
