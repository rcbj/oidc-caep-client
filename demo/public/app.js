// CAEP demo SPA. The OIDC client runs HERE, in the browser, as a public client: Authorization Code + PKCE,
// state/nonce, PAR, DPoP with a non-extractable key, RFC 9207, token caching with auto-refresh, and a CAEP
// (Shared Signals) stream polled with the active account's access token.
//
// Several accounts can be signed in at once (an OP such as iya-sts with authn.multipleAccounts keeps one
// session per person per browser). The library caches every account's tokens for the whole browser, shared
// by its tabs, and each tab has ONE active account: only its tokens are used and refreshed, and only its
// stream is polled. Switching makes another cached account active; its stream first catches up on the
// signals queued while it was dormant.
import { decodeJwt, decodeProtectedHeader } from 'jose';
import {
  AccountManager, CAEP, discoverSSFTransmitter, IndexedDBKeyStore, MemoryKeyStore, needsInteraction, OIDCClient,
  oidcDiscoveryUrl, SSFReceiver, Subject, subjectMatches, SUPPORTED_ID_TOKEN_ALGS, validateOpenIdProviderMetadata,
} from 'oidc-caep-client';

const $ = (id) => document.getElementById(id);
const ORIGIN = location.origin;
const URLS = { redirectUri: `${ORIGIN}/callback`, postLogoutRedirectUri: `${ORIGIN}/` };
const CAEP_EVENT_NAMES = Object.values(CAEP).map((u) => u.split('/').pop());
const DEFAULT_CAEP_EVENTS = ['session-revoked', 'credential-change', 'token-claims-change', 'assurance-level-change', 'device-compliance-change'];
const CONFIG_KEY = 'oidc-caep-demo.config';
const FORM_STORE_KEY = 'oidc-caep-demo.config-form';
// Shared by the tabs (localStorage): each account's stream id, and the signals every tab has received.
const STREAMS_KEY = 'oidc-caep-demo.stream-ids';
const LOG_KEY = 'oidc-caep-demo.event-log';
// Per tab (sessionStorage): which log view, and when this tab last looked at each account's signals.
const LOG_VIEW_KEY = 'oidc-caep-demo.log-view';
const SEEN_KEY = 'oidc-caep-demo.seen';
const NOT_STORED = new Set(['initial-token']);

/** @type {OIDCClient|undefined} */ let client;
/** @type {AccountManager|undefined} */ let accounts;
let config;
const ui = { error: undefined, attention: undefined, notices: [], ended: new Map(), busy: undefined };
/** Per account, in this tab: refresh count, step-up requirement, notices from its signals. */
const perAccount = new Map();
/** The tokens the token endpoint returned at this tab's last sign-in, for the active account only. */
let signInTokens;
/** The one stream this tab polls: the active account's. */
let caep = { key: undefined, receiver: undefined, state: { status: 'waiting-for-user' } };

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
  node.append(...children.filter((c) => c !== '' && c !== undefined && c !== null && c !== false));
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

const labelOf = (a) => a ? a.name ?? a.preferred_username ?? a.email ?? a.sub : '—';
const initialOf = (a) => String(labelOf(a))[0]?.toUpperCase() ?? '?';
const stateOf = (key) => {
  if (!perAccount.has(key)) perAccount.set(key, { refreshCount: 0, lastRefresh: undefined, stepUp: undefined, notices: [] });
  return perAccount.get(key);
};
/** This tab's active account, when it is signed in (its tokens are usable). */
const signedIn = () => (accounts?.active?.status === 'signed-in' ? accounts.active : undefined);

const STATUS = {
  'signed-in': ['ok', 'Signed in'],
  'tokens-missing': ['warn', 'Tokens expired'],
  'signed-out': ['', 'Signed out'],
  ended: ['danger', 'Session ended'],
};

// ---------------------------------------------------------------------------
// Configuration → client
// ---------------------------------------------------------------------------

async function applyConfig(cfg, { register } = {}) {
  accounts?.close();
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

  // One token cache for every account in this browser (IndexedDB, shared by the tabs); one active account
  // per tab. The hooks tie this tab's one CAEP stream to its active account.
  accounts = new AccountManager(client, {
    storeKey: `accounts:${metadata.issuer}:${config.clientId}`,
    onActivate: (account, { getTokenSet }) => startCaep(account, getTokenSet),
    onDeactivate: (account) => stopCaep(account.key),
    onLeave: (account, { getTokenSet }) => deleteStream(account, getTokenSet),
  });
  accounts.on('refreshed', (a) => {
    const s = stateOf(a.key);
    s.refreshCount += 1;
    s.lastRefresh = Date.now();
    render();
  });
  accounts.on('ended', (a, reason) => {
    ui.ended.set(a.key, reason);
    render();
  });
  accounts.on('activated', (a) => {
    if (a?.key !== signInTokens?.key) signInTokens = undefined;
    ui.attention = undefined;
  });
  accounts.on('activation_error', (a, err) => {
    ui.error = `Could not make ${labelOf(a)} active: ${describe(err)}`;
    render();
  });
  accounts.on('change', () => {
    // Another tab may have signed out or ended this tab's active account.
    if (caep.key && accounts.get(caep.key)?.status !== 'signed-in') stopCaep(caep.key);
    render();
  });
  await accounts.init();
  return client;
}

function pickIdTokenAlg(metadata) {
  const algs = metadata.id_token_signing_alg_values_supported ?? [];
  if (algs.includes('RS256')) return 'RS256';
  return algs.find((a) => SUPPORTED_ID_TOKEN_ALGS.includes(a)) ?? 'RS256';
}

// ---------------------------------------------------------------------------
// Sign-in, switching, callback, sign-out
// ---------------------------------------------------------------------------

/** Sends the browser to the IdP with the request `make` builds. */
async function go(make, what = 'sign-in') {
  if (!accounts) return;
  try {
    const { url } = await make(accounts);
    location.assign(url);
  } catch (err) {
    ui.error = `Could not start the ${what}: ${describe(err)}`;
    render();
  }
}

const acr = () => ({ acrValues: config.acrValues || undefined });
const signIn = () => go((m) => m.signIn(acr()));
const addAccount = () => go((m) => m.addAccount(acr()));
const chooseAccount = () => go((m) => m.chooseAccount(acr()));
const resume = (key) => go((m) => m.resume(key, acr()), 'silent sign-in');
const reauthenticate = (key) => go((m) => m.reauthenticate(key, acr()));

/** Makes another cached account this tab's active account. Its stream catches up first. */
async function activate(key) {
  closeMenu();
  ui.busy = `Switching to ${labelOf(accounts.get(key))}: checking the signals queued for this account…`;
  render();
  try {
    await accounts.activate(key);
  } catch (err) {
    ui.error = `Could not switch to ${labelOf(accounts.get(key))}: ${describe(err)}`;
  } finally {
    ui.busy = undefined;
  }
  await render();
}

async function completeCallback() {
  try {
    const { account, tokenSet, added } = await accounts.handleCallback(location.href);
    perAccount.delete(account.key);
    ui.ended.delete(account.key);
    if (accounts.activeKey === account.key) signInTokens = { key: account.key, tokenSet };
    ui.notices.unshift({ level: 'info', text: added ? `${labelOf(account)} added. Your other accounts stay signed in, dormant until you switch to them.` : `Signed in as ${labelOf(account)}.` });
  } catch (err) {
    const who = err.account ? labelOf(err.account) : undefined;
    if (needsInteraction(err) && err.account) {
      ui.attention = { key: err.account.key, text: `The identity provider could not sign ${who} in without asking (${err.error}): their session there has ended.` };
    } else if (err.error === 'account_selection_required') {
      ui.error = 'Several accounts are signed in at the identity provider and the request did not say which; choose one.';
    } else if (err.code === 'account_mismatch') {
      ui.error = 'You signed in as somebody else at the identity provider, not the account this page asked for. Nothing was changed.';
    } else {
      ui.error = `Sign-in failed: ${describe(err)}`;
    }
  } finally {
    history.replaceState(null, '', '/');
  }
}

/** Signs one account out of this browser and at the IdP (its session only); the others stay signed in. */
async function signOut(key = accounts.activeKey) {
  closeMenu();
  const logout = await accounts.signOut(key).catch((err) => { ui.error = `Sign-out failed: ${describe(err)}`; });
  if (logout) location.assign(logout.url);
  else render();
}

async function signOutAll() {
  closeMenu();
  const logout = await accounts.signOutAll().catch((err) => { ui.error = `Sign-out failed: ${describe(err)}`; });
  if (logout) location.assign(logout.url);
  else render();
}

async function forget(key) {
  await accounts.forget(key);
  ui.ended.delete(key);
  render();
}

/** Before a new configuration: every account is signed out of this browser and forgotten. */
async function resetAccounts() {
  if (!accounts) return;
  await accounts.signOutAll({ endSession: false }).catch(() => {});
  for (const a of accounts.list()) await accounts.forget(a.key).catch(() => {});
  perAccount.clear();
  ui.ended.clear();
}

// ---------------------------------------------------------------------------
// CAEP: this tab polls ONE stream, the active account's, authorised by its (DPoP-bound) access token.
// A stream created with a person's token belongs to that person and carries events about them only, so
// each account keeps its own stream at the transmitter; a dormant account's stream keeps queueing events,
// and activating the account catches up on them before its tokens are used.
// ---------------------------------------------------------------------------

function subjectFor(a) {
  return config.caep.subjectFormat === 'email' && a.email ? Subject.email(a.email) : Subject.issSub(a.iss, a.sub);
}

const streamIds = () => store.get(STREAMS_KEY) ?? {};
function rememberStream(key, id) {
  const ids = streamIds();
  if (id) ids[key] = id;
  else delete ids[key];
  store.set(STREAMS_KEY, ids);
}

const transmitterIssuer = () => config.caep.transmitterIssuer || config.metadata.issuer;

function makeReceiver(account, getTokenSet, streamId) {
  const c = config.caep;
  return new SSFReceiver({
    transmitterIssuer: transmitterIssuer(),
    streamId,
    // Every management and poll call carries THIS account's access token, with a DPoP proof when bound.
    authorizationHeaders: async (req) => client.resourceHeaders(await getTokenSet(), req),
    eventsRequested: c.events.map((n) => Object.values(CAEP).find((u) => u.endsWith(`/${n}`))),
    description: `oidc-caep-client in-browser demo @ ${ORIGIN} (${labelOf(account)})`,
    pollIntervalMs: 5000,
    maxSetAgeSec: c.maxSetAgeSec,
    handlers: handlersFor(account.key, getTokenSet),
  });
}

/** onActivate: start (or reuse) the account's stream and act on what it queued while dormant. */
async function startCaep(account, getTokenSet) {
  if (!config?.caep?.enabled) return;
  const key = account.key;
  caep = { key, receiver: undefined, state: { status: 'connecting', transmitter: transmitterIssuer() } };
  render();
  try {
    const held = streamIds()[key];
    let r = makeReceiver(account, getTokenSet, held);
    try {
      await r.start({ catchUp: true });
    } catch (err) {
      if (!held) throw err;
      // The remembered stream is gone (deleted, or not ours any more): create a new one.
      await r.stop();
      r = makeReceiver(account, getTokenSet);
      await r.start({ catchUp: true });
    }
    if (caep.key !== key || accounts.get(key)?.status !== 'signed-in') {
      // A signal received while catching up ended the account, or another account was activated meanwhile.
      await r.stop();
      return;
    }
    caep.receiver = r;
    rememberStream(key, r.stream.stream_id);
    if (config.caep.onlyUser && r.metadata.add_subject_endpoint) {
      await r.addSubject(subjectFor(account)).catch((err) => log({ account: key, name: 'subject', action: `Could not add the subject: ${describe(err)}` }));
    }
    caep.state = { status: 'connected', transmitter: transmitterIssuer(), streamStatus: r.stream.status ?? 'enabled' };
    r.requestVerification({ timeoutMs: 30_000 }).catch(() => {});
  } catch (err) {
    // Shown on the stream card; the account is still activated so the person is not locked out by an
    // unreachable transmitter.
    if (caep.key === key) caep.state = { status: 'error', transmitter: transmitterIssuer(), error: `Could not catch up: ${describe(err)}` };
  }
  render();
}

/** onDeactivate: stop polling; the stream stays at the transmitter and keeps queueing events. */
async function stopCaep(key) {
  if (caep.key !== key) return;
  const r = caep.receiver;
  caep = { key: undefined, receiver: undefined, state: { status: config?.caep?.enabled ? 'waiting-for-user' : 'disabled' } };
  if (r) await r.stop().catch(() => {});
}

/** onLeave: the account is signed out or ended; delete its stream while its tokens still work. */
async function deleteStream(account, getTokenSet) {
  await stopCaep(account.key);
  const id = streamIds()[account.key];
  rememberStream(account.key, undefined);
  if (!id || !config?.caep?.enabled) return;
  const r = makeReceiver(account, getTokenSet, id);
  try {
    await r.discover();
    r.stream = { stream_id: id };
    await r.deleteStream();
  } catch { /* the transmitter forgets an unused stream on its own */ }
}

/** The signals every tab has received, newest first (shared through localStorage). */
const eventLog = () => store.get(LOG_KEY) ?? [];
let logView = store.get(LOG_VIEW_KEY, sessionStorage) ?? 'active';

function log(entry) {
  const entries = eventLog();
  // Poll delivery is at-least-once, and two tabs with the same active account poll the same stream.
  if (entry.jti && entries.some((e) => e.jti === entry.jti && e.account === entry.account)) return;
  const full = { at: Date.now(), label: labelOf(accounts.get(entry.account)), ...entry };
  entries.unshift(full);
  entries.length = Math.min(entries.length, 300);
  store.set(LOG_KEY, entries);
  renderLog(full.at);
}

/** Signals this tab has not looked at yet, for an account that is not active here. */
function unreadFor(key) {
  if (key === accounts?.activeKey) return 0;
  const seen = store.get(SEEN_KEY, sessionStorage)?.[key] ?? 0;
  return eventLog().filter((e) => e.account === key && e.at > seen).length;
}
function markSeen(key) {
  if (!key) return;
  const seen = store.get(SEEN_KEY, sessionStorage) ?? {};
  seen[key] = Date.now();
  store.set(SEEN_KEY, seen, sessionStorage);
}

/** Wraps a policy for one account's stream: only events about that account (or the stream) are acted on. */
function handle(key, policy) {
  return async (evt) => {
    if (evt.jti && eventLog().some((e) => e.jti === evt.jti && e.account === key)) return;
    const identity = accounts.identity(key);
    const mine = identity && subjectMatches(evt.subject, identity);
    const streamId = caep.key === key ? caep.receiver?.stream?.stream_id ?? streamIds()[key] : undefined;
    const aboutStream = !evt.subject || (evt.subject.format === 'opaque' && evt.subject.id === streamId);
    let action;
    try {
      action = mine || aboutStream ? await policy(evt) : 'Not about this account (or another of its sessions); ignored.';
    } catch (err) {
      action = `Handler failed: ${describe(err)}`;
    }
    const caughtUp = accounts.activeKey !== key ? ' (caught up on activation)' : '';
    log({ account: key, name: evt.name, type: evt.type, jti: evt.jti, subject: evt.subject, payload: evt.payload, action: `${action}${caughtUp}` });
    render();
  };
}

function handlersFor(key, getTokenSet) {
  const s = () => stateOf(key);
  const on = (policy) => handle(key, policy);
  const end = (reason) => accounts.end(key, reason);
  return {
    sessionRevoked: on(async (evt) => {
      await end(evt.reasonUser?.en ?? 'The session was revoked by the identity provider.');
      return 'Session ended; its cached tokens discarded. Other accounts are unaffected.';
    }),
    tokenClaimsChange: on(async (evt) => {
      await getTokenSet({ forceRefresh: true });
      return `Refreshed tokens for new claims (${Object.keys(evt.payload.claims ?? {}).join(', ') || 'unspecified'}).`;
    }),
    credentialChange: on(async (evt) => {
      const { credential_type: type = 'credential', change_type: change } = evt.payload;
      if (['revoke', 'delete'].includes(change)) {
        await end(`The ${type} was ${change}d; sign in again.`);
        return `Credential ${change}d: session ended.`;
      }
      s().notices.unshift({ level: 'info', text: `The ${type} was ${change ? `${change}d` : 'changed'} at the identity provider.` });
      return 'User notified; session kept.';
    }),
    assuranceLevelChange: on((evt) => {
      const { current_level: current, previous_level: previous, change_direction: dir } = evt.payload;
      s().stepUp = dir === 'decrease' ? `Assurance dropped from ${previous} to ${current}.` : undefined;
      return dir === 'decrease' ? 'Step-up authentication required.' : 'Step-up requirement cleared.';
    }),
    deviceComplianceChange: on(async (evt) => {
      if (evt.payload.current_status === 'not-compliant') {
        await end('The device is no longer compliant with security policy.');
        return 'Device not compliant: session ended.';
      }
      return 'Device compliant: no action.';
    }),
    riskLevelChange: on(async (evt) => {
      const { current_level: level, risk_reason: why } = evt.payload;
      if (level === 'HIGH') {
        await end(`High risk detected (${why ?? 'no reason given'}).`);
        return 'Risk HIGH: session ended.';
      }
      s().stepUp = level === 'MEDIUM' ? `Risk raised to MEDIUM (${why ?? 'no reason given'}).` : undefined;
      return `Risk ${level}: ${level === 'MEDIUM' ? 'step-up required' : 'step-up cleared'}.`;
    }),
    sessionEstablished: on((evt) => `Informational: new session at the IdP (acr=${evt.payload.acr ?? 'n/a'}).`),
    sessionPresented: on(() => 'Informational: session presented to another service.'),
    verification: on((evt) => `Stream verified (state=${evt.payload.state ?? 'none'}).`),
    streamUpdated: on((evt) => {
      if (caep.key === key) caep.state = { ...caep.state, streamStatus: evt.payload.status };
      return `Transmitter set the stream to "${evt.payload.status}".`;
    }),
    unhandled: on((evt) => `No handler for ${evt.type}.`),
    error: (err, ctx) => {
      if (ctx.phase === 'poll' && caep.key === key) {
        caep.state = { ...caep.state, error: `Last poll failed at ${new Date().toLocaleTimeString()}: ${describe(err)}` };
        render();
      }
    },
  };
}

// ---------------------------------------------------------------------------
// Rendering
// ---------------------------------------------------------------------------

async function render() {
  const configured = !!client;
  const me = signedIn();
  const list = accounts?.list() ?? [];
  $('signed-out').hidden = !configured || !!me;
  $('session-card').hidden = !me;
  $('token-card').hidden = !me;
  $('tokens-card').hidden = !me;
  $('security-card').hidden = !configured;
  $('accounts-card').hidden = !list.length;
  if (me) markSeen(me.key);

  renderWho(list);
  renderHero(list);
  renderAccounts(list);

  if (me) {
    $('session-title').textContent = `Session · ${labelOf(me)}`;
    const claims = (await accounts.getTokenSet().catch(() => undefined))?.claims ?? me;
    const shown = ['sub', 'name', 'email', 'preferred_username', 'acr', 'amr', 'sid', 'iss', 'auth_time'];
    $('claims').replaceChildren(...shown.filter((k) => claims[k] !== undefined).flatMap((k) => [
      el('dt', {}, k),
      el('dd', {}, k === 'auth_time' ? new Date(claims[k] * 1000).toLocaleTimeString() : typeof claims[k] === 'object' ? JSON.stringify(claims[k]) : String(claims[k])),
    ]));
    const pill = $('session-pill');
    const { stepUp, refreshCount } = stateOf(me.key);
    pill.textContent = stepUp ? 'Step-up required' : 'Active';
    pill.className = `pill ${stepUp ? 'warn' : 'ok'}`;
    $('refresh-count').textContent = `${refreshCount} refreshes`;
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
      ['Token cache', 'every signed-in account\'s tokens, in IndexedDB, shared by this browser\'s tabs'],
      ['One active account per tab', 'only its tokens are reachable, refreshed and used to poll; the others stay dormant until activated, and their queued signals are acted on first'],
      ['Several accounts', 'a sign-in naming an account refuses anybody else; sign-out names the account\'s ID token so only its IdP session ends; refreshes are locked across tabs'],
      ['Resource indicators', f.resourceIndicators ? f.resourceIndicators.join(', ') : 'none'],
      ['Page', 'CSP (no inline script), Referrer-Policy no-referrer, framing denied'],
    ];
    $('security-list').replaceChildren(...items.map(([k, v]) => el('li', {}, el('strong', {}, k), el('span', { class: 'muted' }, ` ${v}`))));
  }

  renderConfig();
  renderStream();
  renderBanners();
  renderLog();
  tick();
  await renderTokens();
}

function avatar(a, cls = '') {
  return el('span', { class: `avatar ${cls}`, 'aria-hidden': 'true' }, initialOf(a));
}

function badge(key) {
  const n = unreadFor(key);
  return n ? el('span', { class: 'badge', title: `${n} new signal${n > 1 ? 's' : ''}` }, String(n)) : '';
}

function closeMenu() {
  const menu = document.querySelector('.acct-menu');
  if (menu) menu.open = false;
}

/** The top bar: this tab's active account and the Switch account menu. */
function renderWho(list) {
  const who = $('who');
  if (!client) return who.replaceChildren();
  if (!list.length) return who.replaceChildren(el('button', { class: 'btn primary', onclick: () => signIn() }, 'Sign in'));
  const cur = accounts.active;
  const others = list.filter((a) => a.key !== cur?.key);
  const otherUnread = others.reduce((n, a) => n + unreadFor(a.key), 0);
  const wasOpen = document.querySelector('.acct-menu')?.open;
  const row = (a) => el('button', { class: 'menu-row', type: 'button', role: 'menuitem', onclick: () => activate(a.key) },
    avatar(a),
    el('span', { class: 'menu-who' }, el('span', {}, labelOf(a)), el('span', { class: 'muted small' }, a.email ?? a.sub)),
    a.status === 'signed-in' ? '' : el('span', { class: `pill ${STATUS[a.status][0]}` }, STATUS[a.status][1]),
    badge(a.key));
  const menu = el('details', { class: 'acct-menu' },
    el('summary', { 'aria-label': 'Switch account' },
      cur ? avatar(cur) : '',
      el('span', { class: 'menu-name' }, cur ? labelOf(cur) : 'Choose an account'),
      otherUnread ? el('span', { class: 'badge', title: 'New signals for your other accounts' }, String(otherUnread)) : '',
      el('span', { class: 'caret', 'aria-hidden': 'true' }, '▾')),
    el('div', { class: 'menu', role: 'menu' },
      el('p', { class: 'menu-head' }, 'Switch account'),
      ...(others.length ? others.map(row) : [el('p', { class: 'muted small menu-note' }, 'No other account yet.')]),
      el('div', { class: 'menu-sep' }),
      el('button', { class: 'menu-row', type: 'button', role: 'menuitem', onclick: () => addAccount() }, el('span', { class: 'avatar plus', 'aria-hidden': 'true' }, '+'), 'Sign in with another account'),
      el('button', { class: 'menu-row', type: 'button', role: 'menuitem', onclick: () => chooseAccount() }, el('span', { class: 'avatar plus', 'aria-hidden': 'true' }, '⇄'), 'Choose at the identity provider'),
      el('p', { class: 'muted small menu-note' }, 'Switching changes this tab only. The account you leave stays signed in, dormant, and switching back needs no password.'),
      el('div', { class: 'menu-sep' }),
      cur?.status === 'signed-in' ? el('button', { class: 'menu-row', type: 'button', role: 'menuitem', onclick: () => signOut() }, `Sign out ${labelOf(cur)}`) : '',
      el('button', { class: 'menu-row', type: 'button', role: 'menuitem', onclick: () => signOutAll() }, 'Sign out of all accounts')));
  if (wasOpen) menu.open = true;
  who.replaceChildren(menu);
}

function renderHero(list) {
  const cur = accounts?.active;
  const actions = [];
  let title = 'Continuous access, in real time.';
  let text = 'Sign in through your identity provider. This page keeps your tokens, refreshes them before they expire, and listens for CAEP events that can change or end your session while you\'re using it. You can sign in with several accounts and switch between them.';
  if (cur && cur.status === 'tokens-missing') {
    title = `Continue as ${labelOf(cur)}`;
    text = 'The tokens cached for this account have expired and cannot be refreshed. New ones can be fetched without a password while its session at the identity provider lasts.';
    actions.push(el('button', { class: 'btn primary', onclick: () => resume(cur.key) }, `Continue as ${labelOf(cur)}`));
  } else if (cur) {
    title = cur.status === 'ended' ? `${labelOf(cur)}'s session was ended` : `${labelOf(cur)} is signed out`;
    text = `${cur.status === 'ended' && cur.endedReason ? `${cur.endedReason} ` : ''}Sign in again as ${labelOf(cur)}, switch to another account, or sign in with another account.`;
    actions.push(el('button', { class: 'btn primary', onclick: () => reauthenticate(cur.key) }, `Sign in again as ${labelOf(cur)}`));
  } else if (list.some((a) => a.status === 'signed-in')) {
    title = 'Choose an account for this tab';
    text = 'These accounts are signed in in this browser. Each tab uses one of them at a time: pick one in the Accounts card. No password is needed.';
  } else if (list.length) {
    title = 'Choose an account';
    text = 'None of the accounts in this browser is signed in. Sign in again as one of them in the Accounts card, or sign in with another account.';
  }
  actions.push(el('button', { class: `btn ${actions.length ? 'ghost' : 'primary'}`, onclick: () => (list.length ? addAccount() : signIn()) }, list.length ? 'Sign in with another account' : 'Sign in'));
  $('hero-title').textContent = title;
  $('hero-text').textContent = text;
  $('hero-actions').replaceChildren(...actions);
}

/** The Accounts card: every account in this browser, its status, and what can be done with it. */
function renderAccounts(list) {
  const cur = accounts?.activeKey;
  $('accounts-count').textContent = `${list.filter((a) => a.status === 'signed-in').length} of ${list.length} signed in`;
  $('accounts-list').replaceChildren(...list.map((a) => {
    const [tone, label] = STATUS[a.status];
    const role = a.status !== 'signed-in' ? '' : a.key === cur ? `active in this tab${config.caep.enabled ? ` · stream ${caep.state.status === 'connected' ? caep.state.streamStatus ?? 'enabled' : caep.state.status}` : ''}` : 'dormant: tokens cached, not refreshed or polled';
    const btn = (text, onclick, cls = 'ghost') => el('button', { class: `btn small-btn ${cls}`, type: 'button', onclick: (e) => withBusy(e.currentTarget, onclick) }, text);
    const actions = [
      a.key !== cur && btn('Switch', () => activate(a.key), a.status === 'signed-in' ? '' : 'ghost'),
      a.status === 'tokens-missing' && btn('Continue', () => resume(a.key)),
      (a.status === 'ended' || a.status === 'signed-out') && btn('Sign in again', () => reauthenticate(a.key)),
      (a.status === 'signed-in' || a.status === 'tokens-missing') && btn('Sign out', () => signOut(a.key)),
      a.status !== 'signed-in' && btn('Forget', () => forget(a.key)),
    ].filter(Boolean);
    return el('li', { class: `acct${a.key === cur ? ' current' : ''}` },
      avatar(a),
      el('div', { class: 'acct-body' },
        el('div', { class: 'acct-name' }, labelOf(a), a.key === cur ? el('span', { class: 'pill ok' }, 'active') : '', badge(a.key)),
        el('div', { class: 'muted small' }, [a.email ?? a.sub, a.sid && `sid ${a.sid}`, role].filter(Boolean).join(' · ')),
        a.endedReason && a.status === 'ended' ? el('div', { class: 'small acct-why' }, a.endedReason) : ''),
      el('div', { class: 'acct-side' }, el('span', { class: `pill ${tone}` }, label), el('div', { class: 'acct-actions' }, ...actions)));
  }));
  $('accounts-hint').textContent = 'Every signed-in account\'s tokens are cached in this browser and shared by its tabs. Each tab has one active account: only its tokens are used and refreshed, and only its stream is polled. Switching activates another account; signals queued for it while it was dormant are acted on first.';
}

function renderStream() {
  const me = signedIn();
  const st = me && caep.key === me.key ? caep : { state: { status: config?.caep?.enabled ? (ui.busy ? 'connecting' : 'waiting-for-user') : 'disabled' } };
  const ssfState = st.state;
  const status = ssfState.status === 'connected' ? ssfState.streamStatus ?? 'enabled' : ssfState.status;
  $('stream-title').textContent = me ? `CAEP stream · ${labelOf(me)}` : 'CAEP stream';
  const pill = $('ssf-pill');
  pill.textContent = status;
  pill.className = `pill ${status === 'enabled' ? 'ok' : status === 'error' ? 'danger' : 'warn'}`;
  const r = st.receiver;
  const s = r?.stream;
  const transmitter = ssfState.transmitter ?? (config ? transmitterIssuer() : undefined);
  $('ssf-info').replaceChildren(...[
    ['transmitter', transmitter ?? '—'],
    ...(s ? [['stream_id', s.stream_id], ['delivery', 'poll (RFC 8936)'], ['SET audience', [].concat(s.aud ?? '—').join(', ')]] : []),
    ...(r?.metadata?.default_subjects ? [['default_subjects', r.metadata.default_subjects]] : []),
    ...(ssfState.status === 'waiting-for-user' ? [['note', 'Sign in: the active account\'s stream is created with its own access token.']] : []),
    ...((accounts?.list().length ?? 0) > 1 ? [['other accounts', 'dormant: their streams keep queueing at the transmitter, and are caught up when the account is activated']] : []),
  ].flatMap(([k, v]) => [el('dt', {}, k), el('dd', {}, v)]));
  $('ssf-events').replaceChildren(...(s?.events_delivered ?? []).map((e) => el('span', { class: 'chip', title: e }, e.split('/').pop())));
  $('btn-verify').disabled = !s;
  $('btn-reconnect').disabled = !me || !config?.caep?.enabled;
  $('ssf-error').hidden = !ssfState.error;
  $('ssf-error').textContent = ssfState.error ?? '';
  $('live').classList.toggle('on', !!caep.receiver);
}

function renderBanners() {
  const items = [];
  const banner = (level, title, text, ...actions) => el('div', { class: `banner ${level}`, role: level === 'danger' ? 'alert' : 'status' },
    el('div', {}, el('strong', {}, title), el('span', {}, text)), actions.length ? el('div', { class: 'banner-actions' }, ...actions) : '');
  const dismiss = (fn) => el('button', { class: 'btn', onclick: () => { fn(); render(); } }, 'Dismiss');
  if (ui.busy) items.push(banner('info', 'One moment', ui.busy));
  if (ui.error) items.push(banner('danger', 'Something went wrong', ui.error, dismiss(() => { ui.error = undefined; })));
  if (ui.attention) {
    const a = accounts?.get(ui.attention.key);
    items.push(banner('warn', `${labelOf(a)} needs to sign in`, ui.attention.text,
      el('button', { class: 'btn', onclick: () => reauthenticate(ui.attention.key) }, `Sign in as ${labelOf(a)}`),
      dismiss(() => { ui.attention = undefined; })));
  }
  const me = signedIn();
  for (const [key, reason] of ui.ended) {
    const a = accounts?.get(key);
    // The active account's ending is told by the hero card instead.
    if (!a || a.status !== 'ended' || key === accounts.activeKey) continue;
    const now = me ? ` This tab is now ${labelOf(me)}.` : '';
    items.push(banner('danger', `${labelOf(a)}'s session was ended`, `${reason}${now}`,
      el('button', { class: 'btn', onclick: () => reauthenticate(key) }, `Sign in again as ${labelOf(a)}`),
      dismiss(() => ui.ended.delete(key))));
  }
  if (me && stateOf(me.key).stepUp) {
    items.push(banner('warn', 'Step-up authentication required', stateOf(me.key).stepUp, el('button', { class: 'btn', onclick: () => reauthenticate(me.key) }, 'Re-authenticate')));
  }
  const notices = [...(me ? stateOf(me.key).notices.map((n) => [n, stateOf(me.key).notices]) : []), ...ui.notices.map((n) => [n, ui.notices])];
  for (const [n, from] of notices.slice(0, 3)) {
    items.push(banner(n.level, 'Notice', n.text, dismiss(() => from.splice(from.indexOf(n), 1))));
  }
  $('banners').replaceChildren(...items);
}

async function tick() {
  const me = signedIn();
  const t = me && await accounts.getTokenSet().catch(() => undefined);
  if (!t?.expires_at) return;
  const now = Date.now() / 1000;
  const lifetime = Math.max(1, t.expires_at - (t.issued_at ?? now));
  const left = Math.max(0, t.expires_at - now);
  const skew = Math.min(60, lifetime / 2);
  const fmt = (s) => `${Math.floor(s / 60)}:${String(Math.floor(s % 60)).padStart(2, '0')}`;
  const { lastRefresh } = stateOf(me.key);
  $('expires-in').textContent = fmt(left);
  $('refresh-in').textContent = t.refresh_token ? fmt(Math.max(0, left - skew)) : 'n/a';
  $('last-refresh').textContent = lastRefresh ? `${Math.round((Date.now() - lastRefresh) / 1000)}s ago` : 'never';
  $('meter-fill').style.width = `${(left / lifetime) * 100}%`;
  $('meter-skew').style.width = `${(skew / lifetime) * 100}%`;
}
setInterval(tick, 1000);

const SEVERITY = {
  'session-revoked': 'danger', 'credential-change': 'warn', 'device-compliance-change': 'warn', 'risk-level-change': 'warn',
  'assurance-level-change': 'warn', 'token-claims-change': 'info', 'session-established': 'ok', 'session-presented': 'ok',
  verification: 'ok', 'stream-updated': 'info',
};

/** The event log, for the active account or for every account. `freshAt` flashes the entry just received. */
function renderLog(freshAt) {
  const cur = accounts?.activeKey;
  const entries = eventLog();
  const all = logView === 'all' || !cur;
  const shown = entries.filter((e) => all || e.account === cur);
  for (const b of document.querySelectorAll('.log-seg')) {
    b.classList.toggle('on', b.dataset.view === logView);
    b.setAttribute('aria-selected', String(b.dataset.view === logView));
  }
  const multi = (accounts?.list().length ?? 0) > 1 || entries.some((e) => e.account && e.account !== cur);
  $('log').replaceChildren(...shown.map((entry) => logEntry(entry, entry.at === freshAt, all && multi)));
  $('log-empty').hidden = shown.length > 0;
  $('log-empty').textContent = entries.length && !all
    ? `No signals for ${labelOf(accounts.active)} yet. Switch to "All accounts" to see the others'.`
    : 'No CAEP events yet. Sign in, then trigger an event at your identity provider (for example, revoke your session).';
  const others = (accounts?.list() ?? []).reduce((n, a) => n + unreadFor(a.key), 0);
  $('log-all-count').textContent = others ? ` (${others} new)` : '';
}

function logEntry(entry, fresh, showAccount) {
  const node = $('log-item').content.firstElementChild.cloneNode(true);
  const evt = node.querySelector('.evt');
  evt.textContent = entry.name;
  evt.className = `evt ${SEVERITY[entry.name] ?? 'info'}`;
  evt.title = entry.type ?? '';
  node.querySelector('time').textContent = new Date(entry.at).toLocaleTimeString();
  const who = node.querySelector('.log-who');
  who.hidden = !showAccount;
  who.textContent = entry.label ?? '—';
  node.querySelector('.action').textContent = entry.action;
  node.querySelector('pre').textContent = JSON.stringify({ subject: entry.subject, payload: entry.payload, jti: entry.jti }, null, 2);
  if (fresh) node.classList.add('fresh');
  return node;
}

for (const b of document.querySelectorAll('.log-seg')) {
  b.addEventListener('click', () => {
    logView = b.dataset.view;
    store.set(LOG_VIEW_KEY, logView, sessionStorage);
    renderLog();
  });
}
// Signals received by the other tabs.
window.addEventListener('storage', (e) => {
  if (e.key === LOG_KEY) render();
});

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
  const me = signedIn();
  if (!me) return;
  const { refreshCount } = stateOf(me.key);
  const set = tokenTab === 'signIn'
    ? (signInTokens?.key === me.key ? signInTokens.tokenSet : undefined)
    : await accounts.getTokenSet().catch(() => undefined);
  $('tokens-note').textContent = tokenTab === 'signIn'
    ? `As returned by the token endpoint when ${labelOf(me)} signed in.`
    : `As currently cached for ${labelOf(me)}, the active account${refreshCount ? ` (after ${refreshCount} refresh${refreshCount > 1 ? 'es' : ''})` : ''}.`;
  if (!set) {
    $('tokens-body').replaceChildren(el('p', { class: 'muted small' }, tokenTab === 'signIn'
      ? 'Only kept for a sign-in made in this tab, while that account stays active. See "Current".'
      : 'Not available.'));
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

for (const b of document.querySelectorAll('.tok-seg')) {
  b.addEventListener('click', () => {
    tokenTab = b.dataset.which;
    for (const x of document.querySelectorAll('.tok-seg')) {
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
  $('storage-hint').textContent = $('use-dpop').checked
    ? 'Every signed-in account\'s tokens are cached in IndexedDB, shared by this browser\'s tabs. Script in this page can read them, but they are DPoP-bound: useless without the non-extractable key.'
    : '⚠ Every signed-in account\'s tokens are cached in IndexedDB as bearer tokens: any script injected into this page could read and replay them. Turn DPoP on.';
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
    // Reconfiguring signs every account out here.
    await resetAccounts();
    await applyConfig(cfg, { register });
    editing = false;
    formFilled = false;
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
for (const id of ['caep-enabled', 'use-dpop']) $(id).addEventListener('change', updateFieldsets);
for (const r of document.querySelectorAll('input[name="reg-mode"]')) r.addEventListener('change', updateMode);
$('btn-edit-config').addEventListener('click', () => { editing = true; formFilled = false; renderConfig(); });
$('btn-cancel').addEventListener('click', () => { editing = false; formFilled = false; renderConfig(); });

$('btn-add-account').addEventListener('click', () => addAccount());
$('btn-choose-account').addEventListener('click', () => chooseAccount());
document.addEventListener('click', (e) => {
  const menu = document.querySelector('.acct-menu');
  if (menu?.open && !menu.contains(e.target)) menu.open = false;
});
document.addEventListener('keydown', (e) => {
  if (e.key === 'Escape') closeMenu();
});

$('btn-userinfo').addEventListener('click', (e) => withBusy(e.currentTarget, async () => {
  const out = $('userinfo-out');
  out.hidden = false;
  const me = signedIn();
  try {
    const claims = await client.userinfo(await accounts.getTokenSet(), { expectedSub: me.sub });
    out.textContent = `GET userinfo (${labelOf(me)}) → 200\n${JSON.stringify(claims, null, 2)}`;
  } catch (err) {
    out.textContent = `GET userinfo failed: ${describe(err)}`;
  }
}));
$('btn-refresh').addEventListener('click', (e) => withBusy(e.currentTarget, async () => {
  try {
    await accounts.refresh();
  } catch (err) {
    ui.error = `Refresh failed: ${describe(err)}`;
    render();
  }
}));
$('btn-verify').addEventListener('click', (e) => withBusy(e.currentTarget, async () => {
  try {
    await caep.receiver.requestVerification({ timeoutMs: 15_000 });
  } catch (err) {
    caep.state = { ...caep.state, error: `Verification failed: ${describe(err)}` };
    render();
  }
}));
$('btn-reconnect').addEventListener('click', (e) => withBusy(e.currentTarget, async () => {
  const me = signedIn();
  const tokens = (opts) => accounts.getTokenSet(opts);
  await deleteStream(me, tokens);
  await startCaep(me, tokens);
}));

// ---------------------------------------------------------------------------
// Start-up
// ---------------------------------------------------------------------------

async function start() {
  const saved = store.get(CONFIG_KEY);
  if (saved?.metadata && saved.clientId) {
    try {
      await applyConfig(saved);
    } catch (err) {
      ui.error = `Saved configuration could not be applied: ${describe(err)}`;
      client = undefined;
      accounts = undefined;
    }
  }
  if (client) {
    const params = new URLSearchParams(location.search);
    if (location.pathname === '/callback') {
      await completeCallback();
    } else if (params.has('state')) {
      // Back from RP-initiated logout: the state must be the one sent.
      try {
        const { context } = await client.completeEndSession(location.href);
        const who = context?.key && accounts.get(context.key);
        ui.notices.unshift({ level: 'info', text: who ? `${labelOf(who)} is signed out of the identity provider. Your other accounts stay signed in.` : 'You are signed out of the identity provider.' });
      } catch (err) {
        ui.error = `Logout response rejected: ${describe(err)}`;
      }
      history.replaceState(null, '', '/');
    }
  } else if (location.pathname === '/callback') {
    ui.error = 'Returned from the identity provider, but this browser has no configuration for it.';
    history.replaceState(null, '', '/');
  }
  await render();
}

start();
