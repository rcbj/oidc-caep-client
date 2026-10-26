// CAEP demo SPA. The OIDC client runs HERE, in the browser, as a public client: Authorization Code + PKCE,
// state/nonce, PAR, DPoP with the key in session storage, RFC 9207, token caching with auto-refresh, and a
// CAEP (Shared Signals) stream polled with the active account's access token.
//
// Several accounts can be signed in at once (an OP such as iya-sts with authn.multipleAccounts keeps one
// session per person per browser). The library caches every account's tokens for the whole browser, shared
// by its tabs, and each tab has ONE active account: only its tokens are used and refreshed, and only its
// stream is polled. Switching makes another cached account active; its stream first catches up on the
// signals queued while it was dormant.
import { decodeJwt, decodeProtectedHeader } from 'jose';
import {
  AccountManager, CAEP, MemoryKeyStore, MemoryTokenStore, needsInteraction, OIDCClient,
  oidcDiscoveryUrl, SSFReceiver, Subject, subjectMatches, SUPPORTED_ID_TOKEN_ALGS, validateOpenIdProviderMetadata,
  WebStorageKeyStore, WebStorageTokenStore,
} from 'oidc-caep-client';

const $ = (id) => document.getElementById(id);
const ORIGIN = location.origin;
const URLS = { redirectUri: `${ORIGIN}/callback`, postLogoutRedirectUri: `${ORIGIN}/` };
// Every CAEP 1.0 event type, by its short name. A stream asks for the ones selected on the CAEP tab.
const CAEP_EVENTS = Object.values(CAEP).map((uri) => uri.split('/').pop());
const CONFIG_KEY = 'oidc-caep-demo.config';
// Shared by the tabs (localStorage): each account's stream id.
const STREAMS_KEY = 'oidc-caep-demo.stream-ids';
// Per tab (sessionStorage): the signals this tab received. The transmitter lets a session see only events
// about its own user, so the log shows the active account's alone and is never shared with other tabs.
const LOG_KEY = 'oidc-caep-demo.event-log';
const PAGE_TAB_KEY = 'oidc-caep-demo.page-tab';
const LABELS_KEY = 'oidc-caep-demo.labels';
// Shared by the tabs (localStorage): the event types this browser subscribes its streams to.
const EVENTS_KEY = 'oidc-caep-demo.caep-events';
// Kept when the configuration file changes. DPoP, PAR and the CAEP subscription used to be form fields.
const CLIENT_DEFAULTS = {
  dpop: true,
  par: 'auto',
  caep: {
    enabled: true,
    transmitterIssuer: '',
    maxSetAgeSec: 3600,
    subjectFormat: 'iss_sub',
    onlyUser: true,
  },
};

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

/** Display name and username learned from UserInfo, keyed by account. The ID token's subject is not a name. */
function accountLabel(key) {
  const all = store.get(LABELS_KEY, sessionStorage) ?? {};
  return all[key] ?? {};
}
function labelOf(a) {
  if (!a) return '—';
  const saved = accountLabel(a.key);
  const display = String(saved.name || a.name || '').trim();
  const username = String(saved.username || a.preferred_username || '').trim();
  if (display && username) return `${display} (${username})`;
  return display || username || a.email || a.sub || '—';
}
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

async function applyConfig(cfg) {
  accounts?.close();
  const metadata = typeof cfg.metadata === 'string' ? JSON.parse(cfg.metadata) : cfg.metadata;
  validateOpenIdProviderMetadata(metadata);
  if (!cfg.clientId) throw new Error('client_id is required');
  // This tab only. sessionStorage survives the redirect to the IdP and a reload, and closes with the tab.
  // localStorage is left for the configuration and the stream ids.
  const tabStorage = globalThis.sessionStorage;
  client = await OIDCClient.fromMetadata(metadata, {
    redirectUri: URLS.redirectUri,
    postLogoutRedirectUri: URLS.postLogoutRedirectUri,
    scope: cfg.scope || undefined,
    resource: cfg.resource || undefined,
    par: cfg.par ?? 'auto',
    dpop: cfg.dpop ? { keyStore: tabStorage ? new WebStorageKeyStore() : new MemoryKeyStore() } : false,
    idTokenSignedResponseAlg: cfg.idTokenAlg || pickIdTokenAlg(metadata),
    clientId: cfg.clientId,
  });
  config = { ...cfg, metadata };
  store.set(CONFIG_KEY, config);

  // One token cache for this tab (sessionStorage); one active account in the tab. The hooks tie this
  // tab's one CAEP stream to its active account.
  accounts = new AccountManager(client, {
    store: tabStorage ? new WebStorageTokenStore() : new MemoryTokenStore(),
    storeKey: `accounts:${metadata.issuer}:${config.clientId}`,
    onActivate: async (account, { getTokenSet }) => {
      await rememberProfile(account, getTokenSet);
      await startCaep(account, getTokenSet);
    },
    onDeactivate: (account) => stopCaep(account.key),
    onLeave: (account, { getTokenSet }) => deleteStream(account, getTokenSet),
  });
  accounts.on('refreshed', (a) => {
    const s = stateOf(a.key);
    s.refreshCount += 1;
    s.lastRefresh = Date.now();
    render();
  });
  // A signed-out or forgotten account's signals leave the tab with it.
  accounts.on('signed-out', (a) => clearLog(a.key));
  accounts.on('forgotten', (a) => clearLog(a.key));
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
// login: do not continue whoever is already signed in at the IdP. That skips
// this request's sign-in screen, and on iya-sts the control for becoming
// somebody else leaves for the user portal. consent: offline_access is
// ignored unless the request asks for it (OIDC Core §11).
const signIn = () => go((m) => m.signIn({ ...acr(), prompt: 'login consent' }));
const addAccount = () => go((m) => m.addAccount(acr()));
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

// ---------------------------------------------------------------------------
// CAEP: this tab polls ONE stream, the active account's, authorised by its (DPoP-bound) access token.
// A stream belongs to the principal that created it. This public client does not create, change, or
// delete streams: ssf.read can list, get, and poll, and ssf.manage is what writes. A dormant account's
// stream keeps queueing events, and activating the account catches up on them before its tokens are used.
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
function jwtPayload(token) {
  const part = String(token || '').split('.')[1];
  if (!part) return {};
  try {
    const padded = part.replace(/-/g, '+').replace(/_/g, '/');
    return JSON.parse(atob(padded.padEnd(padded.length + (4 - padded.length % 4) % 4, '='))) || {};
  } catch {
    return {};
  }
}
function firstText(...values) {
  for (const value of values) {
    const text = String(value ?? '').trim();
    if (text) return text;
  }
  return '';
}
// The transmitter enforces the scope inside the access token, which may be narrower than oidc.json.
function scopesOf(set) {
  const fromToken = String(jwtPayload(set?.access_token).scope || '').split(/\s+/).filter(Boolean);
  if (fromToken.length) return fromToken;
  return String(set?.scope || '').split(/\s+/).filter(Boolean);
}

/** Reads the display name and username. Profile claims are at UserInfo, not in this flow's ID token. */
async function rememberProfile(account, getTokenSet) {
  let set;
  try { set = await getTokenSet(); } catch { return; }
  const access = jwtPayload(set?.access_token);
  let info = {};
  try {
    info = await client.userinfo(set, { expectedSub: account.sub }) ?? {};
  } catch { /* the access token's username still labels the account */ }
  const name = firstText(info.name, info.nickname, account.name);
  const username = firstText(info.preferred_username, access.username, account.preferred_username);
  if (!name && !username) return;
  const all = store.get(LABELS_KEY, sessionStorage) ?? {};
  all[account.key] = { name, username };
  store.set(LABELS_KEY, all, sessionStorage);
}
/** The event types to subscribe to: the saved selection, or every CAEP type. */
function selectedEvents() {
  const saved = store.get(EVENTS_KEY);
  return Array.isArray(saved) ? CAEP_EVENTS.filter((n) => saved.includes(n)) : CAEP_EVENTS;
}
const eventUris = (names) => names.map((n) => Object.values(CAEP).find((u) => u.endsWith(`/${n}`)));

/** Asks the transmitter for the selected event types when the stream asks for others. Needs ssf.manage. */
async function syncEvents(r) {
  const want = eventUris(selectedEvents());
  const have = r.stream?.events_requested ?? [];
  if (want.length === have.length && want.every((u) => have.includes(u))) return false;
  await r.updateStream({ events_requested: want });
  return true;
}

const canReadStream = (scopes) => scopes.includes('ssf.read') || scopes.includes('ssf.manage');
const canWriteStream = (scopes) => scopes.includes('ssf.manage');
// The verify button follows the configuration. The transmitter still refuses a write the token lacks.
const streamWrite = () => String(config?.scope || '').split(/\s+/).includes('ssf.manage');

/** List this account's streams and poll the first one. Does not create a stream. */
async function adoptListed(account, getTokenSet) {
  const probe = makeReceiver(account, getTokenSet);
  await probe.discover();
  const existing = await probe.listStreams();
  const id = existing.find((s) => s?.stream_id)?.stream_id;
  if (!id) return undefined;
  const r = makeReceiver(account, getTokenSet, id);
  await r.start({ catchUp: true });
  return r;
}

function makeReceiver(account, getTokenSet, streamId) {
  const c = config.caep;
  return new SSFReceiver({
    transmitterIssuer: transmitterIssuer(),
    streamId,
    // Every management and poll call carries THIS account's access token, with a DPoP proof when bound.
    authorizationHeaders: async (req) => client.resourceHeaders(await getTokenSet(), req),
    eventsRequested: eventUris(selectedEvents()),
    description: `oidc-caep-client in-browser demo @ ${ORIGIN} (${labelOf(account)})`,
    pollIntervalMs: 5000,
    maxSetAgeSec: c.maxSetAgeSec,
    handlers: handlersFor(account.key, getTokenSet),
  });
}

/** Quiet stream-card state: a note, not the red transmitter error. */
function streamNote(key, status, note) {
  if (caep.key !== key) return;
  caep.state = { status, transmitter: transmitterIssuer(), note };
}

/** onActivate: read the account's stream and act on what it queued while dormant. */
async function startCaep(account, getTokenSet) {
  if (!config?.caep?.enabled) return;
  const key = account.key;
  caep = { key, receiver: undefined, state: { status: 'connecting', transmitter: transmitterIssuer() } };
  render();
  try {
    const scopes = scopesOf(await getTokenSet());
    if (!canReadStream(scopes)) {
      streamNote(key, 'unavailable', 'This sign-in was not issued ssf.read, so this tab is not reading a stream.');
      render();
      return;
    }
    const write = canWriteStream(scopes);
    const held = streamIds()[key];
    let r;
    if (held) {
      r = makeReceiver(account, getTokenSet, held);
      try {
        await r.start({ catchUp: true });
      } catch (err) {
        await r.stop().catch(() => {});
        if (!write) {
          // The remembered stream is gone. Do not create a replacement.
          r = await adoptListed(account, getTokenSet);
          if (!r) {
            streamNote(key, 'no-stream', 'No stream for this account. This client reads with ssf.read and does not create one.');
            render();
            return;
          }
        } else {
          r = makeReceiver(account, getTokenSet);
          await r.start({ catchUp: true });
        }
      }
    } else if (write) {
      r = makeReceiver(account, getTokenSet);
      await r.start({ catchUp: true });
    } else {
      r = await adoptListed(account, getTokenSet);
      if (!r) {
        streamNote(key, 'no-stream', 'No stream for this account. This client reads with ssf.read and does not create one.');
        render();
        return;
      }
    }
    if (caep.key !== key || accounts.get(key)?.status !== 'signed-in') {
      // A signal received while catching up ended the account, or another account was activated meanwhile.
      await r.stop();
      return;
    }
    caep.receiver = r;
    rememberStream(key, r.stream.stream_id);
    if (write) {
      await syncEvents(r).catch((err) => log({ account: key, name: 'subscription', action: `Could not update the stream's event types: ${describe(err)}` }));
    }
    if (write && config.caep.onlyUser && r.metadata.add_subject_endpoint) {
      await r.addSubject(subjectFor(account)).catch((err) => log({ account: key, name: 'subject', action: `Could not add the subject: ${describe(err)}` }));
    }
    caep.state = { status: 'connected', transmitter: transmitterIssuer(), streamStatus: r.stream.status ?? 'enabled', write };
    if (write) r.requestVerification({ timeoutMs: 30_000 }).catch(() => {});
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

/** onLeave: the account is signed out or ended. Delete its stream only when the token can write. */
async function deleteStream(account, getTokenSet) {
  await stopCaep(account.key);
  const id = streamIds()[account.key];
  if (!id || !config?.caep?.enabled) return;
  let scopes = [];
  try { scopes = scopesOf(await getTokenSet()); } catch { return; }
  if (!canWriteStream(scopes)) return;
  rememberStream(account.key, undefined);
  const r = makeReceiver(account, getTokenSet, id);
  try {
    await r.discover();
    r.stream = { stream_id: id };
    await r.deleteStream();
  } catch { /* the transmitter forgets an unused stream on its own */ }
}

// The log used to be shared through localStorage, where every tab could read every account's signals.
store.del(LOG_KEY);

/** The signals this tab has received, newest first, for every account it has had active. */
const eventLog = () => store.get(LOG_KEY, sessionStorage) ?? [];

/** Removes one account's signals from this tab. */
function clearLog(key) {
  store.set(LOG_KEY, eventLog().filter((e) => e.account !== key), sessionStorage);
  renderLog();
}

function log(entry) {
  const entries = eventLog();
  // Poll delivery is at-least-once.
  if (entry.jti && entries.some((e) => e.jti === entry.jti && e.account === entry.account)) return;
  const full = { at: Date.now(), ...entry };
  entries.unshift(full);
  entries.length = Math.min(entries.length, 300);
  store.set(LOG_KEY, entries, sessionStorage);
  renderLog(full.at);
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

  renderWho(list);
  renderHero(list);

  $('session-empty').hidden = !!me;
  $('claims').hidden = !me;
  $('btn-userinfo').disabled = !me;
  $('btn-refresh').disabled = !me;
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
  } else {
    $('session-title').textContent = 'Session';
    $('claims').replaceChildren();
    const pill = $('session-pill');
    pill.textContent = 'Signed out';
    pill.className = 'pill';
    $('refresh-count').textContent = '';
  }

  $('security-empty').hidden = configured;
  $('security-list').hidden = !configured;
  if (configured) {
    const f = client.securityFeatures;
    const items = [
      ['Public client', 'no client secret; token_endpoint_auth_method none'],
      ['PKCE', f.pkce],
      ['state', f.state],
      ['nonce', 'random, checked against the ID token'],
      ['Issuer identification', f.issuerIdentification],
      ['Pushed Authorization Requests', f.par ? 'on: the request never passes through the browser URL' : 'off'],
      ['DPoP', f.dpop ? `on (${f.dpop.alg}, this tab's session storage, jkt ${f.dpop.jkt.slice(0, 12)}…)` : 'off: bearer tokens'],
      ['ID token', f.idToken],
      ['TLS', f.tlsEnforced ? 'required for the IdP and redirect URIs (loopback excepted)' : 'not enforced'],
      ['Token cache', 'this tab\'s tokens, in session storage, cleared when the tab closes'],
      ['One active account per tab', 'only its tokens are reachable, refreshed and used to poll; the others stay dormant until activated, and their queued signals are acted on first'],
      ['Several accounts', 'a sign-in naming an account refuses anybody else; sign-out names the account\'s ID token so only its IdP session ends'],
      ['Resource indicators', f.resourceIndicators ? f.resourceIndicators.join(', ') : 'none'],
      ['Page', 'CSP (no inline script), Referrer-Policy no-referrer, framing denied'],
    ];
    $('security-list').replaceChildren(...items.map(([k, v]) => el('li', {}, el('strong', {}, k), el('span', { class: 'muted' }, ` ${v}`))));
  }

  renderStream();
  renderBanners();
  renderLog();
  tick();
  await renderTokens();
}

function avatar(a, cls = '') {
  return el('span', { class: `avatar ${cls}`, 'aria-hidden': 'true' }, initialOf(a));
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
  // The active account is listed too while it has no session, so that choosing it signs it in.
  const choices = cur && cur.status !== 'signed-in' ? [cur, ...others] : others;
  const wasOpen = document.querySelector('.acct-menu')?.open;
  // An account with no session (signed out, or ended) can only come back through a sign-in that names it.
  const pick = (a) => (a.status === 'signed-in' ? activate(a.key) : (closeMenu(), reauthenticate(a.key)));
  const row = (a) => el('button', { class: 'menu-row', type: 'button', role: 'menuitem', onclick: () => pick(a) },
    avatar(a),
    el('span', { class: 'menu-who' }, el('span', {}, labelOf(a)), a.email ? el('span', { class: 'muted small' }, a.email) : ''),
    a.status === 'signed-in' ? '' : el('span', { class: `pill ${STATUS[a.status][0]}` }, STATUS[a.status][1]));
  const menu = el('details', { class: 'acct-menu' },
    el('summary', { 'aria-label': 'Switch account' },
      cur ? avatar(cur) : '',
      el('span', { class: 'menu-name' }, cur ? labelOf(cur) : 'Choose an account'),
      el('span', { class: 'caret', 'aria-hidden': 'true' }, '▾')),
    el('div', { class: 'menu', role: 'menu' },
      el('p', { class: 'menu-head' }, 'Switch account'),
      ...(choices.length ? choices.map(row) : [el('p', { class: 'muted small menu-note' }, 'No other account yet.')]),
      el('div', { class: 'menu-sep' }),
      el('button', { class: 'menu-row', type: 'button', role: 'menuitem', onclick: () => addAccount() }, el('span', { class: 'avatar plus', 'aria-hidden': 'true' }, '+'), 'Sign in with another account'),
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
  let title = 'Sign in';
  let text = 'Sign in through your identity provider. This tab keeps the session and the tokens. CAEP events are on the other tab.';
  if (!client) {
    title = 'Identity provider';
    text = 'Loading the OIDC configuration.';
  } else if (cur?.status === 'signed-in') {
    title = `Signed in as ${labelOf(cur)}`;
    text = 'The session, token cache, and tokens for this account are on this tab.';
  } else if (cur && cur.status === 'tokens-missing') {
    title = `Continue as ${labelOf(cur)}`;
    text = 'The tokens cached for this account have expired and cannot be refreshed. New ones can be fetched without a password while its session at the identity provider lasts.';
    actions.push(el('button', { class: 'btn primary', onclick: () => resume(cur.key) }, `Continue as ${labelOf(cur)}`));
  } else if (cur) {
    title = cur.status === 'ended' ? `${labelOf(cur)}'s session was ended` : `${labelOf(cur)} is signed out`;
    text = `${cur.status === 'ended' && cur.endedReason ? `${cur.endedReason} ` : ''}Sign in again as ${labelOf(cur)}, switch to another account, or sign in with another account.`;
    actions.push(el('button', { class: 'btn primary', onclick: () => reauthenticate(cur.key) }, `Sign in again as ${labelOf(cur)}`));
  } else if (list.some((a) => a.status === 'signed-in')) {
    title = 'Choose an account for this tab';
    text = 'These accounts are signed in in this tab. Pick one from the menu under your name. No password is needed.';
  } else if (list.length) {
    title = 'Choose an account';
    text = 'None of the accounts in this tab is signed in. Sign in again as one of them from the menu, or sign in with another account.';
  }
  if (client) actions.push(el('button', { class: `btn ${actions.length ? 'ghost' : 'primary'}`, onclick: () => (list.length ? addAccount() : signIn()) }, list.length ? 'Sign in with another account' : 'Sign in'));
  $('hero-title').textContent = title;
  $('hero-text').textContent = text;
  $('hero-actions').replaceChildren(...actions);
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
    ...(ssfState.status === 'waiting-for-user' ? [['note', 'Sign in. This tab reads the active account\'s stream when its access token carries ssf.read.']] : []),
    ...(ssfState.note ? [['note', ssfState.note]] : []),
    ...((accounts?.list().length ?? 0) > 1 ? [['other accounts', 'dormant: their streams keep queueing at the transmitter, and are caught up when the account is activated']] : []),
  ].flatMap(([k, v]) => [el('dt', {}, k), el('dd', {}, v)]));
  $('ssf-events').replaceChildren(...(s?.events_delivered ?? []).map((e) => el('span', { class: 'chip', title: e }, e.split('/').pop())));
  renderEventPicker(me && caep.key === me.key && caep.receiver ? caep.state : undefined);
  $('btn-verify').disabled = !s || !streamWrite();
  $('btn-verify').title = streamWrite() ? '' : 'Needs the ssf.manage scope';
  $('btn-reconnect').disabled = !me || !config?.caep?.enabled;
  $('ssf-error').hidden = !ssfState.error;
  $('ssf-error').textContent = ssfState.error ?? '';
  $('live').classList.toggle('on', !!caep.receiver);
}

/** The checkboxes are drawn once and kept as the person left them; this sets the button and the note. */
function renderEventPicker(state) {
  const picked = pickedEvents();
  const saved = selectedEvents();
  const dirty = picked.length !== saved.length || picked.some((n) => !saved.includes(n));
  const button = $('btn-events');
  button.disabled = !state?.write || !picked.length || !dirty;
  $('events-note').textContent = !state
    ? 'Sign in to change this stream\'s event types.'
    : !state.write
      ? 'Changing the stream needs the ssf.manage scope. This sign-in was issued ssf.read only.'
      : !picked.length ? 'Choose at least one event type.' : dirty ? 'Not applied yet.' : 'The stream asks for these.';
}
const pickedEvents = () => [...document.querySelectorAll('#event-options input:checked')].map((i) => i.value);

function drawEventOptions() {
  const saved = selectedEvents();
  $('event-options').replaceChildren(...CAEP_EVENTS.map((name) => el('label', { class: 'check' },
    el('input', { type: 'checkbox', value: name, ...(saved.includes(name) ? { checked: '' } : {}), onchange: () => renderStream() }),
    el('span', {}, name))));
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
  if (!t?.expires_at) {
    $('expires-in').textContent = '—';
    $('refresh-in').textContent = '—';
    $('last-refresh').textContent = '—';
    $('meter-fill').style.width = '0%';
    $('meter-skew').style.width = '0%';
    return;
  }
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

/** The event log: the active account's signals only. `freshAt` flashes the entry just received. */
function renderLog(freshAt) {
  const cur = accounts?.activeKey;
  const shown = cur ? eventLog().filter((e) => e.account === cur) : [];
  $('log').replaceChildren(...shown.map((entry) => logEntry(entry, entry.at === freshAt)));
  $('btn-clear-log').disabled = shown.length === 0;
  $('log-empty').hidden = shown.length > 0;
  $('log-empty').textContent = cur
    ? `No CAEP events for ${labelOf(accounts.active)} yet. Trigger one at your identity provider (for example, revoke your session).`
    : 'No CAEP events yet. Sign in, then trigger an event at your identity provider (for example, revoke your session).';
}

function logEntry(entry, fresh) {
  const node = $('log-item').content.firstElementChild.cloneNode(true);
  const evt = node.querySelector('.evt');
  evt.textContent = entry.name;
  evt.className = `evt ${SEVERITY[entry.name] ?? 'info'}`;
  evt.title = entry.type ?? '';
  node.querySelector('time').textContent = new Date(entry.at).toLocaleTimeString();
  node.querySelector('.action').textContent = entry.action;
  node.querySelector('pre').textContent = JSON.stringify({ subject: entry.subject, payload: entry.payload, jti: entry.jti }, null, 2);
  if (fresh) node.classList.add('fresh');
  return node;
}

$('btn-clear-log').addEventListener('click', () => clearLog(accounts?.activeKey));

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
  if (!me) {
    $('tokens-note').textContent = 'No tokens until someone is signed in on this tab.';
    $('tokens-body').replaceChildren();
    return;
  }
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
// OIDC configuration file
// ---------------------------------------------------------------------------

function parseOidcFile(doc) {
  if (!doc || typeof doc !== 'object') throw new Error('The configuration file is not a JSON object.');
  const metadataUrl = String(doc.metadataUrl ?? '').trim();
  const clientId = String(doc.client_id ?? doc.clientId ?? '').trim();
  const scopes = Array.isArray(doc.scopes)
    ? doc.scopes.map((s) => String(s).trim()).filter(Boolean).join(' ')
    : String(doc.scopes ?? '').trim();
  if (!metadataUrl) throw new Error('The configuration file needs metadataUrl.');
  if (!clientId) throw new Error('The configuration file needs client_id.');
  if (!scopes) throw new Error('The configuration file needs scopes.');
  const url = new URL(metadataUrl.includes('/.well-known/') ? metadataUrl : oidcDiscoveryUrl(metadataUrl.replace(/\/+$/, '')));
  return { metadataUrl: url.href, clientId, scopes };
}

async function fetchProviderMetadata(metadataUrl) {
  const res = await fetch(metadataUrl, { headers: { accept: 'application/json' } });
  if (!res.ok) throw new Error(`HTTP ${res.status} from ${metadataUrl}`);
  const metadata = await res.json();
  validateOpenIdProviderMetadata(metadata);
  return metadata;
}

/** Connects the in-browser client from an OIDC configuration file. */
async function connectFromFile(doc) {
  const parsed = parseOidcFile(doc);
  const metadata = await fetchProviderMetadata(parsed.metadataUrl);
  const same = client
    && config?.metadataUrl === parsed.metadataUrl
    && config?.clientId === parsed.clientId
    && config?.scope === parsed.scopes;
  if (!same) {
    await applyConfig({
      metadata,
      metadataUrl: parsed.metadataUrl,
      clientId: parsed.clientId,
      scope: parsed.scopes,
      ...CLIENT_DEFAULTS,
      caep: { ...CLIENT_DEFAULTS.caep },
    });
  }
}

function showPageTab(which) {
  const name = which === 'caep' ? 'caep' : 'identity';
  store.set(PAGE_TAB_KEY, name, sessionStorage);
  for (const id of ['identity', 'caep']) {
    const on = id === name;
    $(`panel-${id}`).hidden = !on;
    const tab = $(`tab-${id}`);
    tab.setAttribute('aria-selected', String(on));
    tab.tabIndex = on ? 0 : -1;
  }
}

for (const tab of document.querySelectorAll('.page-tab')) {
  tab.addEventListener('click', () => showPageTab(tab.dataset.page));
}
document.querySelector('.page-tabs').addEventListener('keydown', (e) => {
  if (e.key !== 'ArrowRight' && e.key !== 'ArrowLeft') return;
  const tabs = [...document.querySelectorAll('.page-tab')];
  const i = tabs.indexOf(document.activeElement);
  if (i < 0) return;
  e.preventDefault();
  const next = tabs[(i + (e.key === 'ArrowRight' ? 1 : tabs.length - 1)) % tabs.length];
  next.focus();
  showPageTab(next.dataset.page);
});
showPageTab(store.get(PAGE_TAB_KEY, sessionStorage) === 'caep' ? 'caep' : 'identity');

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
// Not withBusy: its finally would enable the button again, and renderStream() decides that.
$('btn-events').addEventListener('click', async (e) => {
  e.currentTarget.disabled = true;
  store.set(EVENTS_KEY, pickedEvents());
  const r = caep.receiver;
  try {
    if (r && caep.state.write && await syncEvents(r)) {
      log({ account: caep.key, name: 'subscription', action: `Stream now asks for: ${selectedEvents().join(', ')}.` });
    }
  } catch (err) {
    caep.state = { ...caep.state, error: `Could not update the stream's event types: ${describe(err)}` };
  }
  render();
});
$('btn-reconnect').addEventListener('click', (e) => withBusy(e.currentTarget, async () => {
  const me = signedIn();
  const tokens = (opts) => accounts.getTokenSet(opts);
  const scopes = scopesOf(await tokens().catch(() => ({})));
  if (canWriteStream(scopes)) await deleteStream(me, tokens);
  else await stopCaep(me.key);
  await startCaep(me, tokens);
}));

// ---------------------------------------------------------------------------
// Start-up
// ---------------------------------------------------------------------------

async function start() {
  drawEventOptions();
  try {
    const res = await fetch('/oidc.json', { cache: 'no-store' });
    if (!res.ok) throw new Error(`HTTP ${res.status} reading /oidc.json`);
    await connectFromFile(await res.json());
  } catch (err) {
    ui.error = `OIDC configuration could not be applied: ${describe(err)}`;
    client = undefined;
    accounts = undefined;
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
