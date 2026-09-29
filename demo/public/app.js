// SPA for the CAEP demo. All tokens stay on the server (BFF pattern); the browser only sees
// session state and CAEP activity, pushed over Server-Sent Events.

const $ = (id) => document.getElementById(id);
const api = (path, opts = {}) => fetch(path, { ...opts, headers: { 'x-demo-csrf': '1', ...opts.headers } });

let state = { authenticated: false };
const notices = [];

const SEVERITY = {
  'session-revoked': 'danger',
  'credential-change': 'warn',
  'device-compliance-change': 'warn',
  'risk-level-change': 'warn',
  'assurance-level-change': 'warn',
  'token-claims-change': 'info',
  'session-established': 'ok',
  'session-presented': 'ok',
  verification: 'ok',
  'stream-updated': 'info',
};

// ---------------------------------------------------------------------------
// Rendering
// ---------------------------------------------------------------------------

function render() {
  const { authenticated, user, token, config } = state;
  const configured = !!config?.configured;
  $('signed-out').hidden = authenticated || !configured;
  $('session-card').hidden = !authenticated;
  $('token-card').hidden = !authenticated;
  $('tokens-card').hidden = !authenticated;

  $('who').replaceChildren(...(authenticated
    ? [
        el('span', { class: 'avatar', 'aria-hidden': 'true' }, String(user.name ?? user.email ?? user.sub)[0].toUpperCase()),
        el('span', {}, user.name ?? user.email ?? user.sub),
        el('button', { class: 'btn ghost', onclick: logout }, 'Sign out'),
      ]
    : configured ? [el('a', { class: 'btn primary', href: '/login' }, 'Sign in')] : []));

  if (authenticated) {
    const shown = ['sub', 'name', 'email', 'acr', 'amr', 'sid', 'iss', 'auth_time'];
    $('claims').replaceChildren(...shown.filter((k) => user[k] !== undefined).flatMap((k) => [
      el('dt', {}, k),
      el('dd', {}, k === 'auth_time' ? new Date(user[k] * 1000).toLocaleTimeString() : typeof user[k] === 'object' ? JSON.stringify(user[k]) : String(user[k])),
    ]));
    const pill = $('session-pill');
    pill.textContent = state.stepUpRequired ? 'Step-up required' : 'Active';
    pill.className = `pill ${state.stepUpRequired ? 'warn' : 'ok'}`;
    $('refresh-count').textContent = `${token?.refresh_count ?? 0} refreshes`;
  }

  renderConfig();
  const ssf = state.ssf;
  if (ssf) {
    const status = ssf.status === 'connected' ? ssf.streamStatus ?? 'enabled' : ssf.status;
    const pill = $('ssf-pill');
    pill.textContent = status;
    pill.className = `pill ${status === 'enabled' ? 'ok' : status === 'error' ? 'danger' : 'warn'}`;
    $('ssf-info').replaceChildren(...[
      ['transmitter', ssf.transmitter ?? '—'],
      ...(ssf.authorizedBy ? [['authorized by', ssf.authorizedBy]] : []),
      ...(ssf.info ? [['note', ssf.info]] : []),
      ...(ssf.default_subjects ? [['default_subjects', ssf.default_subjects]] : []),
      ...(ssf.aud ? [['SET audience', [].concat(ssf.aud).join(', ')]] : []),
      ...(ssf.stream_id ? [['subjects', ssf.subjects?.length
        ? ssf.subjects.map((x) => x.sub ?? x.email ?? JSON.stringify(x)).join(', ')
        : ssf.default_subjects === 'ALL' ? 'none added: ALL users in the realm' : 'none added']] : []),
      ...(ssf.max_set_age_sec !== undefined ? [['max SET age', ssf.max_set_age_sec ? `${ssf.max_set_age_sec}s` : 'unlimited']] : []),
      ['stream_id', ssf.stream_id ?? '—'],
      ['delivery', ssf.delivery ? `${ssf.delivery} (${ssf.delivery.endsWith('8935') ? 'push' : 'poll'})` : '—'],
    ].flatMap(([k, v]) => [el('dt', {}, k), el('dd', {}, v)]));
    $('ssf-events').replaceChildren(...ssf.events_delivered.map((e) => el('span', { class: 'chip', title: e }, e.split('/').pop())));
    $('btn-verify').disabled = !ssf.stream_id;
    $('btn-reconnect').disabled = !configured || ssf.status === 'disabled';
    $('ssf-error').hidden = !ssf.error;
    $('ssf-error').textContent = ssf.error ?? '';
  }

  renderBanners();
  tick();
}

function renderBanners() {
  const items = [];
  if (!state.authenticated && state.endedReason) {
    items.push(banner('danger', 'Your session was ended', state.endedReason, el('a', { class: 'btn', href: '/login' }, 'Sign in again')));
  }
  if (state.authenticated && state.stepUpRequired) {
    items.push(banner('warn', 'Step-up authentication required', state.stepUpRequired, el('a', { class: 'btn', href: '/login?stepup=1' }, 'Re-authenticate')));
  }
  const err = new URLSearchParams(location.search).get('error');
  if (err) items.push(banner('danger', 'Sign-in failed', err));
  for (const n of notices) items.push(banner(n.level, 'Notice from the identity provider', n.text));
  $('banners').replaceChildren(...items);
}

function banner(level, title, text, action) {
  return el('div', { class: `banner ${level}`, role: level === 'danger' ? 'alert' : 'status' },
    el('div', {}, el('strong', {}, title), el('span', {}, text)), action ?? '');
}

/** Updates the token countdown once a second. */
function tick() {
  const t = state.token;
  if (!state.authenticated || !t?.expires_at) return;
  const now = Date.now() / 1000;
  const lifetime = Math.max(1, t.expires_at - (t.issued_at ?? now));
  const left = Math.max(0, t.expires_at - now);
  const skew = Math.min(t.skew_sec, lifetime / 2);
  $('expires-in').textContent = fmt(left);
  $('refresh-in').textContent = t.has_refresh_token ? fmt(Math.max(0, left - skew)) : 'n/a';
  $('last-refresh').textContent = t.last_refresh ? `${Math.round((Date.now() - t.last_refresh) / 1000)}s ago` : 'never';
  $('meter-fill').style.width = `${(left / lifetime) * 100}%`;
  $('meter-skew').style.width = `${(skew / lifetime) * 100}%`;
}
setInterval(tick, 1000);

const fmt = (s) => `${Math.floor(s / 60)}:${String(Math.floor(s % 60)).padStart(2, '0')}`;

function addLogEntry(entry, fresh) {
  const node = $('log-item').content.firstElementChild.cloneNode(true);
  const evt = node.querySelector('.evt');
  evt.textContent = entry.name;
  evt.className = `evt ${SEVERITY[entry.name] ?? 'info'}`;
  evt.title = entry.type;
  node.querySelector('time').textContent = new Date(entry.at).toLocaleTimeString();
  node.querySelector('.action').textContent = entry.action;
  node.querySelector('pre').textContent = JSON.stringify({ subject: entry.subject, payload: entry.payload, jti: entry.jti }, null, 2);
  if (fresh) node.classList.add('fresh');
  $('log').prepend(node);
  $('log-empty').hidden = true;
}

function el(tag, attrs = {}, ...children) {
  const node = document.createElement(tag);
  for (const [k, v] of Object.entries(attrs)) {
    if (k.startsWith('on')) node.addEventListener(k.slice(2), v);
    else node.setAttribute(k, v);
  }
  node.append(...children.filter((c) => c !== ''));
  return node;
}

// ---------------------------------------------------------------------------
// Identity provider configuration
// ---------------------------------------------------------------------------

let editing = false;
let formFilled = false;

function renderConfig() {
  const cfg = state.config;
  if (!cfg) return;
  const cur = cfg.current;
  const showForm = !cfg.configured || editing;
  $('config-form').hidden = !showForm;
  $('config-summary').hidden = showForm;
  $('btn-cancel').hidden = !cfg.configured;
  const pill = $('config-pill');
  pill.textContent = cfg.configured ? 'Configured' : 'Not configured';
  pill.className = `pill ${cfg.configured ? 'ok' : 'warn'}`;

  if (cur) {
    $('config-summary-kv').replaceChildren(...[
      ['issuer', cur.issuer],
      ['client_id', cur.clientId],
      ...(cur.registration ? [['registration', `dynamic · ${new Date(cur.registration.registered_at).toLocaleString()}${cur.registration.manageable ? ' · manageable (RFC 7592)' : ''}`]] : []),
      ['client auth', cur.effectiveAuthMethod],
      ['ID token alg', cur.effectiveIdTokenAlg],
      ['scope', cur.effectiveScope],
      ['CAEP', cur.caep.enabled ? `${cur.caep.delivery} · ${cur.caep.transmitterIssuer ?? `${cur.issuer} (OIDC issuer)`}` : 'disabled'],
    ].flatMap(([k, v]) => [el('dt', {}, k), el('dd', {}, v ?? '—')]));
  }

  $('register-urls').replaceChildren(...[
    ['redirect_uri', cfg.urls.redirectUri],
    ['post_logout_redirect_uri', cfg.urls.postLogoutRedirectUri],
    ['CAEP push endpoint', cfg.urls.pushEndpointUrl],
  ].flatMap(([k, v]) => [
    el('dt', {}, k),
    el('dd', {}, el('span', {}, v), el('button', { class: 'copy', type: 'button', onclick: (e) => copy(v, e.currentTarget) }, 'Copy')),
  ]));

  if (showForm && !formFilled) fillForm(cfg);
}

function fillForm(cfg) {
  formFilled = true;
  const cur = cfg.current;
  $('metadata').value = cur ? JSON.stringify(cur.metadata, null, 2) : '';
  $('client-id').value = cur?.clientId ?? '';
  $('client-secret').value = '';
  $('client-secret').placeholder = cur?.hasClientSecret ? '•••••••• (unchanged)' : '';
  $('clear-secret-row').hidden = !cur?.hasClientSecret;
  $('clear-secret').checked = false;
  $('auth-method').value = cur?.tokenEndpointAuthMethod ?? '';
  populateAlgs(cur?.metadata, cur?.idTokenSignedResponseAlg ?? '');
  $('scope').value = cur?.scope ?? '';
  $('caep-enabled').checked = cur ? cur.caep.enabled : true;
  // The transmitter defaults to the OIDC issuer; remember when the field holds that automatic value.
  $('ssf-issuer').value = cur?.caep.transmitterIssuer ?? cur?.issuer ?? '';
  autoSsfIssuer = cur && !cur.caep.transmitterIssuer ? cur.issuer : '';
  $('ssf-delivery').value = cur?.caep.delivery ?? (cfg.isLocal ? 'poll' : 'push');
  $('ssf-scope').value = cur?.caep.managementScope ?? '';
  $('ssf-auth').value = cur?.caep.managementAuth ?? 'user';
  $('ssf-max-age').value = cur?.caep.maxSetAgeSec ?? 3600;
  $('ssf-only-users').checked = cur ? cur.caep.onlySignedInUsers !== false : true;
  $('ssf-subject').value = cur?.caep.subjectFormat ?? 'iss_sub';
  const selected = new Set(cur?.caep.events ?? cfg.defaultCaepEvents);
  $('ssf-events-pick').replaceChildren(...cfg.caepEvents.map((name) => el('label', { class: 'check small' },
    Object.assign(el('input', { type: 'checkbox', value: name }), { checked: selected.has(name) }), name)));
  $('ssf-token').value = '';
  $('ssf-token').placeholder = cur?.caep.hasManagementToken ? '•••••••• (unchanged)' : '';
  $('config-error').hidden = true;
  document.querySelector('input[name="reg-mode"][value="static"]').checked = true;
  $('client-name').value = cur?.registration?.client_name ?? '';
  $('initial-token').value = '';
  $('software-statement').value = '';
  summarizeMetadata();
  updateCaepFieldset();
  updateMode();
  // With nothing configured on the server (e.g. after a restart), bring back what was last typed.
  if (!cur && restoreForm()) {
    try {
      const issuer = JSON.parse($('metadata').value).issuer;
      if ($('ssf-issuer').value.trim() === issuer) autoSsfIssuer = issuer;
    } catch {
      // No valid metadata stored: nothing to follow.
    }
    summarizeMetadata();
    updateCaepFieldset();
    updateMode();
    restoreForm(); // again, for values whose options only exist once the metadata is read (ID token alg)
  }
}

// ---------------------------------------------------------------------------
// Remembered form values (localStorage). Secrets are never stored: client_secret, the management API
// bearer token and the DCR initial access token.
// ---------------------------------------------------------------------------

const FORM_STORE_KEY = 'oidc-caep-demo.config-form';
const NOT_STORED = new Set(['client-secret', 'clear-secret', 'ssf-token', 'initial-token']);

function formFields() {
  return [...$('config-form').querySelectorAll('input, select, textarea')]
    .filter((f) => f.type !== 'password' && !NOT_STORED.has(f.id));
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
  try {
    localStorage.setItem(FORM_STORE_KEY, JSON.stringify(values));
  } catch {
    // Storage unavailable (private window, blocked): the form still works, it just isn't remembered.
  }
}

/** Puts back the stored values. Returns false when nothing was stored. */
function restoreForm() {
  let values;
  try {
    values = JSON.parse(localStorage.getItem(FORM_STORE_KEY) || 'null');
  } catch {
    values = null;
  }
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
  return true;
}

const regMode = () => document.querySelector('input[name="reg-mode"]:checked').value;

/** Shows the fields for the chosen client registration mode. */
function updateMode() {
  let m;
  try { m = JSON.parse($('metadata').value); } catch { m = undefined; }
  const canRegister = !!m?.registration_endpoint;
  const dcr = document.querySelector('input[name="reg-mode"][value="dynamic"]');
  dcr.disabled = !canRegister;
  if (!canRegister && dcr.checked) document.querySelector('input[name="reg-mode"][value="static"]').checked = true;
  $('dcr-note').textContent = canRegister ? 'OpenID Connect Dynamic Client Registration' : m ? 'This IdP has no registration_endpoint' : 'Load the metadata first';
  const dynamic = regMode() === 'dynamic';
  $('static-fields').hidden = dynamic;
  $('dynamic-fields').hidden = !dynamic;
  $('alg-hint').textContent = dynamic
    ? 'Registered as id_token_signed_response_alg. The app refuses the registration if the IdP assigns a different algorithm.'
    : 'Must match the algorithm your client is registered with at the IdP.';
  $('btn-save').textContent = dynamic ? 'Register client & connect' : 'Save & connect';
}

/** ID token algs offered: those the OP advertises that the library can verify. */
function populateAlgs(metadata, selected = $('id-token-alg').value) {
  const supported = state.config?.supportedIdTokenAlgs ?? [];
  const advertised = [].concat(metadata?.id_token_signing_alg_values_supported ?? []);
  const usable = advertised.filter((a) => supported.includes(a));
  const skipped = advertised.filter((a) => a !== 'none' && !supported.includes(a));
  $('id-token-alg').replaceChildren(
    el('option', { value: '' }, `Automatic (${usable.includes('RS256') ? 'RS256' : usable.find((a) => !a.startsWith('HS')) ?? 'RS256'})`),
    ...usable.map((a) => el('option', { value: a }, a)),
  );
  $('id-token-alg').value = usable.includes(selected) ? selected : '';
  $('id-token-alg').title = skipped.length ? `Not verifiable by this library: ${skipped.join(', ')}` : '';
}

let autoSsfIssuer = '';

function updateSsfIssuerHint(oidcIssuer) {
  const value = $('ssf-issuer').value.trim();
  $('ssf-issuer-hint').textContent = !value ? ''
    : value === oidcIssuer ? 'Same as the OIDC issuer.'
    : `Differs from the OIDC issuer (${oidcIssuer}).`;
}

/** Live feedback on the pasted metadata document. */
function summarizeMetadata() {
  const out = $('metadata-summary');
  const text = $('metadata').value.trim();
  out.className = 'hint';
  if (!text) {
    out.textContent = '';
    return;
  }
  let m;
  try {
    m = JSON.parse(text);
  } catch (err) {
    out.textContent = `Not valid JSON: ${err.message}`;
    out.classList.add('bad');
    updateMode();
    return;
  }
  const required = ['issuer', 'authorization_endpoint', 'token_endpoint', 'jwks_uri', 'response_types_supported', 'subject_types_supported', 'id_token_signing_alg_values_supported'];
  const missing = required.filter((k) => m?.[k] === undefined);
  if (missing.length) {
    out.textContent = `Missing required metadata: ${missing.join(', ')}`;
    out.classList.add('bad');
    return;
  }
  const extras = ['userinfo_endpoint', 'end_session_endpoint', 'revocation_endpoint'].filter((k) => m[k]).map((k) => k.replace('_endpoint', ''));
  out.textContent = `Issuer ${m.issuer} · ID token algs ${[].concat(m.id_token_signing_alg_values_supported).join(', ')}${extras.length ? ` · ${extras.join(', ')}` : ''}`;
  out.classList.add('ok');
  // Keep the SSF transmitter issuer on the OIDC issuer unless the user typed a different one.
  const ssfIssuer = $('ssf-issuer');
  if (!ssfIssuer.value.trim() || ssfIssuer.value.trim() === autoSsfIssuer) {
    ssfIssuer.value = m.issuer;
    autoSsfIssuer = m.issuer;
  }
  updateSsfIssuerHint(m.issuer);
  populateAlgs(m);
  // Suggest the OP's SSF management scopes (e.g. "ssf:read ssf:write") when none is set.
  const ssfScopes = [].concat(m.scopes_supported ?? []).filter((sc) => /^ssf[:._-]/i.test(sc));
  if (!$('ssf-scope').value && ssfScopes.length) $('ssf-scope').value = ssfScopes.join(' ');
  if (!$('scope').value && ssfScopes.length) {
    const base = ['openid', 'profile', 'email', ...([].concat(m.scopes_supported ?? []).includes('offline_access') ? ['offline_access'] : [])];
    $('scope').value = [...base, ...ssfScopes].join(' ');
  }
  updateMode();
}

function updateCaepFieldset() {
  document.querySelector('.caep').classList.toggle('off', !$('caep-enabled').checked);
  const auth = $('ssf-auth').value;
  $('ssf-scope-row').hidden = auth !== 'client_credentials';
  $('ssf-token-row').hidden = auth !== 'token';
  $('ssf-auth-hint').textContent = {
    user: 'The stream is created when a user signs in, with that user\'s access token (request the transmitter\'s scopes, e.g. ssf:read ssf:write, in the OIDC scope). The token is refreshed automatically.',
    client_credentials: 'Needs a confidential client (client_secret) allowed to use the client credentials grant.',
    token: 'A bearer token you obtained elsewhere.',
  }[auth];
  $('push-warning').hidden = !($('ssf-delivery').value === 'push' && state.config?.isLocal);
}

async function fetchMetadata() {
  const out = $('fetch-result');
  out.className = 'hint';
  out.textContent = 'Fetching…';
  const res = await api('/api/config/discover', {
    method: 'POST', headers: { 'content-type': 'application/json' }, body: JSON.stringify({ url: $('discovery-url').value }),
  });
  const body = await res.json();
  if (!res.ok) {
    out.textContent = body.error;
    out.classList.add('bad');
    return;
  }
  $('metadata').value = JSON.stringify(body.metadata, null, 2);
  summarizeMetadata();
  const methods = (body.ssf.delivery_methods_supported ?? []).map((d) => (d.endsWith('8935') ? 'push' : d.endsWith('8936') ? 'poll' : d));
  out.textContent = body.ssf.found
    ? `Loaded ${body.discoveryUrl}. SSF transmitter found (delivery: ${methods.join(', ') || 'unspecified'}).`
    : `Loaded ${body.discoveryUrl}. No SSF metadata at this issuer; set the transmitter issuer below, or turn off CAEP.`;
  out.classList.add(body.ssf.found ? 'ok' : 'bad');
  saveForm();
  if (methods.length === 1 && ['push', 'poll'].includes(methods[0])) {
    $('ssf-delivery').value = methods[0];
    updateCaepFieldset();
  }
}

async function saveConfig(e) {
  e.preventDefault();
  const cur = state.config?.current;
  const payload = {
    metadata: $('metadata').value,
    registration: {
      mode: regMode(),
      clientName: $('client-name').value,
      initialAccessToken: $('initial-token').value || undefined,
      softwareStatement: $('software-statement').value.trim() || undefined,
    },
    clientId: $('client-id').value,
    clientSecret: $('client-secret').value || undefined,
    keepSecret: !$('client-secret').value && !!cur?.hasClientSecret && !$('clear-secret').checked,
    tokenEndpointAuthMethod: $('auth-method').value,
    idTokenSignedResponseAlg: $('id-token-alg').value,
    scope: $('scope').value,
    caep: {
      enabled: $('caep-enabled').checked,
      transmitterIssuer: $('ssf-issuer').value,
      delivery: $('ssf-delivery').value,
      managementScope: $('ssf-scope').value,
      managementAuth: $('ssf-auth').value,
      maxSetAgeSec: $('ssf-max-age').value,
      onlySignedInUsers: $('ssf-only-users').checked,
      managementToken: $('ssf-token').value || undefined,
      keepManagementToken: !$('ssf-token').value && !!cur?.caep.hasManagementToken,
      subjectFormat: $('ssf-subject').value,
      events: [...document.querySelectorAll('#ssf-events-pick input:checked')].map((i) => i.value),
    },
  };
  const err = $('config-error');
  err.hidden = true;
  const res = await api('/api/config', { method: 'POST', headers: { 'content-type': 'application/json' }, body: JSON.stringify(payload) });
  const body = await res.json();
  if (!res.ok) {
    err.textContent = body.error;
    err.hidden = false;
    return;
  }
  editing = false;
  formFilled = false;
  await load();
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
for (const r of document.querySelectorAll('input[name="reg-mode"]')) r.addEventListener('change', updateMode);
$('caep-enabled').addEventListener('change', updateCaepFieldset);
$('ssf-delivery').addEventListener('change', updateCaepFieldset);
$('ssf-auth').addEventListener('change', updateCaepFieldset);
$('ssf-issuer').addEventListener('input', () => {
  let issuer = '';
  try { issuer = JSON.parse($('metadata').value).issuer ?? ''; } catch { /* no metadata yet */ }
  updateSsfIssuerHint(issuer);
});
$('btn-edit-config').addEventListener('click', () => { editing = true; formFilled = false; renderConfig(); });
$('btn-cancel').addEventListener('click', () => { editing = false; formFilled = false; renderConfig(); });

// ---------------------------------------------------------------------------
// Tokens (debug view of the signed-in user's own tokens)
// ---------------------------------------------------------------------------

let tokenTab = 'signIn';
let tokenData;

async function loadTokens() {
  if (!state.authenticated) return;
  const res = await api('/api/tokens');
  if (!res.ok) return;
  tokenData = await res.json();
  renderTokens();
}

function renderTokens() {
  if (!tokenData) return;
  const set = tokenData[tokenTab];
  $('tokens-note').textContent = tokenTab === 'signIn'
    ? 'As returned by the token endpoint when you signed in.'
    : `As currently cached${tokenData.refreshCount ? ` (after ${tokenData.refreshCount} refresh${tokenData.refreshCount > 1 ? 'es' : ''})` : ' (no refresh yet)'}.`;
  if (!set) {
    $('tokens-body').replaceChildren(el('p', { class: 'muted small' }, 'Not available.'));
    return;
  }
  const meta = [set.token_type && `token_type ${set.token_type}`, set.scope && `scope "${set.scope}"`,
    set.expires_at && `expires ${new Date(set.expires_at * 1000).toLocaleTimeString()}`].filter(Boolean).join(' · ');
  $('tokens-body').replaceChildren(
    el('p', { class: 'tok-meta' }, meta),
    tokenBlock('OAuth2 access token', set.access_token, tokenData.usedForSsf && tokenTab === 'current' ? 'authorizes the CAEP stream' : ''),
    tokenBlock('OAuth2 refresh token', set.refresh_token),
    tokenBlock('OIDC ID token', set.id_token),
  );
}

function tokenBlock(title, tok, note = '') {
  if (!tok) return el('div', { class: 'tok' }, el('div', { class: 'tok-head' }, el('h3', {}, title)), el('p', { class: 'tok-meta' }, 'Not issued.'));
  const p = tok.payload ?? {};
  const facts = tok.jwt ? [
    p.aud !== undefined && `aud ${JSON.stringify(p.aud)}`,
    (p.scope ?? p.scp) !== undefined && `scope "${[].concat(p.scope ?? p.scp).join(' ')}"`,
    p.exp && `exp ${new Date(p.exp * 1000).toLocaleTimeString()}`,
    tok.header?.alg && `alg ${tok.header.alg}`,
  ].filter(Boolean).join(' · ') : 'Opaque: not a JWT, so there is nothing to decode.';
  const copyBtn = el('button', { class: 'copy', type: 'button', onclick: (e) => copy(tok.raw, e.currentTarget) }, 'Copy');
  return el('div', { class: 'tok' },
    el('div', { class: 'tok-head' },
      el('h3', {}, title, el('span', { class: `pill ${tok.jwt ? 'ok' : ''}` }, tok.jwt ? 'JWT' : 'opaque'), note ? el('span', { class: 'pill warn' }, note) : ''),
      copyBtn),
    el('p', { class: 'tok-meta' }, facts),
    el('pre', { class: 'tok-raw' }, tok.raw),
    ...(tok.jwt ? [
      Object.assign(el('details', {}, el('summary', { class: 'muted small' }, 'Decoded header'), el('pre', {}, JSON.stringify(tok.header, null, 2)))),
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
    loadTokens();
  });
}

// ---------------------------------------------------------------------------
// Data
// ---------------------------------------------------------------------------

async function load() {
  const res = await api('/api/session');
  state = await res.json();
  render();
  loadTokens();
}

function connect() {
  const es = new EventSource('/api/events');
  es.onopen = () => $('live').classList.add('on');
  es.onerror = () => $('live').classList.remove('on');
  es.addEventListener('history', (e) => {
    $('log').replaceChildren();
    for (const entry of JSON.parse(e.data).reverse()) addLogEntry(entry, false);
  });
  es.addEventListener('caep', (e) => {
    addLogEntry(JSON.parse(e.data), true);
    load(); // stream status / claims may have changed
  });
  es.addEventListener('session', (e) => {
    state = { ...state, ...JSON.parse(e.data) };
    render();
    loadTokens();
  });
  es.addEventListener('status', () => load());
  es.addEventListener('notice', (e) => {
    notices.unshift(JSON.parse(e.data));
    notices.length = Math.min(notices.length, 3);
    renderBanners();
  });
}

async function logout() {
  const res = await api('/logout', { method: 'POST' });
  const { redirect } = await res.json();
  location.href = redirect;
}

async function withBusy(button, fn) {
  button.disabled = true;
  try { await fn(); } finally { button.disabled = false; }
}

$('btn-userinfo').addEventListener('click', (e) => withBusy(e.currentTarget, async () => {
  const res = await api('/api/userinfo');
  const out = $('userinfo-out');
  out.hidden = false;
  out.textContent = `GET userinfo → ${res.status}\n${JSON.stringify(await res.json(), null, 2)}`;
}));

$('btn-refresh').addEventListener('click', (e) => withBusy(e.currentTarget, async () => {
  await api('/api/refresh', { method: 'POST' });
}));

$('btn-verify').addEventListener('click', (e) => withBusy(e.currentTarget, async () => {
  const res = await api('/api/ssf/verify', { method: 'POST' });
  if (!res.ok) {
    const body = await res.json();
    $('ssf-error').textContent = `Verification failed: ${body.message ?? body.error}`;
    $('ssf-error').hidden = false;
  }
}));

$('btn-reconnect').addEventListener('click', (e) => withBusy(e.currentTarget, async () => {
  await api('/api/ssf/connect', { method: 'POST' });
  await load();
}));

if (location.search.includes('error=')) setTimeout(() => history.replaceState(null, '', '/'), 8000);
load().then(connect);
