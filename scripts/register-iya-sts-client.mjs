#!/usr/bin/env node
/**
 * Register this demo as a public OIDC client on a running iya-sts.
 *
 * The application is written in the default realm: `<base>/admin-api`, not
 * `/realm/<id>/admin-api`. That is the realm whose issuer is the origin of
 * the configuration file's metadata URL (https://localhost:8081 for the
 * default file).
 *
 * The access token is minted the way iya-sts/tests/tools/admin-api-token.js
 * mints one for the suite. The seeded client is `sts-api-client`, the
 * grant is `client_credentials`, authentication is HTTP Basic, and the token
 * is audienced to `<base>/admin-api` with `admin:read admin:write`.
 * (`sts-management-api` is the management API's own resource object, never a
 * client: iya-sts answers `invalid_client` to a caller presenting it.) The
 * secret is `STS_ADMIN_API_CLIENT_SECRET` or `ADMIN_API_CLIENT_SECRET`, the
 * same variables the test jobs read (tests/protocol/sts_directory_bulk_load_scim.js).
 * On the compose stack that secret lives in OpenBao; docs/management-api.md
 * says how to read it into the environment.
 *
 *   ADMIN_API_CLIENT_SECRET=… node scripts/register-iya-sts-client.mjs
 *   node scripts/register-iya-sts-client.mjs --config demo/public/oidc.json \
 *     --public-url http://localhost:3000
 *
 * Running it again adds the same values to the existing application.
 *
 * The scopes are gated by role in iya-sts. A person is issued ssf.read only
 * while they are in the group ssf-read AND the application is a member of
 * the native role SSF_READ; ssf.manage the same way through ssf-manage and
 * SSF_MANAGE, which does not authorize ssf.read. So the script also:
 *
 *   - adds the application to SSF_READ and SSF_MANAGE as an application
 *     member (roles/add-member, kind application), for whichever of
 *     ssf.read and ssf.manage the configuration file's scopes name;
 *   - creates a test user (default caep-demo-user) when it is absent, and
 *     adds it to the groups ssf-read and ssf-manage. Its password is
 *     CAEP_DEMO_USER_PASSWORD, or one is generated and printed once. An
 *     existing user keeps its password.
 */

import { readFileSync } from 'node:fs';
import https from 'node:https';
import { dirname, resolve } from 'node:path';
import { fileURLToPath } from 'node:url';

const here = dirname(fileURLToPath(import.meta.url));
const repoRoot = resolve(here, '..');

const SSF_ROLES = [
  { scope: 'ssf.read', role: 'SSF_READ', group: 'ssf-read' },
  { scope: 'ssf.manage', role: 'SSF_MANAGE', group: 'ssf-manage' },
];

function usage() {
  return `Usage: node scripts/register-iya-sts-client.mjs [--config path] [--public-url url]
                                                [--test-user name | --no-test-user]

  --config       OIDC file with metadataUrl, client_id, and scopes
                 (default: demo/public/oidc.json)
  --public-url   Where the demo is served. The redirect URI is
                 <public-url>/callback (default: $PUBLIC_URL or http://localhost:3000)
  --test-user    The test user to create and add to ssf-read and ssf-manage
                 (default: caep-demo-user). Its password is $CAEP_DEMO_USER_PASSWORD,
                 or one is generated and printed once.
  --no-test-user Do not create or change a test user.

The management API secret is STS_ADMIN_API_CLIENT_SECRET or ADMIN_API_CLIENT_SECRET.`;
}

function parseArgs(argv) {
  const out = {
    config: resolve(repoRoot, 'demo/public/oidc.json'),
    publicUrl: (process.env.PUBLIC_URL || 'http://localhost:3000').replace(/\/+$/, ''),
    testUser: 'caep-demo-user',
  };
  for (let i = 0; i < argv.length; i += 1) {
    const arg = argv[i];
    if (arg === '--help' || arg === '-h') {
      console.log(usage());
      process.exit(0);
    }
    if (arg === '--config') out.config = resolve(argv[++i] ?? '');
    else if (arg === '--public-url') out.publicUrl = String(argv[++i] ?? '').replace(/\/+$/, '');
    else if (arg === '--test-user') out.testUser = String(argv[++i] ?? '').trim();
    else if (arg === '--no-test-user') out.testUser = '';
    else throw new Error(`Unknown argument ${arg}\n${usage()}`);
  }
  if (!out.publicUrl) throw new Error('--public-url is empty');
  return out;
}

function readOidcFile(path) {
  let doc;
  try {
    doc = JSON.parse(readFileSync(path, 'utf8'));
  } catch (err) {
    throw new Error(`Could not read ${path}: ${err.message}`);
  }
  const metadataUrl = String(doc.metadataUrl ?? '').trim();
  const clientId = String(doc.client_id ?? doc.clientId ?? '').trim();
  const scopes = Array.isArray(doc.scopes)
    ? doc.scopes.map((s) => String(s).trim()).filter(Boolean)
    : String(doc.scopes ?? '').trim().split(/\s+/).filter(Boolean);
  if (!metadataUrl || !clientId || !scopes.length) {
    throw new Error(`${path} must contain metadataUrl, client_id, and scopes`);
  }
  const metadata = new URL(metadataUrl);
  if (!metadata.pathname.includes('/.well-known/')) {
    throw new Error(`metadataUrl must be the openid-configuration URL, not ${metadataUrl}`);
  }
  return { metadataUrl: metadata.href, clientId, scopes, base: metadata.origin };
}

function request(url, { method = 'GET', headers = {}, body } = {}) {
  return new Promise((resolvePromise, reject) => {
    const u = new URL(url);
    const payload = body === undefined ? null : Buffer.from(body);
    const req = https.request({
      hostname: u.hostname,
      port: u.port,
      path: `${u.pathname}${u.search}`,
      method,
      headers: payload ? { ...headers, 'content-length': payload.length } : headers,
      // The listener certificate is this stack's own. The test tool does the
      // same: tests/tools/admin-api-token.js sets rejectUnauthorized: false.
      rejectUnauthorized: false,
    }, (res) => {
      let text = '';
      res.on('data', (chunk) => { text += chunk; });
      res.on('end', () => resolvePromise({ status: res.statusCode, text }));
    });
    req.on('error', reject);
    if (payload) req.write(payload);
    req.end();
  });
}

async function jsonRequest(url, options) {
  const reply = await request(url, options);
  let body;
  try {
    body = reply.text ? JSON.parse(reply.text) : {};
  } catch {
    throw new Error(`${options.method ?? 'GET'} ${url} answered ${reply.status} with non-JSON: ${reply.text.slice(0, 300)}`);
  }
  return { status: reply.status, body };
}

async function mintAdminToken(base, secret) {
  const audience = `${base}/admin-api`;
  const form = `grant_type=client_credentials&scope=${encodeURIComponent('admin:read admin:write')}&resource=${encodeURIComponent(audience)}`;
  const reply = await request(`${base}/oauth2/token`, {
    method: 'POST',
    headers: {
      'content-type': 'application/x-www-form-urlencoded',
      authorization: `Basic ${Buffer.from(`sts-api-client:${secret}`).toString('base64')}`,
    },
    body: form,
  });
  if (reply.status !== 200) {
    throw new Error(`the token endpoint answered ${reply.status} ${reply.text.slice(0, 300)}`);
  }
  const body = JSON.parse(reply.text);
  if (!body.access_token) throw new Error('the token endpoint answered 200 with no access_token');
  return body.access_token;
}

function secretFromEnv() {
  return process.env.STS_ADMIN_API_CLIENT_SECRET || process.env.ADMIN_API_CLIENT_SECRET || '';
}

async function admin(base, token, method, path, body) {
  const reply = await jsonRequest(`${base}/admin-api${path}`, {
    method,
    headers: {
      accept: 'application/json',
      authorization: `Bearer ${token}`,
      ...(body === undefined ? {} : { 'content-type': 'application/json' }),
    },
    body: body === undefined ? undefined : JSON.stringify(body),
  });
  if (reply.status === 401 || reply.status === 403) {
    throw new Error(`${method} ${path} answered ${reply.status}: ${JSON.stringify(reply.body).slice(0, 300)}`);
  }
  return reply;
}

function valuesOf(value) {
  return Array.isArray(value) ? value.map(String) : [String(value)];
}

async function ensure(base, token, spec) {
  const created = await admin(base, token, 'POST', '/applications/create', spec);
  const errors = [].concat(created.body.errors ?? []);
  const already = errors.some((one) => /already in this registry/i.test(String(one)));
  if (created.body.ok) {
    console.log(`Created ${spec.identifier} in the default realm at ${base}.`);
    return;
  }
  if (!already) {
    throw new Error(`POST /admin-api/applications/create refused ${spec.identifier}: ${JSON.stringify(created.body).slice(0, 500)}`);
  }
  console.log(`${spec.identifier} is already in the default realm; adding the demo's values.`);
  for (const protocol of spec.protocols) {
    const added = await admin(base, token, 'POST', '/applications/add', {
      application: spec.identifier,
      attribute: 'appAllowedProtocol',
      value: protocol,
    });
    const already = [].concat(added.body.errors ?? []).some((one) => /already/i.test(String(one)));
    if (!added.body.ok && !already) throw new Error(`declaring ${protocol} was refused: ${JSON.stringify(added.body).slice(0, 300)}`);
  }
  for (const [attribute, raw] of Object.entries(spec.fields)) {
    for (const value of valuesOf(raw)) {
      const added = await admin(base, token, 'POST', '/applications/add', {
        application: spec.identifier,
        attribute,
        value,
      });
      const already = [].concat(added.body.errors ?? []).some((one) => /already/i.test(String(one)));
      if (!added.body.ok && !already) throw new Error(`adding ${attribute}=${value} was refused: ${JSON.stringify(added.body).slice(0, 300)}`);
    }
  }
}

// Makes the application a member of each SSF role whose scope the file asks for. The answer for
// an application that already holds the role is a 400 saying so, which is the state wanted.
async function grantSsfRoles(base, token, clientId, scopes) {
  for (const { scope, role } of SSF_ROLES.filter((r) => scopes.includes(r.scope))) {
    const added = await admin(base, token, 'POST', '/roles/add-member', { role, kind: 'application', member: clientId });
    const already = [].concat(added.body.errors ?? []).some((one) => /already holds/i.test(String(one)));
    if (!added.body.ok && !already) {
      throw new Error(`adding ${clientId} to ${role} was refused: ${JSON.stringify(added.body).slice(0, 300)}`);
    }
    console.log(`${clientId} ${already ? 'already holds' : 'now holds'} ${role}, so it may be issued ${scope}.`);
  }
}

// Creates the test user when absent (an existing one keeps its password) and puts it in each SSF
// group whose scope the file asks for. A group that already lists it answers ok, changed: false.
async function ensureTestUser(base, token, username, scopes) {
  const found = await admin(base, token, 'GET', `/users?user=${encodeURIComponent(username)}`);
  if (found.body.known === true) {
    console.log(`User ${username} already exists; its password is unchanged.`);
  } else {
    const password = process.env.CAEP_DEMO_USER_PASSWORD || '';
    // What a product-mode realm's attribute policy requires of every person (uid is the username).
    const attributes = { cn: `CAEP Demo ${username}`, givenName: 'CAEP', sn: 'Demo', displayName: `CAEP Demo ${username}`, mail: `${username}@caep-demo.test` };
    const body = password
      ? { username, invent: false, credential: 'password', password, passwordConfirm: password, attributes }
      : { username, invent: false, credential: 'generate', attributes };
    const created = await admin(base, token, 'POST', '/users/create', body);
    if (!created.body.ok) throw new Error(`creating ${username} was refused: ${JSON.stringify(created.body).slice(0, 300)}`);
    console.log(`Created user ${username}.`);
    if (created.body.password) console.log(`Generated password for ${username} (shown once): ${created.body.password}`);
    if (created.body.credentialError) console.warn(`WARNING: the password was not set: ${created.body.credentialError}`);
  }
  for (const { group } of SSF_ROLES.filter((r) => scopes.includes(r.scope))) {
    const added = await admin(base, token, 'POST', '/groups/add-member', { group, member: username });
    if (!added.body.ok) throw new Error(`adding ${username} to ${group} was refused: ${JSON.stringify(added.body).slice(0, 300)}`);
    console.log(`${username} ${added.body.changed === false ? 'was already' : 'is now'} in ${group}.`);
  }
}

async function main() {
  const args = parseArgs(process.argv.slice(2));
  const oidc = readOidcFile(args.config);
  const secret = secretFromEnv();
  if (!secret) {
    throw new Error('neither STS_ADMIN_API_CLIENT_SECRET nor ADMIN_API_CLIENT_SECRET is set, so no /admin-api token can be minted. The iya-sts test jobs read the same variables.');
  }
  const publicUrl = new URL(args.publicUrl);
  const redirectUri = new URL('/callback', `${publicUrl.href.replace(/\/+$/, '')}/`).href;
  const postLogout = new URL('/', `${publicUrl.href.replace(/\/+$/, '')}/`).href;
  const token = await mintAdminToken(oidc.base, secret);
  await ensure(oidc.base, token, {
    identifier: oidc.clientId,
    name: 'oidc-caep-client demo',
    protocols: ['oauth2', 'oidc'],
    fields: {
      oauthClientId: oidc.clientId,
      oauthRedirectUri: [redirectUri],
      oauthPostLogoutRedirectUri: [postLogout],
      oauthResponseType: ['code'],
      oauthGrantType: ['authorization_code', 'refresh_token'],
      oauthAllowedScope: oidc.scopes,
      oauthTokenEndpointAuthMethod: 'none',
      appCorsOrigin: [publicUrl.origin],
    },
  });
  await grantSsfRoles(oidc.base, token, oidc.clientId, oidc.scopes);
  if (args.testUser) await ensureTestUser(oidc.base, token, args.testUser, oidc.scopes);
  const view = await admin(oidc.base, token, 'GET', `/applications?application=${encodeURIComponent(oidc.clientId)}`);
  const entry = view.body.application ?? view.body;
  const fields = entry.fields ?? entry;
  const show = (name) => [].concat(fields[name] ?? []).join(' ') || '(none)';
  console.log(`client_id: ${oidc.clientId}`);
  console.log(`metadata:  ${oidc.metadataUrl}`);
  console.log(`redirect:  ${show('oauthRedirectUri')}`);
  console.log(`logout:    ${show('oauthPostLogoutRedirectUri')}`);
  console.log(`scopes:    ${show('oauthAllowedScope')}`);
  console.log(`auth:      ${show('oauthTokenEndpointAuthMethod')}`);
  console.log(`cors:      ${show('appCorsOrigin')}`);
}

main().catch((err) => {
  console.error(err.message);
  process.exit(1);
});
