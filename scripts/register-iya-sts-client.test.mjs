// The origin this script registers: the port the demo listens on, unless one was given.
import assert from 'node:assert/strict';
import { execFileSync } from 'node:child_process';
import { X509Certificate } from 'node:crypto';
import { chmodSync, mkdtempSync, readFileSync, statSync, writeFileSync } from 'node:fs';
import https from 'node:https';
import { tmpdir } from 'node:os';
import { join, resolve } from 'node:path';
import { after, before, describe, it } from 'node:test';
import {
  demoPort, demoUrls, parseArgs, passwordFileFor, rootOnFirstUse, trustAnchor, writePasswordFile,
} from './register-iya-sts-client.mjs';

describe('register-iya-sts-client', () => {
  const noContainer = () => undefined;

  it('registers http://localhost:3001/callback when PORT=3001 and no public URL is set', () => {
    const env = { PUBLIC_URL: '', PORT: '3001' };
    const args = parseArgs([], env);
    assert.equal(args.publicUrlGiven, false);
    const urls = demoUrls(args, env, noContainer);
    assert.equal(urls.redirectUri, 'http://localhost:3001/callback');
    assert.equal(urls.postLogout, 'http://localhost:3001/');
    assert.equal(urls.origin, 'http://localhost:3001');
    const neither = demoUrls(parseArgs([], {}), {}, noContainer);
    assert.equal(neither.redirectUri, 'http://localhost:3000/callback');
  });

  it('an explicit --public-url replaces the origin', () => {
    const env = { PUBLIC_URL: 'http://from-env.test', PORT: '3001' };
    const args = parseArgs(['--public-url', 'https://app.example:8443/'], env);
    assert.equal(args.publicUrlGiven, true);
    assert.equal(args.publicUrl, 'https://app.example:8443');
    const urls = demoUrls(args, env, () => '3002');
    assert.equal(urls.redirectUri, 'https://app.example:8443/callback');
    assert.equal(urls.postLogout, 'https://app.example:8443/');
    assert.equal(urls.origin, 'https://app.example:8443');
  });

  it('keeps a non-empty PUBLIC_URL', () => {
    const env = { PUBLIC_URL: 'http://demo.test:9/', PORT: '3001' };
    const args = parseArgs([], env);
    assert.equal(args.publicUrlGiven, true);
    const urls = demoUrls(args, env, () => '3002');
    assert.equal(urls.redirectUri, 'http://demo.test:9/callback');
    assert.equal(urls.postLogout, 'http://demo.test:9/');
    assert.equal(urls.origin, 'http://demo.test:9');
  });

  it('demoPort prefers the container port over the environment', () => {
    assert.equal(demoPort('3000', '3001'), 3001);
    assert.equal(demoPort('3001', ''), 3001);
    assert.equal(demoPort('', undefined), undefined);
    assert.equal(demoPort('nope', undefined), undefined);
    const env = { PORT: '3000' };
    const urls = demoUrls(parseArgs([], env), env, () => '3001');
    assert.equal(urls.redirectUri, 'http://localhost:3001/callback');
    assert.equal(urls.postLogout, 'http://localhost:3001/');
  });
});

describe('register-iya-sts-client: TLS and the generated password', () => {
  const work = mkdtempSync(join(tmpdir(), 'register-tls-'));
  const openssl = (...args) => execFileSync('openssl', args, { stdio: 'ignore' });
  const ext = join(work, 'ext.cnf');
  writeFileSync(ext, [
    '[ca]', 'basicConstraints = critical, CA:TRUE', 'keyUsage = critical, keyCertSign, cRLSign',
    '[leaf]', 'basicConstraints = critical, CA:FALSE', 'extendedKeyUsage = serverAuth',
    'subjectAltName = IP:127.0.0.1, DNS:localhost', '',
  ].join('\n'));
  const root = (name) => openssl('req', '-x509', '-newkey', 'rsa:2048', '-nodes', '-days', '1',
    '-subj', `/CN=${name}`, '-keyout', join(work, `${name}.key`), '-out', join(work, `${name}.pem`),
    '-addext', 'basicConstraints=critical,CA:TRUE', '-addext', 'keyUsage=critical,keyCertSign,cRLSign');
  root('sts-root');
  root('other-root');
  openssl('req', '-new', '-newkey', 'rsa:2048', '-nodes', '-subj', '/CN=localhost',
    '-keyout', join(work, 'leaf.key'), '-out', join(work, 'leaf.csr'));
  openssl('x509', '-req', '-in', join(work, 'leaf.csr'), '-days', '1', '-set_serial', '7',
    '-CA', join(work, 'sts-root.pem'), '-CAkey', join(work, 'sts-root.key'),
    '-extfile', ext, '-extensions', 'leaf', '-out', join(work, 'leaf.pem'));
  const pem = (name) => readFileSync(join(work, `${name}.pem`), 'utf8');
  const cert = (name) => new X509Certificate(pem(name));
  let server;
  let origin = '';

  before(async () => {
    server = https.createServer({ key: readFileSync(join(work, 'leaf.key')), cert: `${pem('leaf')}${pem('sts-root')}` },
      (req, res) => {
        res.statusCode = req.url === '/tls/server-certificate' ? 200 : 404;
        res.end(req.url === '/tls/server-certificate' ? `${pem('leaf')}${pem('sts-root')}` : '');
      });
    await new Promise((done) => server.listen(0, '127.0.0.1', done));
    origin = `https://127.0.0.1:${server.address().port}`;
  });

  after(async () => {
    await new Promise((done) => server.close(done));
  });

  it('without --ca, takes the presented root on first use', async () => {
    const anchor = await trustAnchor(origin, '');
    assert.equal(anchor.firstUse, true);
    assert.equal(anchor.root.fingerprint256, cert('sts-root').fingerprint256);
    assert.equal(new X509Certificate(anchor.pem).fingerprint256, cert('sts-root').fingerprint256);
  });

  it('without --ca, a server that does not publish its chain is refused', async () => {
    const bare = https.createServer({ key: readFileSync(join(work, 'leaf.key')), cert: pem('leaf') },
      (_req, res) => { res.statusCode = 404; res.end(); });
    await new Promise((done) => bare.listen(0, '127.0.0.1', done));
    try {
      await assert.rejects(trustAnchor(`https://127.0.0.1:${bare.address().port}`, ''), /answered 404/);
    } finally {
      await new Promise((done) => bare.close(done));
    }
  });

  it('with --ca, uses that file and fetches nothing', async () => {
    const anchor = await trustAnchor('https://127.0.0.1:1', join(work, 'sts-root.pem'));
    assert.equal(anchor.firstUse, false);
    assert.equal(anchor.pem, pem('sts-root'));
    await assert.rejects(trustAnchor(origin, join(work, 'ext.cnf')), /no PEM certificate/);
    assert.equal(parseArgs(['--ca', 'x.pem'], {}).ca, resolve('x.pem'));
    assert.equal(parseArgs([], { IYA_STS_CA: 'y.pem' }).ca, resolve('y.pem'));
  });

  it('first use checks the host name and every link, and needs a self-signed root', () => {
    const leaf = cert('leaf');
    assert.equal(rootOnFirstUse('127.0.0.1', [leaf, cert('sts-root')]).fingerprint256, cert('sts-root').fingerprint256);
    assert.throws(() => rootOnFirstUse('elsewhere.example', [leaf, cert('sts-root')]), /altnames|Hostname/);
    assert.throws(() => rootOnFirstUse('127.0.0.1', [leaf, cert('other-root')]), /not signed/);
    assert.throws(() => rootOnFirstUse('127.0.0.1', [leaf]), /self-signed root/);
    assert.throws(() => rootOnFirstUse('127.0.0.1', []), /no certificate/);
  });

  it('writes a generated password to <user>.password, mode 0600, named from the username only', () => {
    const dir = join(work, 'generated');
    const file = writePasswordFile('caep-demo-user', 'p4ss', dir);
    assert.equal(file, join(dir, 'caep-demo-user.password'));
    assert.equal(readFileSync(file, 'utf8'), 'p4ss\n');
    assert.equal(statSync(file).mode & 0o777, 0o600);
    chmodSync(file, 0o644);
    writePasswordFile('caep-demo-user', 'again', dir);
    assert.equal(statSync(file).mode & 0o777, 0o600);
    assert.equal(readFileSync(file, 'utf8'), 'again\n');
    assert.throws(() => passwordFileFor('../escape', dir), /not a username/);
    assert.throws(() => passwordFileFor('.hidden', dir), /not a username/);
    assert.throws(() => passwordFileFor('a/b', dir), /not a username/);
  });
});
