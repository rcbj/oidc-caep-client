// The origin this script registers: the port the demo listens on, unless one was given.
import assert from 'node:assert/strict';
import { describe, it } from 'node:test';
import { demoPort, demoUrls, parseArgs } from './register-iya-sts-client.mjs';

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
