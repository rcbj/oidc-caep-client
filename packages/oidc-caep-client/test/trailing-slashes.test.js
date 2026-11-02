// Trailing slashes are trimmed in linear time (CodeQL js/polynomial-redos). `replace(/\/+$/, '')`
// retries at every slash of a run that is not at the end of the string, so an issuer with a long run
// of slashes followed by any other character took seconds; the loop takes microseconds.

import assert from 'node:assert/strict';
import { describe, it } from 'node:test';
import { oidcDiscoveryUrl } from '../src/index.js';
import { wellKnownUrls } from '../src/discovery.js';

const RUN = '/'.repeat(100_000);
const BUDGET_MS = 500;

function timed(what, fn) {
  const started = performance.now();
  const result = fn();
  const took = performance.now() - started;
  assert.ok(took < BUDGET_MS, `${what} took ${Math.round(took)} ms`);
  return result;
}

describe('trailing slashes', () => {
  it('are trimmed from the issuer and nothing else', () => {
    assert.equal(oidcDiscoveryUrl('https://op/'), 'https://op/.well-known/openid-configuration');
    assert.equal(oidcDiscoveryUrl('https://op/realm///'), 'https://op/realm/.well-known/openid-configuration');
    assert.equal(oidcDiscoveryUrl('https://op//a'), 'https://op//a/.well-known/openid-configuration');
    assert.deepEqual(wellKnownUrls('https://op/realm/a/', 'ssf-configuration'), [
      'https://op/.well-known/ssf-configuration/realm/a',
      'https://op/realm/a/.well-known/ssf-configuration',
    ]);
    assert.deepEqual(wellKnownUrls('https://op/', 'ssf-configuration'), ['https://op/.well-known/ssf-configuration']);
  });

  it('builds the discovery URL from a long run of slashes that is not at the end in linear time', () => {
    const issuer = `https://op${RUN}x`;
    assert.equal(timed('oidcDiscoveryUrl', () => oidcDiscoveryUrl(issuer)), `${issuer}/.well-known/openid-configuration`);
    assert.equal(timed('a run at the end', () => oidcDiscoveryUrl(`https://op${RUN}`)), 'https://op/.well-known/openid-configuration');
  });

  it('builds the well-known URLs from such an issuer path in linear time', () => {
    const urls = timed('wellKnownUrls', () => wellKnownUrls(`https://op${RUN}x`, 'ssf-configuration'));
    assert.equal(urls[0], `https://op/.well-known/ssf-configuration${RUN}x`);
  });
});
