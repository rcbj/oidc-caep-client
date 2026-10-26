// Tests for scripts/version.mjs: the version a build gets, from what is already published.
import assert from 'node:assert/strict';
import { execFileSync } from 'node:child_process';
import { describe, it } from 'node:test';
import { fileURLToPath } from 'node:url';
import { nextVersion } from './version.mjs';

const SCRIPT = fileURLToPath(new URL('./version.mjs', import.meta.url));
const run = (args, published) => execFileSync(process.execPath, [SCRIPT, ...args],
  { env: { ...process.env, NPM_PUBLISHED_VERSIONS: JSON.stringify(published) }, encoding: 'utf8' }).trim();

describe('version numbering', () => {
  const at = (published, channel) => nextVersion(published, { major: 0, minor: 2, channel }).version;

  it('starts a release line at .0 and counts up with no gaps', () => {
    assert.equal(at([], 'latest'), '0.2.0');
    assert.equal(at(['0.2.0'], 'latest'), '0.2.1');
    assert.equal(at(['0.2.0', '0.2.1', '0.2.2'], 'latest'), '0.2.3');
    assert.equal(at(['0.2.1', '0.2.0'], 'latest'), '0.2.2', 'order of the list does not matter');
  });

  it('ignores other release lines, pre-releases and the old timestamp builds', () => {
    const published = ['0.0.0-stage', '0.1.20261026182707', '0.1.20261026193717', '0.3.0', '1.2.0', '0.2.0-next.0', '0.20.4'];
    assert.equal(at(published, 'latest'), '0.2.0');
  });

  it('numbers pre-releases of the release that comes next, from 0', () => {
    assert.equal(at([], 'next'), '0.2.0-next.0');
    assert.equal(at(['0.2.0-next.0', '0.2.0-next.1'], 'next'), '0.2.0-next.2');
    assert.equal(at(['0.2.0-next.0', '0.2.0-next.1', '0.2.0'], 'next'), '0.2.1-next.0', 'a release moves pre-releases on to the next patch');
    assert.equal(at(['0.2.0', '0.2.1-next.9', '0.2.1-next.10'], 'next'), '0.2.1-next.11', 'numeric, not lexical');
  });

  it('refuses an unknown channel', () => {
    assert.throws(() => at([], 'beta'), /channel/);
  });

  it('the command line reads VERSION and the published list', () => {
    assert.equal(run([], ['0.2.0', '0.2.1']), '0.2.2');
    assert.equal(run(['--channel', 'next'], ['0.2.0']), '0.2.1-next.0');
    const record = JSON.parse(run(['--json', '--channel', 'next'], ['0.2.1-next.0']));
    assert.equal(record.version, '0.2.0-next.0');
    assert.equal(record.channel, 'next');
  });
});
