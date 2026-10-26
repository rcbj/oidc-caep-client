#!/usr/bin/env node
// SPDX-FileCopyrightText: 2026 Iya CyberSecurity Solutions, LLC
// SPDX-License-Identifier: MIT
/**
 * The package version, in the usual npm form.
 *
 *   M.N    major.minor, declared in the repo-root VERSION file. Bump it there;
 *          it is the single source of truth.
 *   P      the patch number, worked out at build time from what is already on
 *          npm: one more than the highest published M.N.x release, or 0 when
 *          there is none. Nothing to edit per build, and no gaps.
 *
 * Two channels:
 *
 *   latest   a release, M.N.P (0.2.0, 0.2.1, ...). Built from main.
 *   next     a pre-release of the release that comes next, M.N.P-next.R, where
 *            R is one more than the highest published pre-release of M.N.P,
 *            from 0. Built from develop. npm never resolves a range like
 *            `^0.2.0` to a pre-release, so only `@next` installs one.
 *
 * The npm registry is the counter: CI reads the published versions with
 * `npm view` (or NPM_PUBLISHED_VERSIONS, a JSON array, for tests and offline
 * builds). Publishes of one branch run one at a time (npm-publish.yml's
 * concurrency group), and a release and a pre-release never share a version.
 *
 * The committed package.json files carry M.N.0. The real version is written
 * into the package's package.json at build time (`--set`), in the CI workspace
 * only, so a publish never needs a version commit. After bumping VERSION, run
 * `--sync-manifests` to keep the committed files in step with it.
 *
 *   node scripts/version.mjs                              -> 0.2.3 (the next release)
 *   node scripts/version.mjs --channel next               -> 0.2.3-next.4
 *   node scripts/version.mjs --json [--channel c]         -> the full record
 *   node scripts/version.mjs --set <dir> [--channel c]    -> writes it into <dir>/package.json, prints it
 *   node scripts/version.mjs --check-manifests            -> non-zero if a package.json is not M.N.0
 *   node scripts/version.mjs --sync-manifests             -> rewrites stale package.json versions to M.N.0
 */

import { execFileSync } from 'node:child_process';
import { readFileSync, writeFileSync } from 'node:fs';
import { dirname, join, resolve as resolvePath } from 'node:path';
import { fileURLToPath } from 'node:url';

const ROOT = resolvePath(dirname(fileURLToPath(import.meta.url)), '..');
const VERSION_FILE = 'VERSION';
const PACKAGE_DIR = 'packages/oidc-caep-client';
// The package.json files whose version follows VERSION. The root manifest is a
// private workspace with no version of its own.
const MANIFESTS = [`${PACKAGE_DIR}/package.json`, 'demo/package.json'];
const CHANNELS = ['latest', 'next'];
const PRERELEASE_ID = 'next';

/** M.N from the VERSION file. A malformed or missing file is said out loud, then read as 0.0. */
export function readMajorMinor() {
  const file = join(ROOT, VERSION_FILE);
  let raw = '';
  try {
    raw = readFileSync(file, 'utf8').trim();
  } catch {
    console.error(`[version] no readable ${file}; falling back to 0.0`);
    return { major: '0', minor: '0' };
  }
  const m = /^(\d+)\.(\d+)$/.exec(raw);
  if (m) return { major: m[1], minor: m[2] };
  console.error(`[version] ignoring malformed ${file}: "${raw}" (want M.N)`);
  return { major: '0', minor: '0' };
}

/**
 * The version to publish, given the versions already published.
 * @param {string[]} published  every version of the package on npm
 * @param {{ major: string|number, minor: string|number, channel?: 'latest'|'next' }} opts
 * @returns {{ version: string, patch: number, prerelease: number|undefined }}
 */
export function nextVersion(published, { major, minor, channel = 'latest' }) {
  if (!CHANNELS.includes(channel)) throw new Error(`channel must be ${CHANNELS.join(' or ')}, not "${channel}"`);
  const base = `${major}.${minor}`;
  const escaped = base.replace('.', '\\.');
  const release = new RegExp(`^${escaped}\\.(0|[1-9]\\d*)$`);
  const highest = (re) => published.reduce((max, v) => {
    const m = re.exec(v);
    return m ? Math.max(max, Number(m[1])) : max;
  }, -1);
  const patch = highest(release) + 1;
  if (channel === 'latest') return { version: `${base}.${patch}`, patch, prerelease: undefined };
  const pre = new RegExp(`^${escaped}\\.${patch}-${PRERELEASE_ID}\\.(0|[1-9]\\d*)$`);
  const prerelease = highest(pre) + 1;
  return { version: `${base}.${patch}-${PRERELEASE_ID}.${prerelease}`, patch, prerelease };
}

/** The package's published versions: NPM_PUBLISHED_VERSIONS, else `npm view`. A package not on npm has none. */
export function publishedVersions(name = packageName()) {
  if (process.env.NPM_PUBLISHED_VERSIONS !== undefined) {
    const list = JSON.parse(process.env.NPM_PUBLISHED_VERSIONS);
    if (!Array.isArray(list)) throw new Error('NPM_PUBLISHED_VERSIONS must be a JSON array of versions');
    return list.map(String);
  }
  let out;
  try {
    out = execFileSync('npm', ['view', name, 'versions', '--json', '--prefer-online'],
      { cwd: ROOT, stdio: ['ignore', 'pipe', 'pipe'], encoding: 'utf8' });
  } catch (err) {
    // E404: never published, so everything starts at 0. Anything else (no network, an npm error)
    // must stop the build: guessing could publish a version that already exists or goes backwards.
    if (/E404|404 Not Found/.test(`${err.stdout ?? ''}${err.stderr ?? ''}`)) return [];
    throw new Error(`could not read the published versions of ${name}: ${(err.stderr || err.message).trim().split('\n')[0]}`);
  }
  const parsed = JSON.parse(out || '[]');
  return Array.isArray(parsed) ? parsed : [parsed];
}

function packageName() {
  return JSON.parse(readFileSync(join(ROOT, PACKAGE_DIR, 'package.json'), 'utf8')).name;
}

/** Best-effort commit id; provenance only, so no git is an empty string. */
function gitCommit() {
  if (process.env.GIT_COMMIT) return String(process.env.GIT_COMMIT).trim().slice(0, 12);
  try {
    return execFileSync('git', ['rev-parse', '--short=12', 'HEAD'], { cwd: ROOT, stdio: ['ignore', 'pipe', 'ignore'] })
      .toString().trim();
  } catch {
    return '';
  }
}

/** The version record for a build of `channel` now. */
export function resolve(channel = 'latest') {
  const { major, minor } = readMajorMinor();
  const next = nextVersion(publishedVersions(), { major, minor, channel });
  return { ...next, channel, major, minor, commit: gitCommit(), builtAt: new Date().toISOString().replace(/\.\d{3}Z$/, 'Z') };
}

/** The version every committed package.json carries: M.N with a patch of 0. */
export function manifestVersion() {
  const { major, minor } = readMajorMinor();
  return `${major}.${minor}.0`;
}

/** One `{ path, actual, expected, ok }` per manifest. */
export function checkManifests() {
  const want = manifestVersion();
  return MANIFESTS.map((rel) => {
    const actual = JSON.parse(readFileSync(join(ROOT, rel), 'utf8')).version;
    return { path: rel, actual, expected: want, ok: actual === want };
  });
}

// Rewrites only the "version" value, so the rest of the file keeps its formatting.
function writeVersion(file, version) {
  const text = readFileSync(file, 'utf8');
  if (!/"version":\s*"[^"]*"/.test(text)) throw new Error(`${file} has no "version" to set`);
  writeFileSync(file, text.replace(/("version":\s*)"[^"]*"/, `$1"${version}"`));
}

/** Rewrites each stale manifest to M.N.0, and the lock file's entry for it. Returns `path: old -> new` lines. */
export function syncManifests() {
  const want = manifestVersion();
  const changed = [];
  for (const entry of checkManifests().filter((e) => !e.ok)) {
    writeVersion(join(ROOT, entry.path), want);
    changed.push(`${entry.path}: ${entry.actual} -> ${want}`);
  }
  if (changed.length) {
    const lockFile = join(ROOT, 'package-lock.json');
    try {
      const lock = JSON.parse(readFileSync(lockFile, 'utf8'));
      for (const rel of MANIFESTS) {
        const entry = lock.packages?.[dirname(rel)];
        if (entry) entry.version = want;
      }
      writeFileSync(lockFile, `${JSON.stringify(lock, null, 2)}\n`);
    } catch {
      // No lock or unreadable: npm rewrites these entries on the next install.
    }
  }
  return changed;
}

/** Writes this build's version into `<dir>/package.json`. For the publish workspace, never for a commit. */
export function setPackageVersion(dir, channel = 'latest') {
  const record = resolve(channel);
  writeVersion(join(resolvePath(dir), 'package.json'), record.version);
  return record;
}

function main(args) {
  const at = (flag) => {
    const i = args.indexOf(flag);
    if (i < 0) return undefined;
    if (!args[i + 1] || args[i + 1].startsWith('--')) throw new Error(`${flag} needs a value`);
    return args[i + 1];
  };
  const channel = at('--channel') ?? 'latest';
  const dir = at('--set');
  if (dir) {
    console.log(setPackageVersion(dir, channel).version);
  } else if (args.includes('--check-manifests')) {
    const stale = checkManifests().filter((e) => !e.ok);
    for (const e of stale) console.error(`[version] ${e.path} is ${e.actual}, VERSION says ${e.expected}`);
    if (stale.length) {
      console.error('[version] run: node scripts/version.mjs --sync-manifests');
      process.exit(1);
    }
    console.log(`[version] every manifest is ${manifestVersion()}`);
  } else if (args.includes('--sync-manifests')) {
    const changed = syncManifests();
    console.log(changed.length ? changed.join('\n') : `[version] every manifest is already ${manifestVersion()}`);
  } else if (args.includes('--json')) {
    console.log(JSON.stringify(resolve(channel), null, 2));
  } else {
    console.log(resolve(channel).version);
  }
}

if (process.argv[1] && resolvePath(process.argv[1]) === fileURLToPath(import.meta.url)) {
  try {
    main(process.argv.slice(2));
  } catch (err) {
    console.error(`[version] ${err.message}`);
    process.exit(1);
  }
}
