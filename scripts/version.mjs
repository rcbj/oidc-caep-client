#!/usr/bin/env node
// SPDX-FileCopyrightText: 2026 Iya CyberSecurity Solutions, LLC
// SPDX-License-Identifier: MIT
/**
 * The package version, M.N.O: the scheme iya-sts uses (its common/version.js),
 * ported to this repository.
 *
 *   M.N  major.minor, declared in the repo-root VERSION file. Bump it there;
 *        it is the single source of truth.
 *   O    the build number, which identifies THIS build and no other. By
 *        default it is the UTC build instant as YYYYMMDDHHMMSS: unique per
 *        build, always increasing, and it says when the package was built.
 *        BUILD_NUMBER overrides it; keeping that unique and increasing is then
 *        the caller's job.
 *
 * The committed package.json files carry M.N.0, a valid semver whose patch is
 * a placeholder. The real number is written into the published package's
 * package.json at build time (`--set`), in the CI workspace only, so a
 * publish never needs a version commit. Bumping VERSION and running
 * `--sync-manifests` keeps the committed files in step with it.
 *
 *   node scripts/version.mjs                    -> 0.1.20261026170512
 *   node scripts/version.mjs --json             -> the full record
 *   node scripts/version.mjs --set <dir>        -> writes M.N.O into <dir>/package.json, prints it
 *   node scripts/version.mjs --check-manifests  -> non-zero if a package.json is not M.N.0
 *   node scripts/version.mjs --sync-manifests   -> rewrites stale package.json versions to M.N.0
 */

import { execFileSync } from 'node:child_process';
import { readFileSync, writeFileSync } from 'node:fs';
import { dirname, join, resolve as resolvePath } from 'node:path';
import { fileURLToPath } from 'node:url';

const ROOT = resolvePath(dirname(fileURLToPath(import.meta.url)), '..');
const VERSION_FILE = 'VERSION';
// The package.json files whose version follows VERSION. The root manifest is a
// private workspace with no version of its own.
const MANIFESTS = ['packages/oidc-caep-client/package.json', 'demo/package.json'];

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

function utcStamp(d) {
  const p = (n) => String(n).padStart(2, '0');
  return `${d.getUTCFullYear()}${p(d.getUTCMonth() + 1)}${p(d.getUTCDate())}`
    + `${p(d.getUTCHours())}${p(d.getUTCMinutes())}${p(d.getUTCSeconds())}`;
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

/** A version record for a build happening now: `{ version, major, minor, build, commit, builtAt }`. */
export function resolve(now = new Date()) {
  const { major, minor } = readMajorMinor();
  const build = String(process.env.BUILD_NUMBER ?? '').trim() || utcStamp(now);
  if (!/^(0|[1-9]\d*)$/.test(build)) {
    throw new Error(`BUILD_NUMBER must be a non-negative integer without leading zeros, not "${build}"`);
  }
  return {
    version: `${major}.${minor}.${build}`,
    major,
    minor,
    build,
    commit: gitCommit(),
    builtAt: now.toISOString().replace(/\.\d{3}Z$/, 'Z'),
  };
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

/** Writes this build's M.N.O into `<dir>/package.json`. For the publish workspace, never for a commit. */
export function setPackageVersion(dir, record = resolve()) {
  writeVersion(join(resolvePath(dir), 'package.json'), record.version);
  return record;
}

if (process.argv[1] && resolvePath(process.argv[1]) === fileURLToPath(import.meta.url)) {
  try {
    main(process.argv.slice(2));
  } catch (err) {
    console.error(`[version] ${err.message}`);
    process.exit(1);
  }
}

function main(args) {
  const at = args.indexOf('--set');
  if (at >= 0) {
    if (!args[at + 1]) {
      console.error('[version] --set needs the package directory');
      process.exit(2);
    }
    console.log(setPackageVersion(args[at + 1]).version);
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
    console.log(JSON.stringify(resolve(), null, 2));
  } else {
    console.log(resolve().version);
  }
}
