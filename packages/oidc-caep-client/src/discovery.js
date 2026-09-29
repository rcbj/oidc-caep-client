import { httpRequest, readJson } from './http.js';
import { ValidationError } from './errors.js';

const cache = new Map();

/**
 * Builds the OpenID Connect Discovery 1.0 §4 URL: the well-known suffix is appended to the issuer.
 * @param {string} issuer
 */
export function oidcDiscoveryUrl(issuer) {
  return `${issuer.replace(/\/+$/, '')}/.well-known/openid-configuration`;
}

/**
 * Builds RFC 8414 §3-style well-known URLs: the suffix is inserted between host and path.
 * Some deployments instead append it (OIDC style), so both are returned in preference order.
 * @param {string} issuer
 * @param {string} suffix e.g. "ssf-configuration"
 */
export function wellKnownUrls(issuer, suffix) {
  const u = new URL(issuer);
  const path = u.pathname.replace(/\/+$/, '');
  const inserted = `${u.origin}/.well-known/${suffix}${path}`;
  const appended = `${u.origin}${path}/.well-known/${suffix}`;
  return inserted === appended ? [inserted] : [inserted, appended];
}

/**
 * Fetches metadata from the first URL that answers 2xx and checks that its `issuer` matches exactly.
 * @param {string[]} urls
 * @param {string} expectedIssuer
 * @param {{ timeoutMs?: number, fetch?: typeof fetch, cacheTtlMs?: number }} [opts]
 */
export async function fetchMetadata(urls, expectedIssuer, { cacheTtlMs = 60 * 60_000, ...httpOpts } = {}) {
  const cacheKey = urls.join('|');
  const hit = cache.get(cacheKey);
  if (hit && hit.expiresAt > Date.now()) return hit.metadata;

  let lastError;
  for (const url of urls) {
    const res = await httpRequest(url, { ...httpOpts, headers: { accept: 'application/json' } });
    if (res.status === 404 && url !== urls.at(-1)) {
      await res.body?.cancel();
      continue;
    }
    try {
      const metadata = await readJson(res);
      if (!metadata || typeof metadata !== 'object') throw new ValidationError(`Metadata at ${url} is not a JSON object`);
      // Discovery §4.3 / RFC 8414 §3.3: issuer MUST be identical to the one used to build the URL.
      if (metadata.issuer !== expectedIssuer) {
        throw new ValidationError(
          `Issuer mismatch in ${url}: expected "${expectedIssuer}", got "${metadata.issuer}"`,
          { code: 'issuer_mismatch' },
        );
      }
      cache.set(cacheKey, { metadata, expiresAt: Date.now() + cacheTtlMs });
      return metadata;
    } catch (err) {
      lastError = err;
      break;
    }
  }
  throw lastError ?? new ValidationError(`No metadata found for ${expectedIssuer}`);
}

const REQUIRED_OP_METADATA = [
  'issuer',
  'authorization_endpoint',
  'token_endpoint',
  'jwks_uri',
  'response_types_supported',
  'subject_types_supported',
  'id_token_signing_alg_values_supported',
];

/**
 * Validates an OpenID Provider metadata document (OIDC Discovery 1.0 §3) for use by a code-flow RP.
 * @param {Record<string, any>} metadata
 * @param {string} [expectedIssuer] When given, `issuer` must match exactly (§4.3).
 * @returns {Record<string, any>} the same metadata
 */
export function validateOpenIdProviderMetadata(metadata, expectedIssuer) {
  if (!metadata || typeof metadata !== 'object' || Array.isArray(metadata)) {
    throw new ValidationError('OpenID Provider metadata must be a JSON object');
  }
  const missing = REQUIRED_OP_METADATA.filter((k) => metadata[k] === undefined);
  if (missing.length) {
    throw new ValidationError(`OpenID Provider metadata is missing required fields: ${missing.join(', ')}`);
  }
  if (expectedIssuer !== undefined && metadata.issuer !== expectedIssuer) {
    throw new ValidationError(`Issuer mismatch: expected "${expectedIssuer}", got "${metadata.issuer}"`, { code: 'issuer_mismatch' });
  }
  for (const key of ['issuer', 'authorization_endpoint', 'token_endpoint', 'jwks_uri', 'userinfo_endpoint', 'end_session_endpoint', 'revocation_endpoint']) {
    if (metadata[key] === undefined) continue;
    let url;
    try {
      url = new URL(metadata[key]);
    } catch {
      throw new ValidationError(`OpenID Provider metadata ${key} is not a valid URL`);
    }
    if (key === 'issuer' && (url.search || url.hash)) {
      throw new ValidationError('issuer must not contain a query or fragment');
    }
  }
  if (!Array.isArray(metadata.response_types_supported) || !metadata.response_types_supported.includes('code')) {
    throw new ValidationError('OpenID Provider does not support response_type=code');
  }
  if (!Array.isArray(metadata.id_token_signing_alg_values_supported)) {
    throw new ValidationError('id_token_signing_alg_values_supported must be an array');
  }
  return metadata;
}

/**
 * Retrieves and validates OpenID Provider metadata from `<issuer>/.well-known/openid-configuration`.
 * @param {string} issuer
 * @param {{ timeoutMs?: number, fetch?: typeof fetch, cacheTtlMs?: number }} [opts]
 */
export async function discoverOpenIdProvider(issuer, opts) {
  const metadata = await fetchMetadata([oidcDiscoveryUrl(issuer)], issuer, opts);
  return validateOpenIdProviderMetadata(metadata, issuer);
}

/**
 * Retrieves SSF 1.0 transmitter metadata from `/.well-known/ssf-configuration`
 * (RFC 8414-style path insertion first, then the appended form).
 * @param {string} issuer
 * @param {{ timeoutMs?: number, fetch?: typeof fetch, cacheTtlMs?: number }} [opts]
 */
export async function discoverSSFTransmitter(issuer, opts) {
  const metadata = await fetchMetadata(wellKnownUrls(issuer, 'ssf-configuration'), issuer, opts);
  if (!metadata.jwks_uri) throw new ValidationError('SSF transmitter metadata has no jwks_uri');
  return metadata;
}

/** Clears the in-process metadata cache (mostly useful in tests). */
export function clearDiscoveryCache() {
  cache.clear();
}
