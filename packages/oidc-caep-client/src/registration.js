import { SUPPORTED_ID_TOKEN_ALGS } from './algs.js';
import { OIDCClientError, ValidationError } from './errors.js';
import { httpRequest, readJson } from './http.js';

/**
 * Client metadata values the server must honour exactly as requested; if it registers something else
 * (OIDC Dynamic Client Registration 1.0 §3.2 allows substitution) the registration is rejected.
 */
const MUST_MATCH = ['id_token_signed_response_alg', 'token_endpoint_auth_method'];

/**
 * @typedef {object} ClientRegistration  Client Information Response (RFC 7591 §3.2.1 / OIDC DCR §3.2)
 * @property {string} client_id
 * @property {string} [client_secret]
 * @property {number} [client_secret_expires_at]
 * @property {string} [registration_access_token]  RFC 7592 / OIDC DCR §3.2
 * @property {string} [registration_client_uri]
 * @property {string} [id_token_signed_response_alg]
 * @property {string} [token_endpoint_auth_method]
 */

/**
 * Registers a client with an OpenID Provider (OpenID Connect Dynamic Client Registration 1.0, RFC 7591).
 *
 * @param {Record<string, any>} providerMetadata  OP metadata; must advertise `registration_endpoint`.
 * @param {Record<string, any>} clientMetadata    e.g. { redirect_uris, id_token_signed_response_alg, grant_types, ... }
 * @param {{ initialAccessToken?: string, timeoutMs?: number, fetch?: typeof fetch }} [opts]
 * @returns {Promise<ClientRegistration>}
 */
export async function registerClient(providerMetadata, clientMetadata, { initialAccessToken, ...httpOpts } = {}) {
  const endpoint = providerMetadata?.registration_endpoint;
  if (!endpoint) throw new OIDCClientError('OpenID Provider does not advertise a registration_endpoint', { code: 'registration_not_supported' });
  if (!Array.isArray(clientMetadata?.redirect_uris) || !clientMetadata.redirect_uris.length) {
    throw new TypeError('clientMetadata.redirect_uris is required');
  }
  const alg = clientMetadata.id_token_signed_response_alg;
  if (alg && !SUPPORTED_ID_TOKEN_ALGS.includes(alg)) {
    throw new ValidationError(`Refusing to register id_token_signed_response_alg ${alg}: this library cannot verify it`);
  }
  const advertised = providerMetadata.id_token_signing_alg_values_supported;
  if (alg && Array.isArray(advertised) && !advertised.includes(alg)) {
    throw new ValidationError(`OpenID Provider does not support id_token_signed_response_alg ${alg}`);
  }

  const headers = { 'content-type': 'application/json', accept: 'application/json' };
  if (initialAccessToken) headers.authorization = `Bearer ${initialAccessToken}`;
  const res = await httpRequest(endpoint, { ...httpOpts, method: 'POST', headers, body: JSON.stringify(clientMetadata) });
  const registration = await readJson(res);
  if (!registration?.client_id) throw new ValidationError('Registration response is missing client_id', { response: registration });

  for (const key of MUST_MATCH) {
    if (clientMetadata[key] !== undefined && registration[key] !== undefined && registration[key] !== clientMetadata[key]) {
      throw new ValidationError(
        `The OP registered ${key}=${registration[key]} instead of the requested ${clientMetadata[key]}`,
        { code: 'registration_mismatch', response: registration },
      );
    }
  }
  return registration;
}

/**
 * Reads the current registration (OIDC DCR §4 / RFC 7592 §2.1).
 * @param {ClientRegistration} registration
 * @param {{ timeoutMs?: number, fetch?: typeof fetch }} [opts]
 */
export async function readClientRegistration(registration, opts) {
  const { uri, token } = managementCredentials(registration);
  const res = await httpRequest(uri, { ...opts, headers: { authorization: `Bearer ${token}`, accept: 'application/json' } });
  return readJson(res);
}

/**
 * Deletes a registration (RFC 7592 §2.3).
 * @param {ClientRegistration} registration
 * @param {{ timeoutMs?: number, fetch?: typeof fetch }} [opts]
 */
export async function deleteClientRegistration(registration, opts) {
  const { uri, token } = managementCredentials(registration);
  const res = await httpRequest(uri, { ...opts, method: 'DELETE', headers: { authorization: `Bearer ${token}` } });
  if (!res.ok) await readJson(res);
  else await res.body?.cancel();
}

function managementCredentials(registration) {
  if (!registration?.registration_client_uri || !registration.registration_access_token) {
    throw new OIDCClientError('Registration has no registration_client_uri / registration_access_token', { code: 'registration_not_manageable' });
  }
  return { uri: registration.registration_client_uri, token: registration.registration_access_token };
}
