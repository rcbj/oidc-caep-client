import { OAuthError, OIDCClientError } from './errors.js';

/**
 * Thin fetch wrapper with timeout and consistent error handling.
 * @param {string|URL} url
 * @param {RequestInit & { timeoutMs?: number, fetch?: typeof fetch }} [opts]
 */
export async function httpRequest(url, { timeoutMs = 10_000, fetch: fetchImpl = globalThis.fetch, ...init } = {}) {
  try {
    return await fetchImpl(url, { redirect: 'manual', ...init, signal: AbortSignal.timeout(timeoutMs) });
  } catch (err) {
    throw new OIDCClientError(`HTTP request to ${url} failed: ${err.message}`, { code: 'network_error', cause: err });
  }
}

/**
 * Reads a JSON body; turns OAuth error bodies and non-2xx responses into errors.
 * @param {Response} res
 * @param {typeof OIDCClientError} [ErrorClass]
 */
export async function readJson(res, ErrorClass = OIDCClientError) {
  const text = await res.text();
  let body;
  if (text) {
    try {
      body = JSON.parse(text);
    } catch {
      if (res.ok) throw new ErrorClass(`Expected JSON from ${res.url}, got: ${text.slice(0, 200)}`, { status: res.status });
    }
  }
  if (!res.ok) {
    if (body && typeof body.error === 'string') {
      throw new OAuthError({ ...body, status: res.status, response: body });
    }
    throw new ErrorClass(`HTTP ${res.status} from ${res.url}${text ? `: ${text.slice(0, 200)}` : ''}`, {
      code: 'http_error',
      status: res.status,
      response: body ?? text,
    });
  }
  return body;
}
