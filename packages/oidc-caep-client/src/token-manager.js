import { EventEmitter } from 'node:events';
import { OAuthError, OIDCClientError } from './errors.js';
import { MemoryTokenStore } from './stores.js';
import { TokenSet } from './token-set.js';

const MAX_TIMEOUT_MS = 2 ** 31 - 1;

/**
 * Caches TokenSets per key (typically a user session id) and keeps them fresh.
 *
 * - `getAccessToken(key)` always returns a token valid for at least `refreshSkewSec`, refreshing on demand.
 * - With `autoRefresh` (default), a timer refreshes each token `refreshSkewSec` before it expires.
 * - Concurrent refreshes for the same key are coalesced into one token-endpoint call.
 * - Client-credentials tokens are cached per scope/resource and re-requested when near expiry.
 *
 * Events:
 *   "refreshed"      (key, tokenSet)  — new tokens obtained via refresh_token
 *   "refresh_error"  (key, error)     — refresh failed (tokens are dropped if the grant is invalid)
 *   "expired"        (key)            — tokens for key could not be renewed and were removed
 *   "removed"        (key)            — tokens deleted via delete()
 */
export class TokenManager extends EventEmitter {
  #client;
  #store;
  #timers = new Map();
  #inflight = new Map();
  #ccCache = new Map();
  #opts;

  /**
   * @param {import('./oidc-client.js').OIDCClient} client
   * @param {{ store?: import('./stores.js').TokenStore, refreshSkewSec?: number, autoRefresh?: boolean, minRefreshDelayMs?: number, retryDelayMs?: number }} [opts]
   */
  constructor(client, { store = new MemoryTokenStore(), refreshSkewSec = 60, autoRefresh = true, minRefreshDelayMs = 1000, retryDelayMs = 5000 } = {}) {
    super();
    this.#client = client;
    this.#store = store;
    this.#opts = { refreshSkewSec, autoRefresh, minRefreshDelayMs, retryDelayMs };
  }

  /** Stores tokens for a key and schedules their proactive refresh. */
  async set(key, tokenSet) {
    const ts = TokenSet.from(tokenSet);
    await this.#store.set(key, ts.toJSON());
    this.#schedule(key, ts);
    return ts;
  }

  /** @returns {Promise<TokenSet|undefined>} Cached tokens (possibly expired) for key. */
  async get(key) {
    const raw = await this.#store.get(key);
    return raw ? TokenSet.from(raw) : undefined;
  }

  /**
   * Returns a usable access token for key, refreshing first if it is expired or about to expire.
   * @param {string} key
   * @param {{ forceRefresh?: boolean }} [opts]
   * @returns {Promise<string>}
   */
  async getAccessToken(key, { forceRefresh = false } = {}) {
    let ts = await this.get(key);
    if (!ts) throw new OIDCClientError(`No tokens cached for ${key}`, { code: 'no_tokens' });
    if (forceRefresh || ts.isExpired(this.#opts.refreshSkewSec)) {
      if (ts.refresh_token) {
        ts = await this.refresh(key);
      } else if (ts.isExpired()) {
        await this.#drop(key, 'expired');
        throw new OIDCClientError('Access token expired and no refresh_token is available', { code: 'token_expired' });
      }
    }
    return ts.access_token;
  }

  /**
   * Refreshes tokens for key now. Concurrent calls share a single request.
   * @returns {Promise<TokenSet>}
   */
  refresh(key) {
    const existing = this.#inflight.get(key);
    if (existing) return existing;
    const p = (async () => {
      const current = await this.get(key);
      if (!current) throw new OIDCClientError(`No tokens cached for ${key}`, { code: 'no_tokens' });
      try {
        const next = await this.#client.refresh(current);
        // The key may have been deleted (e.g. CAEP session revoked) while the request was in flight.
        if (!(await this.#store.get(key))) {
          throw new OIDCClientError(`Tokens for ${key} were removed during refresh`, { code: 'no_tokens' });
        }
        await this.set(key, next);
        this.emit('refreshed', key, next);
        return next;
      } catch (err) {
        this.emit('refresh_error', key, err);
        if (err instanceof OAuthError && (err.error === 'invalid_grant' || err.error === 'invalid_client')) {
          await this.#drop(key, 'expired');
        }
        throw err;
      }
    })().finally(() => this.#inflight.delete(key));
    this.#inflight.set(key, p);
    return p;
  }

  /**
   * Removes tokens for key, optionally revoking them at the OP (RFC 7009).
   * @param {string} key
   * @param {{ revoke?: boolean }} [opts]
   */
  async delete(key, { revoke = false } = {}) {
    const ts = await this.get(key);
    await this.#drop(key, 'removed');
    if (revoke && ts) {
      await Promise.allSettled([
        ts.refresh_token && this.#client.revoke(ts.refresh_token, 'refresh_token'),
        this.#client.revoke(ts.access_token, 'access_token'),
      ]);
    }
    return ts;
  }

  /**
   * Returns a cached client-credentials access token, requesting a new one when near expiry.
   * @param {{ scope?: string, resource?: string, audience?: string }} [params]
   * @returns {Promise<string>}
   */
  async getClientCredentialsToken(params = {}) {
    const key = JSON.stringify([params.scope, params.resource, params.audience]);
    const cached = this.#ccCache.get(key);
    if (cached && !(cached instanceof Promise) && !cached.isExpired(this.#opts.refreshSkewSec)) return cached.access_token;
    if (cached instanceof Promise) return (await cached).access_token;
    const p = this.#client.clientCredentials(params);
    this.#ccCache.set(key, p);
    try {
      const ts = await p;
      this.#ccCache.set(key, ts);
      return ts.access_token;
    } catch (err) {
      this.#ccCache.delete(key);
      throw err;
    }
  }

  /** Cancels all refresh timers (call on shutdown). */
  close() {
    for (const t of this.#timers.values()) clearTimeout(t);
    this.#timers.clear();
  }

  async #drop(key, event) {
    clearTimeout(this.#timers.get(key));
    this.#timers.delete(key);
    await this.#store.delete(key);
    this.emit(event, key);
  }

  #schedule(key, ts) {
    clearTimeout(this.#timers.get(key));
    this.#timers.delete(key);
    if (!this.#opts.autoRefresh || ts.expires_at === undefined || !ts.refresh_token) return;
    const dueMs = (ts.expires_at - ts.effectiveSkew(this.#opts.refreshSkewSec)) * 1000 - Date.now();
    const delay = Math.min(MAX_TIMEOUT_MS, Math.max(this.#opts.minRefreshDelayMs, dueMs));
    const timer = setTimeout(() => {
      this.#timers.delete(key);
      this.refresh(key).catch(() => this.#retry(key));
    }, delay);
    timer.unref?.();
    this.#timers.set(key, timer);
  }

  /** After a transient background-refresh failure (already surfaced via "refresh_error"), try again later. */
  async #retry(key) {
    const ts = await this.get(key);
    if (!ts || this.#timers.has(key)) return;
    if (ts.isExpired()) {
      await this.#drop(key, 'expired');
      return;
    }
    const timer = setTimeout(() => {
      this.#timers.delete(key);
      this.refresh(key).catch(() => this.#retry(key));
    }, this.#opts.retryDelayMs);
    timer.unref?.();
    this.#timers.set(key, timer);
  }
}
