/**
 * Storage for tokens and for in-flight authorization transactions.
 *
 * Token store interface (async or sync methods):
 * @typedef {object} TokenStore
 * @property {(key: string) => Promise<object|undefined>|object|undefined} get
 * @property {(key: string, value: object) => Promise<void>|void} set
 * @property {(key: string) => Promise<void>|void} delete
 */

/** @typedef {Record<string, any>} StoredTokens  A token set as a store keeps it (`TokenSet#toJSON()`). */

/**
 * Tokens in memory only (the default, and what the browser-based apps BCP recommends): nothing
 * persists, so a page reload means signing in again, and nothing is left behind in storage for
 * injected script to read later.
 */
export class MemoryTokenStore {
  #map = new Map();
  /** @param {string} key @returns {StoredTokens|undefined} */
  get(key) { return this.#map.get(key); }
  /** @param {string} key @param {StoredTokens} value */
  set(key, value) { this.#map.set(key, value); }
  /** @param {string} key */
  delete(key) { this.#map.delete(key); }
  /** @returns {string[]} */
  keys() { return [...this.#map.keys()]; }
}

/**
 * Tokens in Web Storage (sessionStorage by default), so a reload keeps the session. Anything script in
 * the page can read, it can read: pair this with DPoP so the stored tokens are useless without the
 * non-extractable key.
 */
export class WebStorageTokenStore {
  #storage;
  #prefix;

  /** @param {{ storage?: Storage, prefix?: string }} [opts] */
  constructor({ storage = globalThis.sessionStorage, prefix = 'oidc-caep-client:tokens:' } = {}) {
    if (!storage) throw new TypeError('Web Storage is not available here');
    this.#storage = storage;
    this.#prefix = prefix;
  }

  /** @param {string} key @returns {StoredTokens|undefined} */
  get(key) {
    const raw = this.#storage.getItem(this.#prefix + key);
    return raw ? JSON.parse(raw) : undefined;
  }

  /** @param {string} key @param {StoredTokens} value */
  set(key, value) { this.#storage.setItem(this.#prefix + key, JSON.stringify(value)); }
  /** @param {string} key */
  delete(key) { this.#storage.removeItem(this.#prefix + key); }
}

/**
 * Tokens in IndexedDB, shared by every tab of this origin and kept until deleted. This is the cache an
 * AccountManager uses for all the accounts signed in in this browser. As with Web Storage, script in the
 * page can read it: pair it with DPoP so the stored tokens are useless without the non-extractable key.
 */
export class IndexedDBTokenStore {
  #name;

  /** @param {{ database?: string }} [opts] */
  constructor({ database = 'oidc-caep-client-tokens' } = {}) {
    if (typeof indexedDB === 'undefined') throw new TypeError('IndexedDB is not available here');
    this.#name = database;
  }

  #open() {
    return new Promise((resolve, reject) => {
      const req = indexedDB.open(this.#name, 1);
      req.onupgradeneeded = () => req.result.createObjectStore('tokens');
      req.onsuccess = () => resolve(req.result);
      req.onerror = () => reject(req.error);
    });
  }

  async #tx(mode, fn) {
    const db = await this.#open();
    try {
      return await new Promise((resolve, reject) => {
        const tx = db.transaction('tokens', mode);
        const req = fn(tx.objectStore('tokens'));
        tx.oncomplete = () => resolve(req.result);
        tx.onerror = () => reject(tx.error);
      });
    } finally {
      db.close();
    }
  }

  /** @param {string} key @returns {Promise<StoredTokens|undefined>} */
  get(key) { return this.#tx('readonly', (s) => s.get(key)); }
  /** @param {string} key @param {StoredTokens} value */
  async set(key, value) { await this.#tx('readwrite', (s) => s.put(value, key)); }
  /** @param {string} key */
  async delete(key) { await this.#tx('readwrite', (s) => s.delete(key)); }
}

/**
 * Authorization transactions (state, nonce, PKCE verifier) between the redirect to the OP and the
 * callback. Keyed by `state`; `take()` removes the entry as it reads it, so each transaction — and
 * therefore each authorization response — can be used exactly once.
 *
 * Uses sessionStorage when present (per tab, cleared when the tab closes, survives the round trip to
 * the OP) and memory otherwise.
 */
export class TransactionStore {
  #storage;
  #memory = new Map();
  #prefix;

  /** @param {{ storage?: Storage|null, prefix?: string }} [opts] */
  constructor({ storage = globalThis.sessionStorage ?? null, prefix = 'oidc-caep-client:txn:' } = {}) {
    this.#storage = storage;
    this.#prefix = prefix;
  }

  /** @param {string} id @param {Record<string, any>} transaction */
  set(id, transaction) {
    const value = JSON.stringify(transaction);
    if (this.#storage) this.#storage.setItem(this.#prefix + id, value);
    else this.#memory.set(id, value);
  }

  /**
   * Reads and removes a transaction.
   * @param {string} id
   * @returns {Record<string, any>|undefined}
   */
  take(id) {
    if (typeof id !== 'string' || !id) return undefined;
    let raw;
    if (this.#storage) {
      raw = this.#storage.getItem(this.#prefix + id);
      this.#storage.removeItem(this.#prefix + id);
    } else {
      raw = this.#memory.get(id);
      this.#memory.delete(id);
    }
    return raw ? JSON.parse(raw) : undefined;
  }

  /**
   * Removes transactions older than `maxAgeMs` (abandoned sign-ins).
   * @param {number} maxAgeMs
   */
  sweep(maxAgeMs) {
    const cutoff = Date.now() - maxAgeMs;
    const expired = (raw) => {
      try {
        return (JSON.parse(raw).createdAt ?? 0) < cutoff;
      } catch {
        return true;
      }
    };
    if (this.#storage) {
      for (let i = this.#storage.length - 1; i >= 0; i--) {
        const k = this.#storage.key(i);
        if (k?.startsWith(this.#prefix) && expired(this.#storage.getItem(k))) this.#storage.removeItem(k);
      }
    } else {
      for (const [k, raw] of this.#memory) if (expired(raw)) this.#memory.delete(k);
    }
  }
}
