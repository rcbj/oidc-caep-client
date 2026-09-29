import { calculateJwkThumbprint, exportJWK, generateKeyPair, SignJWT } from 'jose';
import { base64url, digest } from './util.js';

/** DPoP proof algorithms this library can create, in preference order. */
export const DPOP_ALGS = Object.freeze(['ES256', 'ES384', 'PS256', 'RS256']);

/**
 * A DPoP key pair (RFC 9449) and the proofs made with it.
 *
 * The private key is generated NON-EXTRACTABLE: script running in the page (including injected script)
 * can ask it to sign while the page is open, but can never read it out, so a stolen access or refresh
 * token is useless anywhere else. Keep the same key for the lifetime of the tokens it binds; use
 * `IndexedDBKeyStore` to keep it across page loads.
 */
export class DPoPKey {
  #privateKey;
  /** @type {Record<string, any>} */
  publicJwk;
  /** @type {string} */
  alg;
  /** @type {string} RFC 7638 SHA-256 thumbprint of the public key (the `jkt`). */
  thumbprint;

  constructor(alg, privateKey, publicJwk, thumbprint) {
    this.alg = alg;
    this.#privateKey = privateKey;
    this.publicJwk = publicJwk;
    this.thumbprint = thumbprint;
  }

  /**
   * Builds a key from a CryptoKeyPair, generating a new non-extractable pair if none is given.
   * @param {{ alg?: string, keyPair?: CryptoKeyPair }} [opts]
   */
  static async create({ alg = 'ES256', keyPair } = {}) {
    const pair = keyPair ?? await generateKeyPair(alg, { extractable: false });
    const { kty, crv, x, y, n, e } = await exportJWK(pair.publicKey);
    const publicJwk = Object.fromEntries(Object.entries({ kty, crv, x, y, n, e }).filter(([, v]) => v !== undefined));
    const thumbprint = await calculateJwkThumbprint(publicJwk, 'sha256');
    const key = new DPoPKey(alg, pair.privateKey, publicJwk, thumbprint);
    key.keyPair = pair;
    return key;
  }

  /**
   * Loads the key held in `store`, or creates one and stores it.
   * @param {{ get(): Promise<{alg: string, keyPair: CryptoKeyPair}|undefined>, set(value): Promise<void> }} store
   * @param {{ alg?: string }} [opts]
   */
  static async loadOrCreate(store, { alg = 'ES256' } = {}) {
    const held = await store.get();
    if (held?.keyPair && held.alg === alg) return DPoPKey.create({ alg, keyPair: held.keyPair });
    const key = await DPoPKey.create({ alg });
    await store.set({ alg, keyPair: key.keyPair });
    return key;
  }

  /**
   * Creates a DPoP proof JWT (RFC 9449 §4.2).
   * @param {{ method: string, url: string, nonce?: string, accessToken?: string }} opts
   */
  async proof({ method, url, nonce, accessToken }) {
    const claims = { htm: method.toUpperCase(), htu: htuOf(url), jti: crypto.randomUUID() };
    if (nonce) claims.nonce = nonce;
    if (accessToken) claims.ath = base64url(await digest(accessToken, 'SHA-256'));
    return new SignJWT(claims)
      .setProtectedHeader({ typ: 'dpop+jwt', alg: this.alg, jwk: this.publicJwk })
      .setIssuedAt()
      .sign(this.#privateKey);
  }
}

/** The `htu` of a request: its URL without query and fragment (RFC 9449 §4.2). */
export function htuOf(url) {
  const u = new URL(url);
  u.search = '';
  u.hash = '';
  return u.href;
}

/** Remembers the most recent `DPoP-Nonce` each server origin handed out (RFC 9449 §8, §9). */
export class DPoPNonceCache {
  #nonces = new Map();

  get(url) {
    return this.#nonces.get(new URL(url).origin);
  }

  /** Records the nonce a response carries, if any, and returns it. */
  update(url, response) {
    const nonce = response?.headers?.get?.('dpop-nonce');
    if (nonce) this.#nonces.set(new URL(url).origin, nonce);
    return nonce ?? undefined;
  }
}

/** Whether a resource server's 401 asks for a (new) DPoP nonce (RFC 9449 §9). */
export function wantsDpopNonce(response) {
  if (response.status !== 401) return false;
  const www = response.headers.get('www-authenticate') ?? '';
  return /\bdpop\b/i.test(www) && /error="use_dpop_nonce"/.test(www) && !!response.headers.get('dpop-nonce');
}

/**
 * Keeps one DPoP key pair in IndexedDB. CryptoKeys are stored as-is (structured clone), so a
 * non-extractable private key survives page loads without ever being exported.
 */
export class IndexedDBKeyStore {
  #name;
  #key;

  /** @param {{ database?: string, key?: string }} [opts] */
  constructor({ database = 'oidc-caep-client', key = 'dpop-key' } = {}) {
    this.#name = database;
    this.#key = key;
  }

  #open() {
    return new Promise((resolve, reject) => {
      const req = indexedDB.open(this.#name, 1);
      req.onupgradeneeded = () => req.result.createObjectStore('keys');
      req.onsuccess = () => resolve(req.result);
      req.onerror = () => reject(req.error);
    });
  }

  async #tx(mode, fn) {
    const db = await this.#open();
    try {
      return await new Promise((resolve, reject) => {
        const tx = db.transaction('keys', mode);
        const req = fn(tx.objectStore('keys'));
        tx.oncomplete = () => resolve(req.result);
        tx.onerror = () => reject(tx.error);
      });
    } finally {
      db.close();
    }
  }

  get() { return this.#tx('readonly', (s) => s.get(this.#key)); }
  set(value) { return this.#tx('readwrite', (s) => s.put(value, this.#key)); }
  delete() { return this.#tx('readwrite', (s) => s.delete(this.#key)); }
}

/** Keeps a DPoP key in memory only (a new key after every page load). */
export class MemoryKeyStore {
  #value;
  async get() { return this.#value; }
  async set(value) { this.#value = value; }
  async delete() { this.#value = undefined; }
}
