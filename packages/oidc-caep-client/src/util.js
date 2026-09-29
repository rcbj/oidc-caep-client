// Browser-safe primitives: Web APIs only (WebCrypto, TextEncoder, URL), so the library runs unchanged in
// browsers and in Node.js ≥ 20.

const encoder = new TextEncoder();

/** base64url without padding. */
export function base64url(bytes) {
  let binary = '';
  const view = bytes instanceof Uint8Array ? bytes : new Uint8Array(bytes);
  for (let i = 0; i < view.length; i++) binary += String.fromCharCode(view[i]);
  return btoa(binary).replace(/\+/g, '-').replace(/\//g, '_').replace(/=+$/, '');
}

/** A cryptographically random base64url string (default 256 bits). */
export function randomToken(bytes = 32) {
  return base64url(crypto.getRandomValues(new Uint8Array(bytes)));
}

/** SHA-256/384/512 digest of a string. */
export async function digest(value, alg = 'SHA-256') {
  return new Uint8Array(await crypto.subtle.digest(alg, encoder.encode(value)));
}

/**
 * Compares two strings in time independent of where they differ, so a response's `state` or a logout
 * `state` cannot be guessed byte by byte from timing. Both sides are hashed first so their lengths match.
 */
export async function timingSafeEqual(a, b) {
  if (typeof a !== 'string' || typeof b !== 'string') return false;
  const [x, y] = await Promise.all([digest(a), digest(b)]);
  let diff = 0;
  for (let i = 0; i < x.length; i++) diff |= x[i] ^ y[i];
  return diff === 0;
}

/** Loopback hosts, where plain http is acceptable (RFC 8252 §7.3, RFC 9700 §2.6). */
export function isLoopback(url) {
  const host = new URL(url).hostname.replace(/^\[|\]$/g, '');
  return host === 'localhost' || host.endsWith('.localhost') || host === '::1' || /^127(\.\d{1,3}){3}$/.test(host);
}

/** A minimal event emitter (Node's EventEmitter API subset), usable in browsers. */
export class Emitter {
  #listeners = new Map();

  on(event, fn) {
    if (!this.#listeners.has(event)) this.#listeners.set(event, new Set());
    this.#listeners.get(event).add(fn);
    return this;
  }

  off(event, fn) {
    this.#listeners.get(event)?.delete(fn);
    return this;
  }

  once(event, fn) {
    const wrapped = (...args) => {
      this.off(event, wrapped);
      fn(...args);
    };
    return this.on(event, wrapped);
  }

  emit(event, ...args) {
    const set = this.#listeners.get(event);
    if (!set?.size) return false;
    for (const fn of [...set]) {
      try {
        fn(...args);
      } catch (err) {
        queueMicrotask(() => { throw err; });
      }
    }
    return true;
  }
}

/** Resolves when `emitter` next emits `event`, with the event's arguments. */
export function onceEvent(emitter, event) {
  return new Promise((resolve) => emitter.once(event, (...args) => resolve(args)));
}
