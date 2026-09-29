/**
 * Token store interface. Implement this to back the cache with Redis, a database, etc.
 * Values are plain JSON-serialisable objects (TokenSet#toJSON()).
 *
 * @typedef {object} TokenStore
 * @property {(key: string) => Promise<object|undefined>|object|undefined} get
 * @property {(key: string, value: object) => Promise<void>|void} set
 * @property {(key: string) => Promise<void>|void} delete
 * @property {() => Promise<Iterable<string>>|Iterable<string>} [keys]
 */

/** Default in-process token store. */
export class MemoryTokenStore {
  #map = new Map();
  get(key) { return this.#map.get(key); }
  set(key, value) { this.#map.set(key, value); }
  delete(key) { this.#map.delete(key); }
  keys() { return [...this.#map.keys()]; }
}
