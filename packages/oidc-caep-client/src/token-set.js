import { decodeJwt } from 'jose';

const UNSAFE_KEYS = new Set(['__proto__', 'constructor', 'prototype']);

/**
 * Immutable-ish holder for a token endpoint response. Serializable via toJSON()/TokenSet.from().
 */
export class TokenSet {
  /**
   * @param {object} tokens  Token endpoint response (snake_case), optionally with `expires_at` (epoch seconds).
   * @param {object} [claims] Validated ID token claims, if an ID token was issued.
   */
  constructor(tokens, claims) {
    const { expires_in, claims: _ignored, ...rest } = tokens;
    // Field by field rather than Object.assign: a JSON "__proto__" member would otherwise replace this
    // object's prototype. `claims` comes only from the validated ID token (the second argument).
    for (const [name, value] of Object.entries(rest)) {
      if (!UNSAFE_KEYS.has(name)) this[name] = value;
    }
    if (this.expires_at === undefined && expires_in !== undefined) {
      this.issued_at ??= Math.floor(Date.now() / 1000);
      this.expires_at = this.issued_at + Number(expires_in);
    }
    if (claims) this.claims = claims;
    else if (this.id_token && !this.claims) this.claims = decodeJwt(this.id_token);
  }

  /** @returns {number|undefined} Seconds until the access token expires. */
  expiresIn() {
    if (this.expires_at === undefined) return undefined;
    return Math.max(0, this.expires_at - Math.floor(Date.now() / 1000));
  }

  /**
   * Skew to apply for early renewal, capped at half the token lifetime so short-lived
   * tokens aren't considered expired the moment they're issued.
   * @param {number} skewSec
   */
  effectiveSkew(skewSec) {
    if (this.issued_at === undefined || this.expires_at === undefined) return skewSec;
    return Math.min(skewSec, (this.expires_at - this.issued_at) / 2);
  }

  /**
   * @param {number} [skewSec] Treat the token as expired this many seconds early (see effectiveSkew).
   */
  isExpired(skewSec = 0) {
    if (this.expires_at === undefined) return false;
    return this.expires_at - this.effectiveSkew(skewSec) <= Math.floor(Date.now() / 1000);
  }

  toJSON() {
    return { ...this };
  }

  /** @param {TokenSet|object} value */
  static from(value) {
    if (!value || value instanceof TokenSet) return value;
    const { claims, ...tokens } = value;
    return new TokenSet(tokens, claims);
  }
}
