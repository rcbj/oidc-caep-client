const UNSAFE_KEYS = new Set(['__proto__', 'constructor', 'prototype']);

/**
 * Immutable-ish holder for a token endpoint response. Serializable via toJSON()/TokenSet.from().
 */
export class TokenSet {
  // The members a token response can have. Declared so TypeScript knows them; the constructor fills in
  // whichever the response carried, and the rest stay undefined (JSON storage drops them).
  /** @type {string} */
  access_token;
  /** 'Bearer' or 'DPoP'. @type {string} */
  token_type;
  /** @type {string|undefined} */
  refresh_token;
  /** @type {string|undefined} */
  id_token;
  /** @type {string|undefined} */
  scope;
  /** Epoch seconds when the access token expires. @type {number|undefined} */
  expires_at;
  /** Epoch seconds when the tokens were issued. @type {number|undefined} */
  issued_at;
  /** The validated ID token's claims. @type {Record<string, any>|undefined} */
  claims;

  /**
   * @param {Record<string, any>} tokens  Token endpoint response (snake_case), optionally with `expires_at` (epoch seconds).
   * @param {Record<string, any>} [claims] Validated ID token claims, if an ID token was issued.
   */
  constructor(tokens, claims) {
    const { expires_in, claims: _ignored, ...rest } = tokens;
    // Field by field rather than Object.assign: a JSON "__proto__" member would otherwise replace this
    // object's prototype, and one named like a method ("isExpired", "toJSON") would shadow it. `claims`
    // comes only from the validated ID token (the second argument).
    for (const [name, value] of Object.entries(rest)) {
      if (!UNSAFE_KEYS.has(name) && !(name in TokenSet.prototype)) this[name] = value;
    }
    if (this.expires_at === undefined && expires_in !== undefined) {
      this.issued_at ??= Math.floor(Date.now() / 1000);
      this.expires_at = this.issued_at + Number(expires_in);
    }
    // Only claims the client validated. An ID token's payload is never decoded here unverified: code
    // that trusts `claims` (UserInfo's sub check, account keys) must not be handed claims nobody checked.
    if (claims) this.claims = claims;
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

  /** @returns {Record<string, any>} */
  toJSON() {
    return { ...this };
  }

  /**
   * @param {TokenSet|Record<string, any>} value  A TokenSet, or one as stored (`toJSON()`).
   * @returns {TokenSet}
   */
  static from(value) {
    if (!value || value instanceof TokenSet) return value;
    const { claims, ...tokens } = value;
    return new TokenSet(tokens, claims);
  }
}
