/** Asymmetric JWS algorithms this library can verify (via jose, in browsers and Node.js). */
export const ASYMMETRIC_JWS_ALGS = Object.freeze(['RS256', 'RS384', 'RS512', 'PS256', 'PS384', 'PS512', 'ES256', 'ES384', 'ES512', 'EdDSA', 'Ed25519']);

/**
 * ID token algorithms this library can verify. A public client has no secret, so HS* (MACed with the
 * client secret) is not among them.
 */
export const SUPPORTED_ID_TOKEN_ALGS = ASYMMETRIC_JWS_ALGS;
