/** Asymmetric JWS algorithms this library can verify (via jose on Node.js ≥ 20). */
export const ASYMMETRIC_JWS_ALGS = Object.freeze(['RS256', 'RS384', 'RS512', 'PS256', 'PS384', 'PS512', 'ES256', 'ES384', 'ES512', 'EdDSA', 'Ed25519']);

/** ID token algorithms this library can verify; HS* uses the client secret. */
export const SUPPORTED_ID_TOKEN_ALGS = Object.freeze([...ASYMMETRIC_JWS_ALGS, 'HS256', 'HS384', 'HS512']);
