import { base64url, digest, randomToken } from './util.js';

export { randomToken };

/** RFC 7636 §4.1: 43–128 chars; 32 random bytes → 43 base64url chars. */
export function generateCodeVerifier() {
  return randomToken(32);
}

/** RFC 7636 §4.2 S256 transformation. */
export async function codeChallengeS256(verifier) {
  return base64url(await digest(verifier, 'SHA-256'));
}
