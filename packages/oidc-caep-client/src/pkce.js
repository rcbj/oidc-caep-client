import { createHash, randomBytes } from 'node:crypto';

/** @param {number} [bytes] */
export function randomToken(bytes = 32) {
  return randomBytes(bytes).toString('base64url');
}

/** RFC 7636 §4.1: 43–128 chars; 32 random bytes → 43 base64url chars. */
export function generateCodeVerifier() {
  return randomToken(32);
}

/** RFC 7636 §4.2 S256 transformation. */
export function codeChallengeS256(verifier) {
  return createHash('sha256').update(verifier).digest('base64url');
}
