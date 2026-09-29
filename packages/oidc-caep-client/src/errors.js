/**
 * Base class for every error raised by this library.
 */
export class OIDCClientError extends Error {
  /**
   * @param {string} message
   * @param {{ code?: string, status?: number, cause?: unknown, response?: unknown }} [opts]
   */
  constructor(message, { code, status, cause, response } = {}) {
    super(message, cause ? { cause } : undefined);
    this.name = this.constructor.name;
    this.code = code;
    this.status = status;
    this.response = response;
  }
}

/** The authorization server returned an OAuth 2.0 error response (RFC 6749 §5.2 / §4.1.2.1). */
export class OAuthError extends OIDCClientError {
  constructor({ error, error_description, error_uri, status, response }) {
    super(error_description ? `${error}: ${error_description}` : error, { code: error, status, response });
    this.error = error;
    this.error_description = error_description;
    this.error_uri = error_uri;
  }
}

/** A response from the provider failed validation (bad ID token, state mismatch, metadata mismatch...). */
export class ValidationError extends OIDCClientError {}

/** A Security Event Token could not be accepted. `code` is an RFC 8935 §2.3 error code. */
export class SETValidationError extends OIDCClientError {
  constructor(message, code = 'invalid_request', cause) {
    super(message, { code, cause });
  }
}

/** A Shared Signals Framework management API call failed. */
export class SSFError extends OIDCClientError {}
