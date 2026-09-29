const CAEP_BASE = 'https://schemas.openid.net/secevent/caep/event-type/';
const SSF_BASE = 'https://schemas.openid.net/secevent/ssf/event-type/';
const RISC_BASE = 'https://schemas.openid.net/secevent/risc/event-type/';

/** OpenID CAEP 1.0 event types. */
export const CAEP = Object.freeze({
  SESSION_REVOKED: `${CAEP_BASE}session-revoked`,
  TOKEN_CLAIMS_CHANGE: `${CAEP_BASE}token-claims-change`,
  CREDENTIAL_CHANGE: `${CAEP_BASE}credential-change`,
  ASSURANCE_LEVEL_CHANGE: `${CAEP_BASE}assurance-level-change`,
  DEVICE_COMPLIANCE_CHANGE: `${CAEP_BASE}device-compliance-change`,
  SESSION_ESTABLISHED: `${CAEP_BASE}session-established`,
  SESSION_PRESENTED: `${CAEP_BASE}session-presented`,
  RISK_LEVEL_CHANGE: `${CAEP_BASE}risk-level-change`,
});

/** OpenID Shared Signals Framework 1.0 stream-control event types. */
export const SSF = Object.freeze({
  VERIFICATION: `${SSF_BASE}verification`,
  STREAM_UPDATED: `${SSF_BASE}stream-updated`,
});

/** OpenID RISC 1.0 event types (receivable through `onEvent(RISC.X, handler)`). */
export const RISC = Object.freeze({
  ACCOUNT_CREDENTIAL_CHANGE_REQUIRED: `${RISC_BASE}account-credential-change-required`,
  ACCOUNT_PURGED: `${RISC_BASE}account-purged`,
  ACCOUNT_DISABLED: `${RISC_BASE}account-disabled`,
  ACCOUNT_ENABLED: `${RISC_BASE}account-enabled`,
  IDENTIFIER_CHANGED: `${RISC_BASE}identifier-changed`,
  IDENTIFIER_RECYCLED: `${RISC_BASE}identifier-recycled`,
  CREDENTIAL_COMPROMISE: `${RISC_BASE}credential-compromise`,
  OPT_IN: `${RISC_BASE}opt-in`,
  OPT_OUT_INITIATED: `${RISC_BASE}opt-out-initiated`,
  OPT_OUT_CANCELLED: `${RISC_BASE}opt-out-cancelled`,
  OPT_OUT_EFFECTIVE: `${RISC_BASE}opt-out-effective`,
  RECOVERY_ACTIVATED: `${RISC_BASE}recovery-activated`,
  RECOVERY_INFORMATION_CHANGED: `${RISC_BASE}recovery-information-changed`,
});

/** SSF delivery methods. */
export const DELIVERY = Object.freeze({
  PUSH: 'urn:ietf:rfc:8935',
  POLL: 'urn:ietf:rfc:8936',
});

/** Short name ("session-revoked") for an event type URI. */
export function eventName(uri) {
  return uri.slice(uri.lastIndexOf('/') + 1);
}
