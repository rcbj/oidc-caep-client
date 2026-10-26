/**
 * Helpers for RFC 9493 Subject Identifiers, as carried in the SET `sub_id` claim.
 */
export const Subject = Object.freeze({
  issSub: (iss, sub) => ({ format: 'iss_sub', iss, sub }),
  email: (email) => ({ format: 'email', email }),
  phone: (phone_number) => ({ format: 'phone_number', phone_number }),
  opaque: (id) => ({ format: 'opaque', id }),
  account: (uri) => ({ format: 'account', uri }),
  uri: (uri) => ({ format: 'uri', uri }),
  did: (url) => ({ format: 'did', url }),
  aliases: (...identifiers) => ({ format: 'aliases', identifiers }),
  /** SSF complex subject, e.g. { user: Subject.issSub(...), session: Subject.opaque(sid) } */
  complex: (members) => ({ format: 'complex', ...members }),
});

const COMPLEX_MEMBERS = ['user', 'session', 'device', 'application', 'tenant', 'org_unit', 'group'];

/**
 * Tests whether a subject identifier refers to a known identity.
 *
 * `identity` fields: iss, sub, sid (session id), email and email_verified, phone_number and
 * phone_number_verified, plus any of device/application/tenant/org_unit/group as opaque ids.
 *
 * - An email or phone number identifies somebody only when the OP said it was verified
 *   (`email_verified` / `phone_number_verified` true): OIDC Core §5.7 makes neither a stable or unique
 *   identifier, and an unverified one may be anybody's.
 * - A top-level opaque id is compared with `sub`. A session is named inside a complex subject.
 * - In a complex subject every member must match, and the members this identity can't be checked
 *   against count as a non-match: an event about one session matches only an identity holding that `sid`.
 *
 * @param {Record<string, any>} subId  An RFC 9493 subject identifier, e.g. a SET's `sub_id`
 * @param {Record<string, any>} identity
 * @returns {boolean}
 */
export function subjectMatches(subId, identity) {
  if (!subId || typeof subId !== 'object' || !identity) return false;
  switch (subId.format) {
    case 'iss_sub':
      return typeof subId.sub === 'string' && !!identity.sub && subId.sub === identity.sub
        && (!identity.iss || subId.iss === identity.iss);
    case 'email':
      return identity.email_verified === true && typeof identity.email === 'string' && typeof subId.email === 'string'
        && subId.email.toLowerCase() === identity.email.toLowerCase();
    case 'phone_number':
      return identity.phone_number_verified === true && typeof subId.phone_number === 'string'
        && subId.phone_number === identity.phone_number;
    case 'opaque':
      return opaqueIs(subId, identity.sub);
    case 'account':
      return identity.email_verified === true && typeof identity.email === 'string'
        && subId.uri === `acct:${identity.email}`;
    case 'aliases':
      return (subId.identifiers ?? []).some((id) => subjectMatches(id, identity));
    case 'complex': {
      const members = COMPLEX_MEMBERS.filter((m) => subId[m]);
      if (!members.length) return false;
      return members.every((member) => {
        const value = subId[member];
        if (member === 'user') return subjectMatches(value, identity);
        if (member === 'session') return opaqueIs(value, identity.sid);
        return opaqueIs(value, identity[member]);
      });
    }
    default:
      return false;
  }
}

/** An opaque identifier naming exactly `id`: both must be non-empty strings. */
function opaqueIs(value, id) {
  return value?.format === 'opaque' && typeof value.id === 'string' && value.id !== ''
    && typeof id === 'string' && value.id === id;
}
