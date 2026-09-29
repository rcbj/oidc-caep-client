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
 * `identity` fields: iss, sub, email, phone_number, sid (session id), plus any of
 * device/application/tenant/org_unit/group as opaque ids.
 *
 * For complex subjects every member we can evaluate must match and at least one must be evaluable,
 * so a session-scoped event only matches the named session.
 *
 * @param {object} subId
 * @param {Record<string, string|undefined>} identity
 * @returns {boolean}
 */
export function subjectMatches(subId, identity) {
  if (!subId || typeof subId !== 'object') return false;
  switch (subId.format) {
    case 'iss_sub':
      return !!identity.sub && subId.sub === identity.sub && (!identity.iss || subId.iss === identity.iss);
    case 'email':
      return !!identity.email && subId.email?.toLowerCase() === identity.email.toLowerCase();
    case 'phone_number':
      return !!identity.phone_number && subId.phone_number === identity.phone_number;
    case 'opaque':
      return [identity.sub, identity.sid].includes(subId.id);
    case 'account':
      return !!identity.email && subId.uri === `acct:${identity.email}`;
    case 'aliases':
      return (subId.identifiers ?? []).some((id) => subjectMatches(id, identity));
    case 'complex': {
      const results = [];
      for (const member of COMPLEX_MEMBERS) {
        const value = subId[member];
        if (!value) continue;
        if (member === 'user') results.push(subjectMatches(value, identity));
        else if (member === 'session' && identity.sid) results.push(subjectMatches(value, { sid: identity.sid }));
        else if (identity[member]) results.push(subjectMatches(value, { sid: identity[member] }));
      }
      return results.length > 0 && results.every(Boolean);
    }
    default:
      return false;
  }
}
