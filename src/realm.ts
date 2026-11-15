// Realms: separate namespaces of accounts in one schema (sql/010_realms.sql).
//
// `config.realm` names the realm an instance works in; `identity.inRealm(name)`
// gives a second instance bound to another. Every lookup that starts from
// something a caller presents — an address, a session cookie, a reset link, an
// API key, a passkey — is narrowed to the instance's realm, so a credential from
// one realm is simply not found in another. The empty string is the default
// realm, and every account made before realms existed is in it.

import { IdentityError } from './errors.ts';
import type { IdentityConfig } from './types.ts';

export const DEFAULT_REALM = '';

/** The same rule the CHECK constraint holds: lower-case, at most 80, no `|`. */
const REALM = /^[a-z0-9][a-z0-9:._-]{0,79}$/;

/** The realm `config` names, validated; `''` when it names none. */
export function realmOf(config: Pick<IdentityConfig, 'realm'>): string {
  const realm = config.realm ?? DEFAULT_REALM;
  if (realm !== DEFAULT_REALM && !REALM.test(realm)) {
    throw new IdentityError({
      code: 'invalid_config',
      reason: `realm must be empty or match ${REALM} (lower-case letters, digits, ':', '.', '_', '-'), got ${JSON.stringify(realm)}`,
    });
  }
  return realm;
}

/**
 * An address as a rate-limit subject. Per realm, so a flood at one realm never
 * meters the same address in another; the default realm keeps the bare address,
 * so the keys a running deployment already holds stay the same.
 *
 * The realm goes after the address: everything after an address's last `@` is
 * a domain, which cannot hold a `/`, so no default-realm subject can ever equal
 * a realm's.
 */
export const realmSubject = (realm: string, email: string): string =>
  realm === DEFAULT_REALM ? email : `${email}/${realm}`;
