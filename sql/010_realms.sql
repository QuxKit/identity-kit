-- identity-kit realms: one address, separate accounts, in separate places.
--
--   psql -v ON_ERROR_STOP=1 -f sql/010_realms.sql   (after 001_identity.sql,
--                                                    and after 004_oidc.sql if used)
--
-- Required by 0.4. A realm is a namespace of accounts: the same email can hold
-- one account in each realm, and nothing that authenticates in one realm is
-- accepted in another. A school on a learning platform is a realm, so a learner
-- who signs up at two schools has two accounts, and neither school can see or
-- sign in the other's.
--
-- The default realm is the empty string, and every row that existed before this
-- file is in it. An application that never names a realm keeps exactly the
-- uniqueness and the behaviour it had.
--
-- Only `users` carries the realm the library checks. Sessions, reset, verify and
-- magic-link tokens, pending MFA logins and passkeys all point at a user, and
-- the library joins through to it, so a token minted in one realm cannot be
-- redeemed in another however it is replayed. `oauth_identities` carries it as
-- well, because its key has to: the same provider subject may be linked once in
-- each realm.
--
-- API keys are not realm-bound: their owner is an opaque string (a user, a
-- tenant, a service), so the host that issues a key decides whose it is and
-- checks that when it resolves one.
--
-- Re-runnable: every statement is guarded.

CREATE SCHEMA IF NOT EXISTS identity;

ALTER TABLE identity.users ADD COLUMN IF NOT EXISTS realm text NOT NULL DEFAULT '';

DO $$
BEGIN
  IF NOT EXISTS (SELECT 1 FROM pg_constraint WHERE conname = 'users_realm_format') THEN
    -- Lower-case, short, and free of the separator rate-limit keys use, so a
    -- realm can be part of a key without being confused with an address.
    ALTER TABLE identity.users ADD CONSTRAINT users_realm_format
      CHECK (realm = '' OR realm ~ '^[a-z0-9][a-z0-9:._-]{0,79}$');
  END IF;
  IF NOT EXISTS (SELECT 1 FROM pg_constraint WHERE conname = 'users_realm_email_unique') THEN
    ALTER TABLE identity.users ADD CONSTRAINT users_realm_email_unique UNIQUE (realm, email);
  END IF;
  -- Dropped only once its replacement exists, so a failure part-way through
  -- never leaves the table with no uniqueness on email at all.
  ALTER TABLE identity.users DROP CONSTRAINT IF EXISTS users_email_unique;
END;
$$;

DO $$
BEGIN
  IF to_regclass('identity.oauth_identities') IS NULL THEN
    RETURN;
  END IF;
  ALTER TABLE identity.oauth_identities ADD COLUMN IF NOT EXISTS realm text NOT NULL DEFAULT '';
  IF EXISTS (
    SELECT 1 FROM pg_constraint
     WHERE conrelid = 'identity.oauth_identities'::regclass
       AND contype = 'p'
       AND conname = 'oauth_identities_pkey'
       AND array_length(conkey, 1) = 2
  ) THEN
    ALTER TABLE identity.oauth_identities DROP CONSTRAINT oauth_identities_pkey;
    ALTER TABLE identity.oauth_identities ADD CONSTRAINT oauth_identities_pkey PRIMARY KEY (realm, provider, subject);
  END IF;
END;
$$;
