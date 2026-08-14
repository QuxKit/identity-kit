-- identity-kit schema: users, sessions, and the two token tables.
--
--   psql -v ON_ERROR_STOP=1 -f sql/001_identity.sql
--
-- Everything lives in an `identity` schema so it cannot collide with a host
-- application's `users` table and a `search_path` change cannot make either
-- ambiguous. It is the sibling boundary billing-kit's `billing` and tenant-kit's
-- `tenancy` schemas draw, for the same reason.
--
-- A user's id here is the principal the rest of the family keys on: it is the
-- `userId` in tenant-kit's memberships and, through the tenant, the subject a
-- billing-kit charge lands on. This schema owns identity and nothing else — no
-- memberships, no roles, no billing. Those belong to their own libraries.
--
-- Re-runnable: every statement is guarded.

CREATE SCHEMA IF NOT EXISTS identity;

-- gen_random_uuid() is in core since PostgreSQL 13.
DO $$
BEGIN
  IF current_setting('server_version_num')::integer < 130000 THEN
    RAISE EXCEPTION 'identity-kit requires PostgreSQL 13 or newer (gen_random_uuid)';
  END IF;
END;
$$;

-- The person.
--
-- `email` is stored already normalised (trimmed, lower-cased by the library) and
-- carries the UNIQUE constraint; `email_display` keeps what the user typed, for
-- showing back. `password_hash` is nullable so a passwordless account (invited,
-- SSO-only later) is representable. `pepper_version` records which pepper made
-- the hash, so the key can be rotated without a forced reset.
--
-- `failed_logins` / `locked_until` drive exponential backoff, not a hard lock: a
-- hard per-account lock is a denial-of-service primitive anyone who knows an
-- address can point at its owner.
CREATE TABLE IF NOT EXISTS identity.users (
  id                    uuid        PRIMARY KEY DEFAULT gen_random_uuid(),
  email                 text        NOT NULL,
  email_display         text        NOT NULL,
  name                  text,
  email_verified_at     timestamptz,
  password_hash         text,
  pepper_version        integer     NOT NULL DEFAULT 1,
  deletion_requested_at timestamptz,
  failed_logins         integer     NOT NULL DEFAULT 0,
  locked_until          timestamptz,
  created_at            timestamptz NOT NULL DEFAULT now(),
  updated_at            timestamptz NOT NULL DEFAULT now(),
  CONSTRAINT users_email_unique UNIQUE (email)
);

-- Keep updated_at honest without every UPDATE having to remember to set it.
CREATE OR REPLACE FUNCTION identity.touch_updated_at() RETURNS trigger
LANGUAGE plpgsql AS $$
BEGIN
  NEW.updated_at := now();
  RETURN NEW;
END;
$$;

DROP TRIGGER IF EXISTS users_touch_updated_at ON identity.users;
CREATE TRIGGER users_touch_updated_at
  BEFORE UPDATE ON identity.users
  FOR EACH ROW EXECUTE FUNCTION identity.touch_updated_at();

-- Server-side sessions. The row carries only identity — `user_id` — never
-- entitlement, so removal from an organisation (tenant-kit's concern) takes
-- effect on the next request without touching any session. Revocation is a
-- DELETE. Stored by the sha256 of the token, so a leaked backup hands over no
-- live session.
CREATE TABLE IF NOT EXISTS identity.sessions (
  token_hash          text        PRIMARY KEY,
  user_id             uuid        NOT NULL REFERENCES identity.users (id) ON DELETE CASCADE,
  expires_at          timestamptz NOT NULL,
  absolute_expires_at timestamptz NOT NULL,
  ip_address          text,
  user_agent          text,
  created_at          timestamptz NOT NULL DEFAULT now(),
  last_seen_at        timestamptz NOT NULL DEFAULT now()
);

CREATE INDEX IF NOT EXISTS sessions_user_idx ON identity.sessions (user_id);
-- Serves the "have we seen this device before" count on login.
CREATE INDEX IF NOT EXISTS sessions_user_agent_idx ON identity.sessions (user_id, user_agent);

-- Email verification (and the cancel-deletion token, which shares the table via
-- `purpose`). `new_email` is set when the token verifies a change of address.
CREATE TABLE IF NOT EXISTS identity.email_verification_tokens (
  token_hash text        PRIMARY KEY,
  user_id    uuid        NOT NULL REFERENCES identity.users (id) ON DELETE CASCADE,
  purpose    text        NOT NULL DEFAULT 'verify_email',
  new_email  text,
  expires_at timestamptz NOT NULL,
  created_at timestamptz NOT NULL DEFAULT now()
);

CREATE INDEX IF NOT EXISTS email_verification_user_idx
  ON identity.email_verification_tokens (user_id, purpose);

-- Password reset. One live token per user (issuing a new one deletes the old),
-- and burned on any use — success or failure — so a link cannot be replayed out
-- of a mail archive.
CREATE TABLE IF NOT EXISTS identity.password_reset_tokens (
  token_hash text        PRIMARY KEY,
  user_id    uuid        NOT NULL REFERENCES identity.users (id) ON DELETE CASCADE,
  attempts   integer     NOT NULL DEFAULT 0,
  expires_at timestamptz NOT NULL,
  created_at timestamptz NOT NULL DEFAULT now()
);

CREATE INDEX IF NOT EXISTS password_reset_user_idx
  ON identity.password_reset_tokens (user_id);
