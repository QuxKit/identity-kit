-- identity-kit magic-link schema: passwordless email sign-in.
--
--   psql -v ON_ERROR_STOP=1 -f sql/008_magic.sql   (after 001_identity.sql)
--
-- Opt-in: only applications that import identity-kit/magic need this table.
--
-- One live token per user (requesting a new one deletes the old), fifteen
-- minutes, stored as a sha256 — a magic link IS a credential, so it gets the
-- reset token's treatment: burned on any use, in the same transaction as the
-- session it mints.

CREATE SCHEMA IF NOT EXISTS identity;

CREATE TABLE IF NOT EXISTS identity.magic_link_tokens (
  token_hash text        PRIMARY KEY,
  user_id    uuid        NOT NULL REFERENCES identity.users (id) ON DELETE CASCADE,
  expires_at timestamptz NOT NULL,
  created_at timestamptz NOT NULL DEFAULT now()
);

CREATE INDEX IF NOT EXISTS magic_link_user_idx ON identity.magic_link_tokens (user_id);
