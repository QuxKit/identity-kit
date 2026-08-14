-- identity-kit API-key schema.
--
--   psql -v ON_ERROR_STOP=1 -f sql/003_apikeys.sql   (after 001_identity.sql)
--
-- Opt-in: only applications that import identity-kit/apikeys need this table.
--
-- A key belongs to an opaque `owner_id` and acts as its own principal — it never
-- impersonates the user who created it and never inherits a session. `owner_id`
-- is deliberately not a foreign key to identity.users: a key is often owned by an
-- organisation (a tenant-kit tenant), not a person, and identity-kit takes no
-- position on which. The host maps `owner_id` to whatever it authorizes against.
--
-- `scopes` is an opaque string array the host interprets; identity-kit only
-- authenticates the key and hands it back. Roles/permissions are tenant-kit's.

CREATE SCHEMA IF NOT EXISTS identity;

CREATE TABLE IF NOT EXISTS identity.api_keys (
  id             uuid        PRIMARY KEY DEFAULT gen_random_uuid(),
  owner_id       text        NOT NULL,
  -- sha256 of the full key, UNIQUE — the lookup is one index probe and there is
  -- no secret comparison left to make constant-time. sha256 not argon2, for the
  -- same reason as session tokens: 256 bits of entropy has nothing to guess, and
  -- a KDF on every API request is a self-inflicted denial of service.
  key_hash       text        NOT NULL UNIQUE,
  -- Non-secret. Lets a dashboard render `idk_live_k7f3q2xa…` so a customer can
  -- tell two keys apart. The full key is shown once, at creation, and is never
  -- retrievable; "reveal key" is a feature request to refuse.
  display_prefix text        NOT NULL,
  name           text        NOT NULL,
  scopes         text[]      NOT NULL DEFAULT '{}',
  created_by     text,
  expires_at     timestamptz,
  revoked_at     timestamptz,
  created_at     timestamptz NOT NULL DEFAULT now(),
  last_used_at   timestamptz
);

CREATE INDEX IF NOT EXISTS api_keys_owner_idx ON identity.api_keys (owner_id, created_at DESC);
