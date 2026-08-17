-- identity-kit passkeys (WebAuthn) schema.
--
--   psql -v ON_ERROR_STOP=1 -f sql/007_passkeys.sql   (after 001_identity.sql)
--
-- Opt-in: only applications that import identity-kit/passkeys need these tables.
--
-- A passkey is a public key the authenticator holds the private half of. The
-- server stores only the public key, so this table is not a secret store — but
-- `counter` is a security control: an assertion whose counter does not advance
-- past the stored one is a cloned authenticator or a replay, and is refused.
--
-- Challenges live server-side with a TTL, so a host holds no per-request state
-- between begin and finish, and a challenge can be used exactly once.

CREATE SCHEMA IF NOT EXISTS identity;

CREATE TABLE IF NOT EXISTS identity.passkeys (
  -- The credential id, base64url, as the browser reports it.
  id           text        PRIMARY KEY,
  user_id      uuid        NOT NULL REFERENCES identity.users (id) ON DELETE CASCADE,
  -- COSE public key bytes, as the authenticator produced them.
  public_key   bytea       NOT NULL,
  counter      bigint      NOT NULL DEFAULT 0,
  transports   text[]      NOT NULL DEFAULT '{}',
  aaguid       text,
  -- Human label ("MacBook Touch ID"); the user renames it.
  name         text        NOT NULL,
  device_type  text,
  backed_up    boolean     NOT NULL DEFAULT false,
  created_at   timestamptz NOT NULL DEFAULT now(),
  last_used_at timestamptz
);

CREATE INDEX IF NOT EXISTS passkeys_user_idx ON identity.passkeys (user_id, created_at);

-- One row per outstanding challenge, keyed by its sha256. `user_id` is set for
-- registration (and for a login begun for a named user) so the finish can refuse
-- a challenge issued to someone else. Deleted on use; `sweepExpired` prunes the
-- rest.
CREATE TABLE IF NOT EXISTS identity.webauthn_challenges (
  challenge_hash text        PRIMARY KEY,
  purpose        text        NOT NULL,
  user_id        uuid        REFERENCES identity.users (id) ON DELETE CASCADE,
  expires_at     timestamptz NOT NULL,
  created_at     timestamptz NOT NULL DEFAULT now()
);

CREATE INDEX IF NOT EXISTS webauthn_challenges_expires_idx ON identity.webauthn_challenges (expires_at);
