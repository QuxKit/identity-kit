-- identity-kit MFA schema: the second factor.
--
--   psql -v ON_ERROR_STOP=1 -f sql/002_mfa.sql   (after 001_identity.sql)
--
-- Opt-in: only applications that import identity-kit/mfa need these tables.

CREATE SCHEMA IF NOT EXISTS identity;

-- The state between "password correct" and "second factor correct".
--
-- A separate table, not a half-privileged session with an `mfa_pending` flag:
-- a token that only verifyTotp/verifyRecoveryCode ever look up is structurally
-- incapable of authenticating anything else, so no endpoint has to remember to
-- reject it. `attempts` bounds the guesses per password authentication, which is
-- what makes six digits safe.
CREATE TABLE IF NOT EXISTS identity.pending_logins (
  token_hash text        PRIMARY KEY,
  user_id    uuid        NOT NULL REFERENCES identity.users (id) ON DELETE CASCADE,
  attempts   integer     NOT NULL DEFAULT 0,
  expires_at timestamptz NOT NULL,
  created_at timestamptz NOT NULL DEFAULT now()
);

CREATE INDEX IF NOT EXISTS pending_logins_user_idx ON identity.pending_logins (user_id);

-- One TOTP factor per user.
--
-- The secret is ENCRYPTED (AES-256-GCM), not hashed, because verification needs
-- the plaintext — the one auth secret that cannot be one-way, and therefore the
-- one that most needs a key the database leak does not include. `last_used_step`
-- is the highest TOTP counter already accepted: rejecting anything <= it stops a
-- code phished in real time from being replayed inside its own 90-second window.
-- `confirmed_at` is set only after a code verifies, so a mis-scanned QR does not
-- brick the account behind a secret the user does not hold.
CREATE TABLE IF NOT EXISTS identity.totp_factors (
  user_id        uuid        PRIMARY KEY REFERENCES identity.users (id) ON DELETE CASCADE,
  secret_cipher  bytea       NOT NULL,
  secret_iv      bytea       NOT NULL,
  secret_tag     bytea       NOT NULL,
  key_version    integer     NOT NULL DEFAULT 1,
  last_used_step bigint      NOT NULL DEFAULT 0,
  confirmed_at   timestamptz,
  created_at     timestamptz NOT NULL DEFAULT now()
);

-- Recovery codes, argon2id-hashed like passwords (they get transcribed and
-- pasted, and are verified a handful of times per account per lifetime, so the
-- stronger hash is free). Regenerating deletes the old set.
CREATE TABLE IF NOT EXISTS identity.recovery_codes (
  id         uuid        PRIMARY KEY DEFAULT gen_random_uuid(),
  user_id    uuid        NOT NULL REFERENCES identity.users (id) ON DELETE CASCADE,
  code_hash  text        NOT NULL,
  used_at    timestamptz,
  created_at timestamptz NOT NULL DEFAULT now()
);

CREATE INDEX IF NOT EXISTS recovery_codes_user_idx ON identity.recovery_codes (user_id, used_at);
