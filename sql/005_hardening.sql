-- identity-kit hardening: an atomic failure counter, a rate-limit table, and
-- the moment a session last proved a credential.
--
--   psql -v ON_ERROR_STOP=1 -f sql/005_hardening.sql   (after 001_identity.sql)
--
-- Required by 0.2: the core reads users.last_failed_at, sessions.authenticated_at
-- and (unless the limiter is disabled) identity.rate_limits.
--
-- Re-runnable: every statement is guarded.

CREATE SCHEMA IF NOT EXISTS identity;

-- The failure counter is now incremented in place (`failed_logins + 1 …
-- RETURNING`) rather than read-then-written, so concurrent wrong passwords cannot
-- lose increments. `last_failed_at` records when.
ALTER TABLE identity.users ADD COLUMN IF NOT EXISTS last_failed_at timestamptz;

-- When the session's holder last proved a credential (login, or a password
-- change / re-authentication on this session). Rotation carries it forward;
-- MFA enrolment refuses a session whose proof is older than the reauth window.
ALTER TABLE identity.sessions
  ADD COLUMN IF NOT EXISTS authenticated_at timestamptz NOT NULL DEFAULT now();

-- Token buckets for the rate limiter. One row per key; refilled lazily on hit,
-- in a single INSERT … ON CONFLICT DO UPDATE … RETURNING, so a burst from many
-- workers is counted exactly. `sweepExpired` prunes rows idle for a day.
CREATE TABLE IF NOT EXISTS identity.rate_limits (
  key        text             PRIMARY KEY,
  tokens     double precision NOT NULL,
  updated_at timestamptz      NOT NULL
);

CREATE INDEX IF NOT EXISTS rate_limits_updated_idx ON identity.rate_limits (updated_at);
