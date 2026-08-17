-- identity-kit security events: the account's audit trail.
--
--   psql -v ON_ERROR_STOP=1 -f sql/006_events.sql   (after 001_identity.sql)
--
-- Required by 0.3: every flow in the core and the opt-in modules records here
-- (login succeeded / failed, password changed / reset, MFA enrolled / removed,
-- API key issued / revoked, session revoked, passkey registered, magic link
-- used). `events.list(userId)` reads it back for a "recent activity" page and
-- an incident review; `sweepExpired` prunes by age.
--
-- `user_id` is text and carries no foreign key, deliberately: the API-key
-- module's owner is an opaque principal (a user id, or an organisation id — the
-- host decides), and its issue / revoke events are keyed by that owner. Purging
-- an account (`purgeUnverified` / `purgeDeleted`) deletes its events in the
-- same statement batch, so nothing dangles.
--
-- Re-runnable: every statement is guarded.

CREATE SCHEMA IF NOT EXISTS identity;

CREATE TABLE IF NOT EXISTS identity.events (
  id         bigserial   PRIMARY KEY,
  user_id    text        NOT NULL,
  kind       text        NOT NULL,
  ip         text,
  user_agent text,
  at         timestamptz NOT NULL DEFAULT now(),
  metadata   jsonb       NOT NULL DEFAULT '{}'::jsonb
);

-- Serves `events.list(userId, { before })`: newest first, keyset on (at, id).
CREATE INDEX IF NOT EXISTS events_user_at_idx ON identity.events (user_id, at DESC, id DESC);
-- Serves the retention sweep.
CREATE INDEX IF NOT EXISTS events_at_idx ON identity.events (at);
