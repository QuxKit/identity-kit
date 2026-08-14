-- identity-kit OIDC schema: linked provider identities.
--
--   psql -v ON_ERROR_STOP=1 -f sql/004_oidc.sql   (after 001_identity.sql)
--
-- Opt-in: only applications that import identity-kit/oidc need this table.
--
-- One row per (provider, subject) — the provider's stable `sub` claim. It maps a
-- provider identity to a local user. The safety of *when* a row is created lives
-- in the linking policy (src/oidc-link.ts), not here: this table only records the
-- links that policy decided were safe to make.

CREATE SCHEMA IF NOT EXISTS identity;

CREATE TABLE IF NOT EXISTS identity.oauth_identities (
  provider   text        NOT NULL,
  subject    text        NOT NULL,
  user_id    uuid        NOT NULL REFERENCES identity.users (id) ON DELETE CASCADE,
  email      text,
  created_at timestamptz NOT NULL DEFAULT now(),
  PRIMARY KEY (provider, subject)
);

CREATE INDEX IF NOT EXISTS oauth_identities_user_idx ON identity.oauth_identities (user_id);
