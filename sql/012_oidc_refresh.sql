-- identity-kit: a sign-in that renews, for the issuer's phone and desktop apps.
--
--   psql -v ON_ERROR_STOP=1 -f sql/012_oidc_refresh.sql   (after 009_oidc_provider.sql)
--
-- Required by `identity-kit/provider` from this release, whether or not any
-- client uses refresh tokens: the issuer reads `allow_refresh` and
-- `family_id` on every exchange. A host that does not use the provider does not
-- need it, and the core checks for these tables before touching them.
--
-- 009 issued a five-minute access token and nothing that outlives it, which is
-- right for a web app that mints its own session and wrong for a phone app,
-- which would send its owner back through the browser every five minutes. This
-- adds the refresh token, opt-in per client, and the shape of each table is a
-- security decision.
--
--   oidc_refresh_families   one row per sign-in on a device: the thing a person
--                           sees in a list of devices and the thing that is
--                           revoked. Bound to one client and one user. The
--                           absolute expiry lives here and is never extended.
--   oidc_refresh_tokens     the chain of tokens within a family. Each refresh
--                           retires the presented token and adds its successor,
--                           so exactly one token per family is current. A
--                           retired row is KEPT for the life of the family: it
--                           is how a replayed token is recognised as a replay
--                           (and the family revoked) rather than as noise.
--
-- Tokens are stored as sha256, like every other bearer credential here.
-- `sealed_successor` is not an exception: it is the successor encrypted under a
-- key derived from the retired token's PLAINTEXT, which this database never
-- holds. It lets a retry of a refresh whose response was lost be answered with
-- the same successor, and is useless to anyone reading the table.
--
-- Additive and re-runnable.

CREATE SCHEMA IF NOT EXISTS identity;

-- Off unless an operator turns it on for a client. Only a first-party client
-- may have it: a refresh token is standing access, and there is no consent
-- screen on which a third party could be granted that.
ALTER TABLE identity.oidc_clients ADD COLUMN IF NOT EXISTS allow_refresh boolean NOT NULL DEFAULT false;

DO $$
BEGIN
  IF NOT EXISTS (SELECT 1 FROM pg_constraint WHERE conname = 'oidc_clients_refresh_first_party') THEN
    ALTER TABLE identity.oidc_clients ADD CONSTRAINT oidc_clients_refresh_first_party
      CHECK (NOT allow_refresh OR first_party);
  END IF;
END;
$$;

CREATE TABLE IF NOT EXISTS identity.oidc_refresh_families (
  id                  uuid PRIMARY KEY DEFAULT gen_random_uuid(),
  client_id           text NOT NULL REFERENCES identity.oidc_clients (client_id) ON DELETE CASCADE,
  user_id             uuid NOT NULL REFERENCES identity.users (id) ON DELETE CASCADE,
  scope               text NOT NULL,
  -- What the app called the device at sign-in ("Ada's iPhone"). Shown back to
  -- the person in their list of devices; never trusted for anything.
  device_label        text,
  created_at          timestamptz NOT NULL,
  last_used_at        timestamptz NOT NULL,
  -- From the sign-in, never moved. A family refreshed forever is a sign-in
  -- never revoked.
  absolute_expires_at timestamptz NOT NULL,
  revoked_at          timestamptz,
  -- Why, for the incident review: reuse, revoked, signed_out, password_changed,
  -- password_reset, email_changed, account, client.
  revoked_reason      text
);

-- Serves the list of a person's devices and "revoke everything of theirs".
CREATE INDEX IF NOT EXISTS oidc_refresh_families_user ON identity.oidc_refresh_families (user_id) WHERE revoked_at IS NULL;
CREATE INDEX IF NOT EXISTS oidc_refresh_families_expiry ON identity.oidc_refresh_families (absolute_expires_at);

CREATE TABLE IF NOT EXISTS identity.oidc_refresh_tokens (
  token_hash       text PRIMARY KEY,
  family_id        uuid NOT NULL REFERENCES identity.oidc_refresh_families (id) ON DELETE CASCADE,
  -- The token this one replaced; null for the one issued at sign-in. Not a
  -- foreign key: it is a hash to look a successor up by, nothing more.
  parent_hash      text,
  created_at       timestamptz NOT NULL,
  -- The idle expiry: a token nobody presents by this time is dead, and so is
  -- its family, since it holds the only current token.
  expires_at       timestamptz NOT NULL,
  -- Set once, when it is exchanged. A row with this set is retired, and
  -- presenting it again is the reuse that revokes the family.
  rotated_at       timestamptz,
  -- See the header. Cleared as soon as the successor is itself used.
  sealed_successor text
);

-- One successor per token: two requests racing on the same token cannot leave
-- a family with two current tokens.
CREATE UNIQUE INDEX IF NOT EXISTS oidc_refresh_tokens_parent ON identity.oidc_refresh_tokens (parent_hash) WHERE parent_hash IS NOT NULL;
CREATE INDEX IF NOT EXISTS oidc_refresh_tokens_family ON identity.oidc_refresh_tokens (family_id);

-- An access token issued to a family dies with it. Null for the tokens of a
-- client without refresh tokens, which are exactly what they were.
ALTER TABLE identity.oidc_access_tokens ADD COLUMN IF NOT EXISTS family_id uuid REFERENCES identity.oidc_refresh_families (id) ON DELETE CASCADE;
CREATE INDEX IF NOT EXISTS oidc_access_tokens_family ON identity.oidc_access_tokens (family_id) WHERE family_id IS NOT NULL;
