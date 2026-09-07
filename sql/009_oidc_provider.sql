-- Being an issuer, rather than only consuming one.
--
-- 004_oidc.sql is the client half: which external issuer an account is linked
-- to. This is the other direction. One app in a family holds the accounts, and
-- the rest sign in against it.
--
-- Three tables, and the shape of each is a security decision.
--
--   oidc_clients   who may ask. A redirect_uri is matched EXACTLY against this
--                  list, never by prefix or pattern: prefix matching is how an
--                  open redirect becomes an account takeover.
--   oidc_codes     an authorization code, hashed. A code is a bearer
--                  credential for the length of its life; storing it in the
--                  clear means a database read is a login. Single-use is
--                  enforced by a guarded UPDATE, not by a SELECT then an
--                  UPDATE, so two simultaneous redemptions cannot both win.
--   oidc_keys      the signing keys. In the database rather than an
--                  environment variable so a key can be rotated without a
--                  deploy, and so JWKS can publish the retiring one until the
--                  last token signed with it has expired.
--
-- Idempotent — safe to re-run.

CREATE SCHEMA IF NOT EXISTS identity;

CREATE TABLE IF NOT EXISTS identity.oidc_clients (
  client_id     text PRIMARY KEY,
  name          text NOT NULL,
  -- Null for a public client, which is then PKCE-only. A confidential client
  -- stores a hash: the same rule as every other credential here.
  secret_hash   text,
  redirect_uris text[] NOT NULL,
  -- First-party clients are ours, and skip consent because asking somebody to
  -- authorise us to be ourselves is theatre. Anything else is refused until
  -- there is a consent screen to show, rather than consented silently.
  first_party   boolean NOT NULL DEFAULT false,
  created_at    timestamptz NOT NULL DEFAULT now(),
  disabled_at   timestamptz,
  CONSTRAINT oidc_clients_has_redirect CHECK (cardinality(redirect_uris) > 0)
);

CREATE TABLE IF NOT EXISTS identity.oidc_codes (
  code_hash             text PRIMARY KEY,
  client_id             text NOT NULL REFERENCES identity.oidc_clients (client_id) ON DELETE CASCADE,
  user_id               uuid NOT NULL REFERENCES identity.users (id) ON DELETE CASCADE,
  -- Recorded because the token request must present the SAME redirect_uri; a
  -- code minted for one destination cannot be redeemed for another.
  redirect_uri          text NOT NULL,
  code_challenge        text NOT NULL,
  code_challenge_method text NOT NULL CHECK (code_challenge_method = 'S256'),
  nonce                 text,
  scope                 text NOT NULL DEFAULT 'openid',
  expires_at            timestamptz NOT NULL,
  consumed_at           timestamptz,
  created_at            timestamptz NOT NULL DEFAULT now()
);

CREATE INDEX IF NOT EXISTS oidc_codes_expiry ON identity.oidc_codes (expires_at);

-- The access token issued alongside the ID token, so `userinfo` is a real
-- endpoint rather than a decoration. Opaque and hashed: it is a bearer token,
-- and nothing about it needs to be readable by the client.
CREATE TABLE IF NOT EXISTS identity.oidc_access_tokens (
  token_hash text PRIMARY KEY,
  client_id  text NOT NULL REFERENCES identity.oidc_clients (client_id) ON DELETE CASCADE,
  user_id    uuid NOT NULL REFERENCES identity.users (id) ON DELETE CASCADE,
  scope      text NOT NULL DEFAULT 'openid',
  expires_at timestamptz NOT NULL,
  created_at timestamptz NOT NULL DEFAULT now()
);

CREATE INDEX IF NOT EXISTS oidc_access_tokens_expiry ON identity.oidc_access_tokens (expires_at);

CREATE TABLE IF NOT EXISTS identity.oidc_keys (
  kid         text PRIMARY KEY,
  alg         text NOT NULL,
  -- The private half never leaves the server. JWKS publishes public_jwk only.
  private_jwk jsonb NOT NULL,
  public_jwk  jsonb NOT NULL,
  created_at  timestamptz NOT NULL DEFAULT now(),
  -- A retired key still signs nothing and still verifies everything already
  -- signed, until the last such token has expired.
  retired_at  timestamptz
);

CREATE INDEX IF NOT EXISTS oidc_keys_active ON identity.oidc_keys (created_at DESC) WHERE retired_at IS NULL;
