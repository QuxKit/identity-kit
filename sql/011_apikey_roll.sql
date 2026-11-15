-- identity-kit: rolling an API key (opt-in, with 003_apikeys.sql).
--
--   psql -v ON_ERROR_STOP=1 -f sql/011_apikey_roll.sql   (after 003_apikeys.sql)
--
-- Rolling replaces a key without an outage: a new key is minted with the old
-- one's name, scopes and environment, and the old key keeps resolving until the
-- overlap the caller chose runs out (its `expires_at` is pulled in to it). The
-- two rows point at each other so a dashboard can show "replaced by …" and an
-- audit can walk a key's history. Revocation is unchanged and works at any
-- time, on either row: `revoked_at` ends an overlap early.
--
-- Additive and re-runnable.

ALTER TABLE identity.api_keys ADD COLUMN IF NOT EXISTS rolled_from uuid REFERENCES identity.api_keys (id) ON DELETE SET NULL;
ALTER TABLE identity.api_keys ADD COLUMN IF NOT EXISTS replaced_by uuid REFERENCES identity.api_keys (id) ON DELETE SET NULL;
ALTER TABLE identity.api_keys ADD COLUMN IF NOT EXISTS rolled_at   timestamptz;

-- One replacement per key: two clicks on Roll, or two operators at once, cannot
-- leave a key with two live successors.
CREATE UNIQUE INDEX IF NOT EXISTS api_keys_rolled_from_idx ON identity.api_keys (rolled_from) WHERE rolled_from IS NOT NULL;
