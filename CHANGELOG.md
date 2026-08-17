# Changelog

All notable changes to this project are documented here. The format follows
[Keep a Changelog](https://keepachangelog.com/en/1.1.0/) and the project uses
[Semantic Versioning](https://semver.org/).

## [Unreleased]

### Added

- `@quxkit/identity-kit/pg` — `pgExecutor(pool)`, the shipped node-postgres
  adapter (pinned-connection transactions, savepoints for nesting). `pg` is an
  optional peer dependency.
- `examples/password-login` — a runnable end-to-end quickstart.
- Portable CI (`.github/workflows/ci.yml`, Node 20/22, postgres:16 service) and a
  path-independent Gitea workflow; `release.yml` publishes with provenance on a
  `v*` tag; Dependabot; `CODEOWNERS`.
- Biome (`pnpm lint`, `pnpm format`) and c8 coverage (`pnpm test:coverage`) with
  ratcheting thresholds.
- `SECURITY.md`, `CONTRIBUTING.md`, this changelog.
- Test harness: `REQUIRE_DB=1` makes an unreachable database a failure instead
  of a skip; a database-free sanity suite for the harness itself.
- **Rate limiter seam** — `RateLimiter { hit(key, cost?) }` with a Postgres
  token bucket (`createPgRateLimiter`, table `identity.rate_limits`) and a
  memory one (`createMemoryRateLimiter`); applied to signup, login (address +
  IP), reset request, verification resend and MFA verify; `DEFAULT_RATE_LIMITS`;
  `rateLimiter: null` disables. Typed error `rate_limited` with `retryAfterMs`.
- `resendVerification(email)` — a fresh link for an unverified account,
  enumeration-safe.
- **Session rotation** — `rotateSession(token)`; `config.rotateSessions`
  rotates on sliding renewal (`ResolvedSession.rotated`) and on password / MFA
  change of the current session; `ResolvedSession.authenticatedAt`.
- `sweepExpired()` — sessions, reset + verification tokens, pending logins,
  idle rate-limit buckets in one call (`SweepReport`).
- `config.previousPeppers` — a pepper keyring so rotation actually works
  (an old-version hash verifies and is re-peppered on login).
- `totp.previousKeys` — a seal-key keyring; secrets are re-sealed under the
  current `keyVersion` on the next successful verification. Typed error
  `totp_key_version`.
- `apikeys`: `ApiKeySummary.revokedAt`; `revokeApiKey(id, now?)`.
- `sql/005_hardening.sql` — `users.last_failed_at`, `sessions.authenticated_at`,
  `identity.rate_limits`. **Required** by this version.
- New `IdentityError` codes: `rate_limited`, `reauth_required`,
  `invalid_config`, `enrolment_not_started`, `invalid_code`,
  `totp_key_version`, `unknown_provider`, `no_id_token`; README errors table.

### Changed

- `prepublishOnly` runs lint, typecheck, build and test.
- **`beginTotpEnrolment(userId, proof)`** now requires proof of recent
  authentication — `{ password }` or `{ sessionToken }` within
  `config.reauthWindowMs` (default 10 min) — and throws `reauth_required`
  otherwise. This is the one intentional signature change.
- `confirmTotpEnrolment` returns `{ recoveryCodes, rotated? }` (was
  `string[]`) and, with `removeTotp`, takes an optional `keepSessionHash`
  that survives (rotated) instead of everything being revoked.
- `changePassword` returns `PasswordChanged` (`{ rotated? }`; was `void`) and
  takes an optional `now`.
- `revokeApiKey` is a soft revoke (`revoked_at`), the row stays for audit.
- The nine bare `throw new Error` in mfa / apikeys / oidc are `IdentityError`s.

### Fixed

- The failed-login counter is incremented atomically (`failed_logins + 1 …
  RETURNING`); concurrent wrong passwords no longer lose increments, and
  `locked_until` only ever moves later.
- `pepper_version` was swallowed by `verifyPassword`'s catch and reported as
  a wrong password; it now surfaces as documented.
- Signup checks the limiter and the existing address before any hashing; the
  taken-address path burns a dummy verification so timing stays equal.

### Security

- Recovery-code verification checks every unused code (no early break).
- MFA enrolment requires recent authentication (above).
- Session identifiers rotate on privilege change and, opt-in, on renewal.

## [0.1.0]

Initial release: accounts (signup, verification, login with backoff, password
reset, deletion with grace), argon2id + pepper credentials, server-side sessions
with cookie helpers, and the opt-in `mfa`, `apikeys` and `oidc` entry points.
