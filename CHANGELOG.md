# Changelog

All notable changes to this project are documented here. The format follows
[Keep a Changelog](https://keepachangelog.com/en/1.1.0/) and the project uses
[Semantic Versioning](https://semver.org/).

## [Unreleased]

### Added

- `IdentityConfig.registration` closes account creation — `'open'` (the default,
  so nothing changes for an existing host), `'closed'`, or a function asked per
  attempt. Honoured on BOTH doors into `identity.users`: `signup`, and the
  new-user branch of `linkOrCreate`. Existing accounts sign in either way —
  closing registration locks the door, it does not evict anyone.
- `identity.linkOrCreate(claims, now?)` on the instance, which passes the
  configured policy for you. Prefer it over the free function in
  `identity-kit/oidc`: an optional argument on the path hosts think of as
  "logging in" is how social sign-in quietly keeps creating accounts after
  signups were closed.
- `SignupInput.invite`, passed through untouched to the `registration` policy.
  This kit has no invite store and never validates one, which is why
  invite-only is a function rather than a mode. `POST /signup` forwards a body
  `invite` field.
- `registration_closed` failure code (HTTP 403), the `LinkResult` variant
  `{ kind: 'registration_closed' }`, and the `registrationPolicy` /
  `assertRegistrationAllowed` helpers.

### Note for hosts calling `linkOrCreate` directly

Its new fourth argument is optional, so existing calls compile unchanged — and
keep creating accounts whatever `registration` says. Switch to
`identity.linkOrCreate(...)`, or pass `{ registration: config.registration }`.

## [0.2.0] - 2026-08-17

### Fixed

- `signup` stamps `identity.users.created_at` from the injected `clock` instead of
  letting it default to the database's `now()`. The two clocks could disagree, so
  `purgeUnverified` — which derives its cutoff from the injected clock — silently
  deleted nothing and unverified accounts accumulated. A regression test pins the
  stamp and both sides of the window.

### Added

- **Breached-password screening (opt-in)** — `passwordBreached(fetch, { endpoint?,
  strict?, padding?, timeoutMs? })` implements the k-anonymity range API (SHA-1
  computed locally, five hex characters sent, suffixes matched in process) and is
  wired in through `config.breachedPasswords`; `signup`, `resetPassword` and
  `changePassword` then refuse a breached password as `weak_password`. Fails open
  unless `strict`. New `passwordProblemAsync(config, password)`; `passwordProblem`
  is unchanged for the local rules.

- `oidc`: provider flags `allowInsecureRequests` (loopback-only `http://`, for a
  local Keycloak / Dex; anything else is `invalid_config`) and
  `verifyIdTokenSignature` (JWS validation against the provider's JWKS — off by
  default per OIDC Core 3.1.3.7, forced on when `allowInsecureRequests` is set).
  `oidc.begin` / `complete` are now exercised end to end against an in-process
  mock issuer (`test/mock-issuer.ts`, RS256 via `node:crypto`, no new
  dependency), including PKCE / state / nonce mismatches, a wrong signing key,
  a missing nonce claim and the account-takeover refusal.

- **`@quxkit/identity-kit/http`** — `routes({ identity, config, mfa?, apiKeys?,
  magic?, passkeys?, basePath?, csrf? })`: framework-neutral handlers
  (`{ method, path, headers, body, ip }` → `{ status, headers, body }`, `null`
  to fall through) for signup, verify, resend, login, logout, session, csrf,
  password reset request/confirm, password change, MFA begin/confirm/verify/
  remove, API-key create/list/revoke, magic request/consume and passkey
  register/authenticate/list/remove. Session cookies (including rotation) and
  `Authorization: Bearer` handled; `IdentityError` → status codes with the
  limiter key stripped. CSRF double-submit helper (`createCsrf`, `GET /csrf`,
  `csrf: true`). Adapters `nodeListener` (with `trustProxy`, a 413 body cap),
  `expressHandler`, `honoHandler`, typed against local interfaces — no
  framework dependency.

- **`@quxkit/identity-kit/magic`** — passwordless sign-in: `request({ email,
  ipAddress })` (enumeration-safe, rate-limit action `magic_link` 5/hour, one
  live token per user, 15-minute TTL, sha256 at rest, verified accounts only)
  and `consume({ token }, meta)` → session via `finishLogin` (`via:
  'magic_link'`), `mfa_required` when a second factor is wired, or `invalid`;
  event `magic_link_used`; `sweep`. Table `identity.magic_link_tokens`
  (`sql/008_magic.sql`); `SweepReport.magicLinkTokens`. `Mailer.magicLink` /
  `magicLinkUnknownAddress`.

- **`@quxkit/identity-kit/passkeys`** — WebAuthn over `@simplewebauthn/server`
  (a runtime dependency of this subpath; external in the build):
  `registerBegin` (recent-auth `EnrolmentProof`, shared with MFA via the new
  `reauth.ts`) / `registerFinish`, `authenticateBegin` (named user or
  discoverable) / `authenticateFinish` (through `finishLogin`, `via:
  'passkey'`), `list` / `rename` / `remove`, `sweepChallenges`. Tables
  `identity.passkeys` and `identity.webauthn_challenges`
  (`sql/007_passkeys.sql`); challenges are sha256 at rest with a TTL and spent
  on use. Typed errors `invalid_challenge`, `passkey_verification_failed`,
  `passkey_counter_regression`; rate-limit action `passkey_auth` (20/min per
  ip); `SweepReport.webauthnChallenges`. Events `passkey_registered` /
  `passkey_removed`. Tests drive a software authenticator (`test/soft-authenticator.ts`).

- **Security-events log** — `identity.events` (`sql/006_events.sql`,
  **required**): `login_succeeded` / `login_failed` (with a reason),
  `password_changed` / `password_reset`, `session_revoked`, `mfa_enrolled` /
  `mfa_removed`, `api_key_issued` / `api_key_revoked`, `passkey_registered` /
  `passkey_removed`, `magic_link_used`, each with `ip`, `user_agent`, `at`,
  `metadata`. Every existing flow records; `identity.events.list(userId,
  { limit, before })`, `.record`, `.sweep`; free functions `recordEvent`,
  `listEvents`, `sweepEvents`, `deleteEventsFor`; `config.eventRetentionMs`
  (default 90 days) applied by `sweepExpired()` (`SweepReport.events`).
  Optional trailing `meta: SessionMeta` on `changePassword`, `resetPassword`,
  `revokeSession`, `revokeAllSessions`, `confirmTotpEnrolment`, `removeTotp`,
  `revokeApiKey`, and `CreateApiKeyInput.meta`. `finishLogin` takes a
  `LoginMethod` recorded as `metadata.via`. Purges delete the account's events.

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
