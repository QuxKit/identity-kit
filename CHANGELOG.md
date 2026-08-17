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

### Changed

- `prepublishOnly` runs lint, typecheck, build and test.

### Fixed

### Security

## [0.1.0]

Initial release: accounts (signup, verification, login with backoff, password
reset, deletion with grace), argon2id + pepper credentials, server-side sessions
with cookie helpers, and the opt-in `mfa`, `apikeys` and `oidc` entry points.
