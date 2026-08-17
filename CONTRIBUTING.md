# Contributing

## Dev setup

```sh
pnpm install
createdb identity_kit_test        # the tests exercise real SQL against this DB
pnpm test
```

Node >= 20.19 and PostgreSQL >= 13 (`gen_random_uuid`). The suites connect to
`postgres://localhost:5432/identity_kit_test` by default; point
`IDENTITY_KIT_TEST_DATABASE_URL` elsewhere if yours differs. Without a reachable
database the DB-backed suites **skip** locally; set `REQUIRE_DB=1` (CI does) to
make that a failure instead.

## Scripts

| Script                | What it does                                              |
| --------------------- | --------------------------------------------------------- |
| `pnpm lint`           | Biome — lint + format check                               |
| `pnpm format`         | Biome — write formatting                                  |
| `pnpm typecheck`      | `tsc --noEmit`                                            |
| `pnpm build`          | tsup → `dist/` (ESM + CJS + d.ts)                         |
| `pnpm test`           | every `test/*.test.ts` against the real DB                |
| `pnpm test:coverage`  | the same under c8; thresholds in `.c8rc.json` are a floor |

Coverage thresholds only ratchet up: if you raise real coverage, raise the
numbers (rounded down to a 5) in the same PR.

## Workflow: issue → branch → PR

Every change starts as an issue that states the problem (not the solution),
gets a branch named `<type>/<issue>-<slug>`, and lands through a pull request.
Nothing goes to `main` directly.

- Commit subjects are conventional-commit style (`feat:`, `fix:`, `test:`,
  `docs:`, `chore:`, `ci:`, `style:`); the body says why.
- **Run `pnpm lint && pnpm typecheck && pnpm build && pnpm test` before
  pushing.** CI runs the same set with coverage.
- Every behavioural fix ships with a test that failed before it. Never weaken
  or skip a test to go green.
- Public API changes are additive; a new error code goes into the
  `IdentityFailure` union and the README's errors table.

## Ground rules for this library

- No `process.env` reads inside `src/`; config is injected.
- Errors are the `IdentityError` union, never a message string to match on.
- SQL lives in the `identity` schema; every migration in `sql/` is re-runnable.
- README diagrams are ASCII; mermaid goes in `docs/DIAGRAMS.md`.
