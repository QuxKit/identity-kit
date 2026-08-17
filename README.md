# @quxkit/identity-kit

<img src="https://raw.githubusercontent.com/QuxKit/quxkit-brand/main/identity-kit/sizes/identity-kit-128.png" width="76" align="right" alt="">

**QuxKit** · gold stone · accounts, credentials, sessions

![status](https://img.shields.io/badge/status-shipped-2ea043) ![licence](https://img.shields.io/badge/licence-Apache--2.0-d6a94b) ![npm](https://img.shields.io/badge/npm-%40quxkit%2Fidentity--kit-cb3837)

User identity and authentication as a library, for the app you already run.

```
 credentials                                  your app
 email + password                             ────────
   │                                          your database
   ▼                                          (identity schema)
 ┌──────────────────────────────────┐               ▲
 │  accounts   signup · login       │  SqlExecutor  │
 │             reset · verify       │───────────────┘
 │     │                            │
 │     ├──▶ credentials             │  MailSender
 │     │    argon2id + pepper       │───────────────▶ mail transport
 │     │                            │
 │     └──▶ sessions                │
 │          server-side, revocable  │
 └──────────────────────────────────┘
   @quxkit/identity-kit — Apache-2.0
                 │
                 ▼
              UserId        ← what the rest of the family consumes
```

_Rendered diagrams (mermaid): [docs/DIAGRAMS.md](https://github.com/QuxKit/identity-kit/blob/main/docs/DIAGRAMS.md)._

identity-kit owns the framed box: what a user **is**, how they **prove it**
(argon2id credentials, server-side sessions), and the account lifecycle around
that — signup, email verification, password reset, deletion. It produces a
`UserId` and stops there. Your app owns the database it writes to (through a
narrow executor) and the transport its mail goes out on (through a seam).

Apache-2.0, sibling to [tenant-kit](https://github.com/QuxKit/tenant-kit) and
[billing-kit](https://github.com/QuxKit/billing-kit): same executor interface,
same design rules, same "library not platform" stance.

## Where it sits in the family

tenant-kit's own README says *"your app owns everything else — its users, its
auth"*. That is the seam this fills. The three libraries layer, each consuming
the one below:

```
 @quxkit/identity-kit     who you are, and how you prove it
        │ UserId
        ▼
 @quxkit/tenant-kit       what you belong to, and what stays isolated
        │ tenantId
        ▼
 @quxkit/billing-kit      what you owe
```

A `UserId` minted here is the `userId` in a tenant-kit membership and, through
the tenant, the subject a billing-kit charge lands on. identity-kit has no
opinion about tenancy, roles or money — those are the other libraries'.

## The problem it solves

Authentication usually arrives in one of two shapes, and both put your user
model somewhere you don't control:

- **A hosted platform** — Clerk, Auth0, WorkOS — that owns your user model and
  bills per active user.
- **A service you deploy** — Ory, Keycloak, SuperTokens — that you run and
  operate as a separate system with its own database and API.

identity-kit is a third shape: **a library you embed.** Accounts, credentials
and sessions compile into the app you already run, over the Postgres you already
have. No per-user fee, no second service.

It is **not** a full identity platform, and does not try to be. OAuth/SSO/SAML
provider flows are deliberately out of scope — that is where a hosted platform
earns its keep. This is the password/session/credential core, done carefully,
with clean seams.

## Quickstart

```ts
import { createIdentity } from '@quxkit/identity-kit';

const identity = createIdentity({
  db,                                   // any SqlExecutor (a pg.Pool adapter is ~15 lines)
  mail: { send: (m) => myTransport(m) }, // you own the relay; the library writes the body
  config: {
    pepper: process.env.AUTH_PEPPER!,   // an HMAC key kept OUT of the database
    pepperVersion: 1,
    appUrl: 'https://app.example.com',
    cookieSecure: true,
  },
});

await identity.signup({ email, password });     // emails a verification link
await identity.verifyEmail(token);              // verifies — does NOT sign in
const result = await identity.login({ email, password });
if (result.kind === 'session') setCookie(identity.sessionCookie(result.token, result.expiresAt));
```

Apply the schema first: `psql -f node_modules/identity-kit/sql/001_identity.sql`.

## What it does carefully

Auth correctness is adversarial, not deterministic — you cannot unit-test your
way to "secure" — so the reasoning is in the code. The load-bearing parts:

- **Passwords** are argon2id (RFC 9106), peppered with an HMAC key the database
  never holds, so a stolen backup is not offline-crackable. `needsRehash`
  upgrades stored hashes on next login, so raising cost later forces no resets.
- **Signup and reset are enumeration-safe.** The same response, the same work
  (argon2 runs on both branches), and an email on both branches, whether or not
  the address exists — so neither the status code nor the timing reveals who has
  an account.
- **Sessions are server-side rows**, so revocation is a `DELETE` that takes
  effect on the next request. A password change or reset revokes every session;
  the row carries identity, never entitlement.
- **Reset tokens are burned on any use**, success or failure, in the same
  transaction as the password write — no replay out of a mail archive, no window
  left live by a recognised-failures-only rule.
- **Lockout is exponential backoff, not a hard lock** — a hard per-account lock
  is a denial-of-service anyone who knows an address can point at its owner.

## What it delegates

- **Mail transport** — the `MailSender` seam. The library composes every message
  (their shape is a security property); the host picks the relay.
- **MFA, API keys, and OIDC** (Google / Apple / any OpenID provider) — shipped,
  as separate opt-in entry points, the same way billing-kit splits metering from
  providers (see below).
- **SAML** — still out of scope; an enterprise-only protocol better served by a
  dedicated gateway.
- **HTTP** — no endpoints, no framework. `login` is a function; how it is routed
  and CSRF-protected is the host's. (Cookie helpers are provided, config-driven,
  and entirely optional.)

## Opt-in modules

Separate entry points, so an app that wants neither compiles neither.

### `identity-kit/mfa` — TOTP + recovery codes

```ts
import { createMfa } from '@quxkit/identity-kit/mfa';

const mfa = createMfa({ db, config, mail, totp: { key: process.env.TOTP_KEY!, keyVersion: 1, issuer: 'Acme' } });
const identity = createIdentity({ db, config, mail, secondFactor: mfa.secondFactor });
// now login() returns { kind: 'mfa_required', pendingToken } for an enrolled user
```

The TOTP secret is **encrypted** (AES-256-GCM) under a key held outside the
database — the one auth secret that cannot be one-way. `lastUsedStep` rejects a
code phished in real time from being replayed in its own window; the
pending-login state is a single-purpose table, never a half-privileged session;
guesses are bounded (five per authentication), which is what makes six digits
safe. Recovery codes are argon2id-hashed. Apply `sql/002_mfa.sql`.

### `identity-kit/apikeys` — keys as their own principal

```ts
import { createApiKeys } from '@quxkit/identity-kit/apikeys';

const keys = createApiKeys({ db, prefix: 'acme' });
const { key } = await keys.createApiKey(ownerId, { name: 'CI', scopes: ['read'] }); // shown once
const principal = await keys.resolveApiKey(presented);  // → { ownerId, scopes } or null
```

A key belongs to an opaque `ownerId` (a user *or* a tenant — the host decides)
and authenticates as it, never as the person who made it, so a leak is a scoped
incident and revocation actually undoes it. Stored as a sha256 (one index probe,
nothing to compare in constant time); a product-specific prefix + checksum lets
secret scanners revoke a leaked key before a customer notices. Roles/permissions
are the host's — identity-kit only authenticates. Apply `sql/003_apikeys.sql`.

### `identity-kit/oidc` — Sign in with Google / Apple

```ts
import { createOidc } from '@quxkit/identity-kit/oidc';

const oidc = createOidc({ db, providers: {
  google: { issuer: 'https://accounts.google.com', clientId, clientSecret, redirectUri },
} });

// route 1: start
const { url, state, nonce, codeVerifier } = await oidc.begin('google');
// stash state/nonce/codeVerifier in the session; redirect to url

// route 2: callback
const { outcome } = await oidc.complete('google', req.url, { state, nonce, codeVerifier });
if (outcome.kind === 'ok') mintSessionFor(outcome.userId);  // via the identity core
```

**The protocol is not hand-rolled** — discovery, PKCE, `state`, `nonce`, code
exchange and ID-token validation are [`openid-client`](https://github.com/panva/openid-client)'s.
What identity-kit owns is the one application-specific, takeover-critical
decision: **account linking**. The rule, tested directly against crafted claims:

- already linked (`provider` + `sub`) → that user;
- a **provider-verified** email that matches a **locally-verified** account → link
  them (both sides proved the address);
- a matching email where **either side is unverified** → **refuse** (`conflict`) —
  this is the takeover, and the host must have the user sign in the existing way
  and link from settings;
- otherwise → create a new passwordless user, verified only if the provider was.

`complete` does not mint a session — OAuth stands in for the password, not the
whole login, so the host mints the session (and decides what a new vs linked user
gets). Apply `sql/004_oidc.sql`. SAML stays out of scope.

## Schema

Everything lives in an `identity` schema so it cannot collide with a host
application's `users` table. `sql/001_identity.sql` declares `users`, `sessions`,
`email_verification_tokens` and `password_reset_tokens`; `002_mfa.sql`,
`003_apikeys.sql` and `004_oidc.sql` add the opt-in modules' tables. All cascade
on delete.

## Development

```sh
pnpm install
pnpm typecheck
createdb identity_kit_test   # the tests exercise real SQL; they skip without a DB
pnpm test
```

The tests assert the security properties against a real Postgres — the token
burned in the same transaction as the write, the unique constraint on email, the
cascade — because that behaviour is in the database, not the TypeScript.


## The QuxKit family

Libraries you embed, not services you operate. Each kit owns one narrow thing
and composes with the rest over shared shapes — one executor interface, one
opaque tenant id, one Money type.

| Package | Stone | What it owns |
|---|---|---|
| [`@quxkit/identity-kit`](https://github.com/QuxKit/identity-kit) | gold | Accounts, argon2id credentials, revocable sessions — produces a `UserId`. |
| [`@quxkit/tenant-kit`](https://github.com/QuxKit/tenant-kit) | green | Tenant directory, request→tenant resolution, row-level-security isolation. |
| [`@quxkit/billing-kit`](https://github.com/QuxKit/billing-kit) | blue | Metering, exact pricing, a double-entry ledger, provider settlement. |
| [`@quxkit/billing-kit-adapters`](https://github.com/QuxKit/billing-kit-adapters) | blue | Payment providers beyond Stripe and Paddle. |
| [`tenant-kit-adapters`](https://github.com/QuxKit/tenant-kit-adapters) | green | Enterprise SSO, SCIM provisioning, RBAC-engine bridges. |
| [`billing-kit-components`](https://github.com/QuxKit/billing-kit-components) | blue | shadcn-compatible billing UI, per seat. |
| [`@quxkit/billing-kit-mcp`](https://github.com/QuxKit/billing-kit-mcp) | blue | Exact money math for AI assistants over MCP. |

## Licence

Apache-2.0. See `LICENSE` and `NOTICE`. Ported from an internal implementation
(ai_member_cloud) to a provider-agnostic library; the security design is
preserved.
