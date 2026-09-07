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
import { pgExecutor } from '@quxkit/identity-kit/pg';   // the shipped node-postgres adapter
import pg from 'pg';

const identity = createIdentity({
  db: pgExecutor(new pg.Pool({ connectionString: process.env.DATABASE_URL })),
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

Apply the schema first: `psql -f node_modules/@quxkit/identity-kit/sql/001_identity.sql`,
`sql/005_hardening.sql` and `sql/006_events.sql` (all re-runnable; see [Schema](#schema)).

`db` is any `SqlExecutor` — two methods, `query` and `transaction`. The `./pg`
subpath ships one over a `pg.Pool` (pinned-connection transactions, savepoints
for nesting); `pg` is an optional peer dependency, so an app on another driver
pays nothing for it. A runnable end-to-end version of this quickstart lives in
[`examples/password-login`](examples/password-login/).

## What it does carefully

Auth correctness is adversarial, not deterministic — you cannot unit-test your
way to "secure" — so the reasoning is in the code. The load-bearing parts:

- **Passwords** are argon2id (RFC 9106), peppered with an HMAC key the database
  never holds, so a stolen backup is not offline-crackable. `needsRehash`
  upgrades stored hashes on next login, so raising cost later forces no resets.
  Rules follow NIST SP 800-63B — a length floor, no composition theatre — with
  an optional [breached-password screen](#breached-passwords).
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
  The failure counter is incremented in place (`failed_logins + 1 … RETURNING`),
  so concurrent wrong passwords all count.
- **A rate limiter sits in front of the expensive paths** — signup, login
  (keyed by address + IP), reset request, verification resend, MFA verify — and
  runs before any hashing, so a limited request costs the server nothing. See
  [Rate limiting](#rate-limiting).
- **Sessions can rotate** — `rotateSession(token)` gives a live session a fresh
  identifier; with `rotateSessions: true` the sliding renewal and a password or
  MFA change on the current session rotate it automatically. See
  [Session rotation](#session-rotation).
- **MFA enrolment needs recent authentication** — a password, or a session that
  proved one inside `reauthWindowMs` (default ten minutes) — so a hijacked
  browser session cannot quietly enrol an attacker's authenticator.
- **Every flow leaves a security event** — logins (and failed ones), password
  changes and resets, MFA enrolled / removed, API keys issued / revoked,
  sessions revoked — with the request's ip and user agent, readable per user.
  See [Security events](#security-events).

## What it delegates

- **Mail transport** — the `MailSender` seam. The library composes every message
  (their shape is a security property); the host picks the relay.
- **MFA, passkeys, magic links, API keys, and OIDC** (Google / Apple / any
  OpenID provider) — shipped, as separate opt-in entry points, the same way billing-kit splits metering from
  providers (see below). `identity-kit/provider` is the other direction: being
  the issuer other apps sign in against (see [Being the issuer](#being-the-issuer)).
- **SAML** — still out of scope; an enterprise-only protocol better served by a
  dedicated gateway.
- **HTTP** — the core is functions, not endpoints. If you want the endpoints,
  `identity-kit/http` ships them framework-neutrally with adapters for
  `node:http`, Express and Hono; see [Mount it](#mount-it). Routing, TLS and the
  server are still the host's.

## Being the issuer

`identity-kit/oidc` signs your users in against somebody else. `identity-kit/provider`
lets your app be the somebody else — one app in a family holds the accounts and
the rest sign in against it, over the same protocol, using the client half this
kit already ships.

```ts
import { createOidcIssuer } from '@quxkit/identity-kit/provider';

const issuer = createOidcIssuer({ db, issuer: 'https://accounts.example.com' });

await issuer.registerClient({
  clientId: 'portal',
  name: 'The storefront',
  secret: process.env.PORTAL_CLIENT_SECRET,   // omit for a public client
  redirectUris: ['https://example.com/api/auth/callback'],
  firstParty: true,
});
```

Your `/authorize` route resolves **your own** session and hands the user id over;
the provider never reads a cookie, because whose session it is belongs to the
host, not to the protocol:

```ts
const { redirectTo } = await issuer.authorize({
  clientId, redirectUri, userId: session.userId,
  state, nonce, codeChallenge, codeChallengeMethod: 'S256',
});
return Response.redirect(redirectTo, 303);
```

Apply `sql/009_oidc_provider.sql`, serve `issuer.discovery()` at
`/.well-known/openid-configuration`, `issuer.jwks()`, and routes for
`issuer.token()` and `issuer.userinfo()`.

### What it deliberately is not

| | |
|---|---|
| No refresh tokens | The consuming app exchanges the code, reads the ID token and mints **its own** session. Nothing needs a credential that outlives that exchange, and a refresh token is a long-lived bearer credential to store, rotate and revoke. |
| No implicit or hybrid flow | Both hand tokens to a browser through a URL. |
| No consent screen, so no third parties | A `firstParty` client skips consent, because asking somebody to authorise you to be yourself is theatre. Any other client is **refused** rather than silently consented on a user's behalf. |
| No dynamic registration | Clients are rows an operator writes. |

PKCE is **required** of every client, confidential ones included: a client secret
protects the token request, while PKCE protects the code, and the code is the part
that travels through a browser. `redirect_uri` is matched exactly, never by prefix —
prefix matching is how an open redirect becomes an account takeover. Codes are
hashed at rest, live 60 seconds, and are consumed by a guarded `UPDATE`, so two
simultaneous redemptions cannot both win.

Signing keys live in the database, not an environment variable, so `rotateKey()`
needs no deploy. A retired key stays published in JWKS until `sweep()` drops it,
which is after anything it signed has expired.

## Rate limiting

```ts
import { createIdentity, createMemoryRateLimiter, createPgRateLimiter } from '@quxkit/identity-kit';

createIdentity({ db, mail, config });                       // default: Postgres token bucket over `db`
createIdentity({ db, mail, config, rateLimiter: null });    // off
createIdentity({ db, mail, config, rateLimiter: createMemoryRateLimiter() });   // single process / tests
createIdentity({ db, mail, config, rateLimiter: createPgRateLimiter({ db, rules: { login: { limit: 5, windowMs: 60_000 } } }) });
```

The seam is `RateLimiter { hit(key, cost?) -> { allowed, retryAfterMs } }`;
bring your own (Redis, an edge limiter) by implementing it. Keys are
`<action>:<subject>` and the action picks the rule, so one limiter covers every
path. Defaults (`DEFAULT_RATE_LIMITS`): signup 10/hour, login 10/5 min per
address + IP, reset request 5/hour, verification resend 5/hour, MFA verify
10/min per user, passkey assertion 20/min per IP, magic-link request 5/hour per
address + IP (`createMfa`, `createPasskeys` and `createMagic` take the same
`rateLimiter` option). A refused hit throws `IdentityError` with code `rate_limited`
and `retryAfterMs`. Pass the caller's IP as `SignupInput.ipAddress` and
`SessionMeta.ipAddress` so the keys include it. The Postgres implementation
needs `sql/005_hardening.sql`; `sweepExpired()` prunes idle buckets.

## Breached passwords

```ts
import { createIdentity, passwordBreached } from '@quxkit/identity-kit';

createIdentity({ db, mail, config: { ...config, breachedPasswords: passwordBreached(fetch) } });
// signup / resetPassword / changePassword now refuse a password seen in a breach
```

NIST SP 800-63B asks for no composition rules **and** screening against known
breaches; `passwordProblem` was only doing the first half. `passwordBreached`
does the second by k-anonymity: SHA-1 is computed locally, only the **first five
hex characters** go out, the API returns every suffix in that bucket and the
match is made in process — the password never leaves it. `fetch` is injected
rather than imported, so it is visible in your code that this makes a network
call, and you choose the endpoint (`endpoint`, for a self-hosted mirror), the
timeout (`timeoutMs`, default 2500 ms) and the response padding (`padding`,
default on).

It **fails open**: an unreachable API answers "not known to be breached", because
a third party being down must not take signup, reset and password change with it.
`strict: true` inverts that. Screening gates *setting* a password, never
*authenticating* with one — someone whose password appears in a breach must
still be able to sign in to change it. `passwordProblemAsync(config, password)`
is the whole check if you want to run it yourself.

## Session rotation

`identity.rotateSession(token)` returns a new token for the same session (same
user, expiry, metadata) and kills the old one at once. With
`config.rotateSessions: true`:

- `resolveSession` rotates when it renews the idle window and returns the new
  token as `rotated` — **set it as the cookie**; `tokenHash` is already the new
  hash;
- `changePassword(..., keepSessionHash)` rotates the kept session and returns it
  as `rotated`, with `authenticatedAt` refreshed.

`confirmTotpEnrolment` / `removeTotp` take a `keepSessionHash` too and always
rotate it (they used to revoke everything). The flag defaults to off so a host
that ignores the return values keeps working; turn it on once yours re-sets the
cookie.

## Mount it

```ts
import { routes, nodeListener } from '@quxkit/identity-kit/http';   // also: expressHandler, honoHandler

const auth = routes({ identity, config, mfa, apiKeys, magic, passkeys, basePath: '/auth', csrf: true });

// node:http
const listener = nodeListener(auth, { trustProxy: true });
http.createServer(async (req, res) => { if (await listener(req, res)) return; myApp(req, res); });

// Express (after express.json())     // Hono
app.use(expressHandler(auth));        // app.all('/auth/*', honoHandler(auth));
```

`routes()` returns `handle(req) -> res | null`, over plain shapes — `{ method,
path, headers, body, ip }` in, `{ status, headers, body }` out — so no framework
is imported and a host on something else writes ten lines. `null` means "not one
of mine": fall through. Endpoints (under `basePath`):

| | |
|---|---|
| `POST /signup` · `POST /verify` · `POST /verify/resend` | account |
| `POST /login` · `POST /logout` · `GET /session` · `GET /csrf` | session |
| `POST /password/reset/request` · `/password/reset/confirm` · `/password/change` | passwords |
| `POST /mfa/begin` · `/mfa/confirm` · `/mfa/verify` · `/mfa/remove` | with `mfa` |
| `GET|POST /apikeys` · `DELETE /apikeys/:id` | with `apiKeys` |
| `POST /magic/request` · `/magic/consume` | with `magic` |
| `POST /passkeys/register/begin|finish` · `GET /passkeys` · `DELETE /passkeys/:id` · `POST /passkeys/authenticate/begin|finish` | with `passkeys` |

Only the modules you pass are mounted; the rest of the paths stay unclaimed.
The session cookie is set and cleared for you (a rotated session comes back as a
new `Set-Cookie` automatically), and `Authorization: Bearer <session token>` is
accepted for SPAs that hold the token themselves. `IdentityError`s become status
codes — `rate_limited` → 429 with `Retry-After`, `reauth_required` → 401,
`bad_credentials` → 403, `weak_password` → 400 — with the limiter key stripped,
since it can carry an email. Anything else propagates to your error handler.

**CSRF** is a double-submit token: `GET /csrf` sets a readable
`__Host-csrf` cookie and returns the same value to echo as `x-csrf-token` (or
`_csrf` in the body). `csrf: true` requires it on every non-GET; it is off by
default because `SameSite=Lax` already blocks cross-site POST. `createCsrf(config)`
is exported for hosts that route themselves.

## Security events

```ts
const recent = await identity.events.list(userId, { limit: 50 });          // newest first
const older  = await identity.events.list(userId, { before: recent.at(-1)!.at });
// [{ id, userId, kind: 'login_succeeded', ip, userAgent, at, metadata: { via: 'password' } }, ...]

await identity.events.record({ userId, kind: 'session_revoked', meta: { ipAddress, userAgent } });
await identity.events.sweep();     // older than config.eventRetentionMs (default 90 days)
```

`identity.events` (table `identity.events`, `sql/006_events.sql`, **required**)
is the account's audit trail. Every flow appends a row: `login_succeeded`
(`metadata.via`: `password` / `totp` / `recovery_code` / `magic_link` /
`passkey`), `login_failed` (`metadata.reason`: `bad_password` / `backoff` /
`unverified` / `deletion_pending` — never for an unknown address, so the log
cannot be read as a list of who has an account), `password_changed`,
`password_reset`, `session_revoked` (`metadata.count`), `mfa_enrolled` /
`mfa_removed`, `api_key_issued` / `api_key_revoked` (keyed by the key's
`ownerId`), `passkey_registered` / `passkey_removed`, `magic_link_used`. Where a
mutation is transactional the event commits with it.

Pass the request's `SessionMeta` (`ipAddress`, `userAgent`) to have it on the
row: `login(input, meta)`, `changePassword(..., meta)`, `resetPassword(...,
meta)`, `revokeSession(hash, meta)`, `confirmTotpEnrolment(..., meta)`,
`removeTotp(..., meta)`, `createApiKey(owner, { meta })`, `revokeApiKey(id, now,
meta)`. Never a secret, a token or a password in `metadata`. The free functions
`recordEvent` / `listEvents` / `sweepEvents` take a `db` for use outside
`createIdentity`. Purging an account (`purgeUnverified` / `purgeDeleted`) deletes
its events; `sweepExpired()` applies the retention.

## Housekeeping

`identity.sweepExpired()` runs every sweeper in one call — expired sessions,
reset and verification tokens, pending logins, idle rate-limit buckets, security
events past retention — and returns the counts. Expiry is always checked on read; this only frees rows.
`purgeUnverified()` and `purgeDeleted()` are separate because they delete
accounts.

## Errors

Failures are one class, `IdentityError`, carrying a discriminated union
(`error.failure`, `error.code`); narrow with `IdentityError.hasCode(e, 'x')`.
What is **not** an error: an already-registered address (enumeration safety is
a property of the return types).

| Code | Thrown by | Meaning |
|---|---|---|
| `weak_password` | signup, changePassword | fails `passwordProblem` or the breach screen; `reason` says why |
| `bad_credentials` | changePassword, removeTotp | current password wrong |
| `no_password` | changePassword, removeTotp | passwordless (OAuth-only) account |
| `pepper_version` | any verify | hash made under a pepper this process does not hold; add it to `config.previousPeppers` |
| `not_found` | requestDeletion, beginTotpEnrolment, removeTotp | no such user |
| `rate_limited` | signup, login, requestPasswordReset, resendVerification, verifyTotp, verifyRecoveryCode | limiter refused; `retryAfterMs` |
| `reauth_required` | beginTotpEnrolment | proof missing, wrong, stale or for another user |
| `enrolment_not_started` | confirmTotpEnrolment | no factor to confirm |
| `invalid_code` | confirmTotpEnrolment | the TOTP code did not verify |
| `totp_key_version` | MFA verify | secret sealed under a key version not in `totp.previousKeys` |
| `invalid_config` | createMfa, createApiKeys | malformed key / prefix at construction |
| `unknown_provider` | oidc begin/complete | no provider registered under that name |
| `no_id_token` | oidc complete | the token response had no ID token |
| `invalid_challenge` | passkeys registerFinish / authenticateFinish | challenge unknown / spent, expired, wrong purpose, or another user's (`reason`) |
| `passkey_verification_failed` | passkeys registerFinish | attestation did not verify (origin, RP id, UV, duplicate credential); `reason` |
| `passkey_counter_regression` | passkeys authenticateFinish | signature counter did not advance — cloned authenticator or replay |

## Opt-in modules

Separate entry points, so an app that wants neither compiles neither.

### `identity-kit/mfa` — TOTP + recovery codes

```ts
import { createMfa } from '@quxkit/identity-kit/mfa';

const mfa = createMfa({ db, config, mail, totp: { key: process.env.TOTP_KEY!, keyVersion: 1, issuer: 'Acme' } });
const identity = createIdentity({ db, config, mail, secondFactor: mfa.secondFactor });
// now login() returns { kind: 'mfa_required', pendingToken } for an enrolled user

// enrolment needs recent authentication: the password, or a session that logged in recently
const { uri, secret } = await mfa.beginTotpEnrolment(userId, { sessionToken });   // or { password }
const { recoveryCodes, rotated } = await mfa.confirmTotpEnrolment(userId, code, undefined, currentSessionHash);
```

Rotate the seal key by bumping `keyVersion`, moving the old key to
`totp.previousKeys: { 1: OLD_KEY }`; each secret is re-sealed under the current
key on its next successful verification, and the old entry can go once no row
carries `key_version = 1`.

The TOTP secret is **encrypted** (AES-256-GCM) under a key held outside the
database — the one auth secret that cannot be one-way. `lastUsedStep` rejects a
code phished in real time from being replayed in its own window; the
pending-login state is a single-purpose table, never a half-privileged session;
guesses are bounded (five per authentication), which is what makes six digits
safe. Recovery codes are argon2id-hashed. Apply `sql/002_mfa.sql`.

### `identity-kit/passkeys` — WebAuthn credentials

```ts
import { createPasskeys } from '@quxkit/identity-kit/passkeys';

const passkeys = createPasskeys({ db, config, mail, rp: { id: 'example.com', name: 'Acme', origin: 'https://app.example.com' } });

// register (signed in; needs recent auth — the same EnrolmentProof as MFA)
const creation = await passkeys.registerBegin(userId, { sessionToken });   // -> navigator.credentials.create
const passkey  = await passkeys.registerFinish(userId, browserResponse, { name: 'MacBook', meta });

// sign in (usernameless: no userId; or name the user to restrict allowCredentials)
const request = await passkeys.authenticateBegin();                        // -> navigator.credentials.get
const result  = await passkeys.authenticateFinish(browserResponse, meta);  // { kind: 'session', token } | { kind: 'failed' }

await passkeys.list(userId); await passkeys.rename(userId, id, 'Phone'); await passkeys.remove(userId, id, meta);
```

The ceremony is [`@simplewebauthn/server`](https://simplewebauthn.dev)'s (a
runtime dependency of this subpath only); the browser half is
`@simplewebauthn/browser` or `PublicKeyCredential.parseCreationOptionsFromJSON`.
What identity-kit owns: the **challenge is stored server-side**
(`identity.webauthn_challenges`, sha256, five-minute TTL, spent on use — even a
failing finish burns it, so nothing replays and the host holds no per-request
state); **registration needs recent authentication** so a hijacked session
cannot add an attacker's key; the **signature counter** is checked before the
signature and a regression is `passkey_counter_regression` (recorded as a
`login_failed`), not a swallowed `verified: false`; user verification is
required at verification time (`userVerification: 'discouraged'` to accept
presence-only keys); a good assertion goes through `finishLogin`, so it is a real
login — same session, new-device mail, `login_succeeded` (`via: 'passkey'`) —
and, being two factors in one authenticator, never asks for TOTP. Apply
`sql/007_passkeys.sql`; `sweepExpired()` prunes stale challenges.

### `identity-kit/magic` — passwordless sign-in by emailed link

```ts
import { createMagic } from '@quxkit/identity-kit/magic';

const magic = createMagic({ db, config, mail, secondFactor: mfa.secondFactor });
await magic.request({ email, ipAddress });                 // { accepted: true } — always
const r = await magic.consume({ token }, { ipAddress, userAgent });
// { kind: 'session', token, expiresAt } | { kind: 'mfa_required', pendingToken } | { kind: 'invalid' }
```

A link is a credential that travels by mail, so it gets the reset token's
discipline: **15 minutes**, **one live token per user**, **sha256 at rest**,
**burned on any use** in the transaction that mints the session. `request` is
enumeration-safe (the same acceptance and a mail on both branches, keyed through
the rate-limit seam as `magic_link`, 5/hour per address + ip). Only a
**verified** account gets a link — an unverified signup may be a squat on
someone else's address, and mailing that address a login would hand the
squatter's account (with the squatter's password still on it) to the victim.
`consume` re-checks at redemption, goes through `finishLogin` (`via:
'magic_link'`, plus a `magic_link_used` event), and does **not** bypass a second
factor. Apply `sql/008_magic.sql`; `sweepExpired()` prunes expired tokens.

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

Two provider flags exist for the awkward cases. `allowInsecureRequests` permits
`http://` and is **loopback-only** (anything else is `invalid_config`), for a
local Keycloak or Dex in development. `verifyIdTokenSignature` checks the ID
token's JWS against the provider's JWKS; it is off by default because in the code
flow the token arrives over a direct TLS connection to the token endpoint, which
is what authenticates the issuer (OIDC Core 3.1.3.7) — and it is forced on
whenever `allowInsecureRequests` is set, since there is then no TLS doing that
job. The whole flow is exercised end to end in the tests against an in-process
issuer (`test/mock-issuer.ts`: discovery, JWKS, authorize, token; RS256 via
`node:crypto`, no extra dependency).

## Schema

Everything lives in an `identity` schema so it cannot collide with a host
application's `users` table. `sql/001_identity.sql` declares `users`, `sessions`,
`email_verification_tokens` and `password_reset_tokens`; `002_mfa.sql`,
`003_apikeys.sql`, `004_oidc.sql` and `007_passkeys.sql` add the opt-in modules' tables;
`005_hardening.sql` adds `users.last_failed_at`, `sessions.authenticated_at` and
the `rate_limits` table (required by the core); `007_passkeys.sql` adds
`passkeys` and `webauthn_challenges` for the passkeys module; `008_magic.sql`
adds `magic_link_tokens`; `006_events.sql` adds the
security-events log (required by the core; keyed by a text `user_id` with no
foreign key, because API-key events are keyed by an opaque owner — purge deletes
them explicitly). Everything else cascades on delete; every file is re-runnable,
applied in order:

```sh
for f in 001_identity 002_mfa 003_apikeys 004_oidc 005_hardening 006_events 007_passkeys 008_magic; do
  psql -v ON_ERROR_STOP=1 -f "node_modules/@quxkit/identity-kit/sql/$f.sql"
done
```

## Development

```sh
pnpm install
createdb identity_kit_test   # the tests exercise real SQL; they skip without a DB
pnpm lint && pnpm typecheck && pnpm build && pnpm test
pnpm test:coverage           # the same under c8; thresholds in .c8rc.json
```

See [CONTRIBUTING.md](CONTRIBUTING.md) for the issue → branch → PR workflow and
[SECURITY.md](SECURITY.md) for how to report a vulnerability privately.

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
