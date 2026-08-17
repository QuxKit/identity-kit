# Security policy

## Supported versions

| Version | Supported |
| ------- | --------- |
| 0.1.x   | yes       |
| < 0.1   | no        |

## Reporting a vulnerability

Please do **not** open a public issue for a security problem.

Report privately to the repository owner (`@brett`) — on GitHub, use
[private vulnerability reporting / security advisories](https://github.com/QuxKit/identity-kit/security/advisories/new);
on the local forge, open an issue marked confidential or contact the owner
directly. Include what you found, how to reproduce it, and what you believe
the impact is.

You will get an acknowledgement within a few days. We follow **coordinated
disclosure with a 90-day window**: we aim to ship a fix and publish an advisory
within 90 days of the report, sooner where the fix is simple, and we will
credit you unless you ask otherwise.

## Scope

**In scope** — anything in this library's own code and schema:

- authentication logic: password verification, pepper handling, `needsRehash`;
- enumeration or timing oracles on signup, login, reset, verification;
- session handling: token issue, resolution, rotation, revocation, cookies;
- MFA: TOTP secret sealing, replay prevention, attempt bounds, recovery codes;
- API keys: shape/checksum gate, resolution, revocation;
- the OIDC account-linking policy;
- the rate limiter and sweepers;
- the SQL in `sql/`.

**Out of scope** — things the host owns and this library documents as such:

- transport security (TLS), CSRF on the host's routes, HTTP framework issues;
- the mail relay (`MailSender`) and what happens to a message after `send`;
- the OIDC provider and `openid-client` itself (report those upstream);
- deployments that set `cookieSecure: false` in production or keep the pepper /
  TOTP key in the database — the docs say not to;
- denial of service by sheer volume against a host with no limiter configured.
