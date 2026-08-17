# Example: password login

Sign up, verify the address, log in, resolve the session cookie, revoke — the
whole core loop against a local Postgres, using the shipped `pg` adapter.

```sh
# from the repo root: build the library the example links to
pnpm install && pnpm build

# a throwaway database with the schema applied
createdb identity_kit_example
psql -v ON_ERROR_STOP=1 -d identity_kit_example -f sql/001_identity.sql

# run it
cd examples/password-login
pnpm install --ignore-workspace   # the example is not a workspace member
DATABASE_URL=postgres://localhost:5432/identity_kit_example pnpm start
```

The "mail transport" prints each message to stdout, so you can see the
verification link, the enumeration-safe "already registered" notice, and the
new-device sign-in mail exactly as a real user would receive them.

`AUTH_PEPPER` is the HMAC key peppered into every password before argon2. The
default here is a placeholder; in a real deployment it is a secret held outside
the database.
