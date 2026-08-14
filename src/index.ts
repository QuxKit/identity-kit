// identity-kit — user identity and authentication as a library.
//
// Accounts, credentials and sessions over a provider-agnostic executor. It owns
// who a person is and how they prove it, and produces a `UserId` — the principal
// tenant-kit's memberships authorize and, through the tenant, a billing-kit
// charge lands on. It does not own tenancy, roles, or billing; those are their
// own libraries.
//
// `createIdentity` binds an executor, config and mail transport over the free
// functions below. Nothing here reads the environment.

export { createIdentity } from './instance.ts';
export type { Identity, IdentityOptions } from './instance.ts';

export { createCredentials, passwordProblem, PARAMS } from './credentials.ts';
export type { Credentials } from './credentials.ts';

export { createMailer } from './mail.ts';
export type { Mailer } from './mail.ts';

export {
  createSession,
  resolveSession,
  revokeSession,
  revokeAllSessions,
  listSessions,
  sweepExpiredSessions,
  sessionCookie,
  clearedSessionCookie,
  cookieName,
  ABSOLUTE_LIFETIME_MS,
  IDLE_LIFETIME_MS,
} from './sessions.ts';

export { createAccounts } from './accounts.ts';
export type { Accounts, AccountsDeps } from './accounts.ts';

export { finishLogin } from './session-login.ts';

export { issueToken, sha256, expiresIn } from './tokens.ts';
export type { IssuedToken } from './tokens.ts';

export { IdentityError } from './errors.ts';
export type { IdentityFailure, IdentityErrorCode } from './errors.ts';

export type {
  Clock,
  IdentityConfig,
  Logger,
  MailSender,
  Message,
  ResolvedSession,
  SecondFactor,
  SessionMeta,
  SessionSummary,
  SignupInput,
  LoginResult,
  ResetResult,
  SqlExecutor,
  User,
  UserId,
} from './types.ts';
