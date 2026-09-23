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

export type { Accounts, AccountsDeps, PasswordChanged } from './accounts.ts';
export { createAccounts } from './accounts.ts';
export type { BreachedPasswordCheck, BreachedPasswordOptions, FetchLike } from './breached.ts';
export { passwordBreached } from './breached.ts';
export type { Credentials } from './credentials.ts';
export { createCredentials, PARAMS, passwordProblem, passwordProblemAsync } from './credentials.ts';
export type { IdentityErrorCode, IdentityFailure } from './errors.ts';
export { IdentityError } from './errors.ts';
export type { Events, ListEventsOptions, RecordEventInput, SecurityEvent, SecurityEventKind } from './events.ts';
export {
  createEvents,
  DEFAULT_EVENT_RETENTION_MS,
  deleteEventsFor,
  listEvents,
  recordEvent,
  sweepEvents,
} from './events.ts';
export type { Identity, IdentityOptions } from './instance.ts';
export { createIdentity } from './instance.ts';
export type { Mailer } from './mail.ts';
export { createMailer } from './mail.ts';
export type {
  RateLimitAction,
  RateLimitDecision,
  RateLimiter,
  RateLimitRule,
  RateLimitRules,
} from './ratelimit.ts';
export { createMemoryRateLimiter, createPgRateLimiter, DEFAULT_RATE_LIMITS, limiterKey } from './ratelimit.ts';
export { assertRegistrationAllowed, registrationPolicy } from './registration.ts';
export type { LoginMethod } from './session-login.ts';
export { finishLogin } from './session-login.ts';
export type { ResolveOptions, SweepOptions, SweepReport } from './sessions.ts';
export {
  ABSOLUTE_LIFETIME_MS,
  clearedSessionCookie,
  cookieName,
  createSession,
  IDLE_LIFETIME_MS,
  listSessions,
  resolveSession,
  revokeAllSessions,
  revokeSession,
  rotateSession,
  sessionCookie,
  sweepExpired,
  sweepExpiredSessions,
} from './sessions.ts';
export type { IssuedToken } from './tokens.ts';
export { expiresIn, issueToken, sha256 } from './tokens.ts';
export type {
  Clock,
  IdentityConfig,
  Logger,
  LoginResult,
  MailSender,
  Message,
  RegistrationAttempt,
  RegistrationDecision,
  RegistrationPolicy,
  RegistrationSetting,
  ResetResult,
  ResolvedSession,
  SecondFactor,
  SessionMeta,
  SessionSummary,
  SignupInput,
  SqlExecutor,
  User,
  UserId,
} from './types.ts';
