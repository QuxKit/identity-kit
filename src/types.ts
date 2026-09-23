// The shared vocabulary: the executor, the config, the seams, and the shapes
// that cross between them.
//
// The executor and clock are the same interfaces billing-kit and tenant-kit
// use, on purpose — a `UserId` produced here is the principal those libraries
// authorize and bill. There is no runtime code in this file, and nothing reads
// `process.env`: a library that reads the environment cannot be instantiated
// twice in one process, which a test suite and a multi-region worker both need.

// --- database ---------------------------------------------------------------

/**
 * The whole database dependency. A bare `pg.Pool` satisfies it; Prisma is not
 * required at runtime. Values arrive as the driver produces them — node-postgres
 * gives TIMESTAMPTZ as a Date and TEXT as a string, which is what the queries
 * here expect.
 */
export interface SqlExecutor {
  query<T = Record<string, unknown>>(text: string, params?: readonly unknown[]): Promise<T[]>;
  /**
   * Run `fn` in one transaction, committing on resolve and rolling back on
   * throw. The executor handed to `fn` must be pinned to a single connection;
   * one that hands back the pool runs the body on different connections and the
   * rollback covers nothing.
   */
  transaction<T>(fn: (tx: SqlExecutor) => Promise<T>): Promise<T>;
}

/** Injected so tests and token lifetimes do not depend on wall-clock drift. */
export type Clock = () => Date;

export interface Logger {
  debug(message: string, fields?: Record<string, unknown>): void;
  info(message: string, fields?: Record<string, unknown>): void;
  warn(message: string, fields?: Record<string, unknown>): void;
  error(message: string, fields?: Record<string, unknown>): void;
}

// --- identity ---------------------------------------------------------------

/** Our identifier for a person. Opaque; this is the value tenant-kit's
 *  memberships and billing-kit's subject are keyed on. */
export type UserId = string;

/**
 * Configuration, injected — never read from the environment inside the library.
 *
 * The pepper is the one secret that must live with the application and never in
 * the database: it is what keeps a stolen backup from being offline-cracked.
 */
export interface IdentityConfig {
  /** HMAC-SHA-256 key peppered into every password before argon2. Keep it out of
   *  the database and out of the backup. */
  pepper: string;
  /** The version stamped on hashes made with the current pepper. Rotation bumps
   *  it, keeps the old key available in `previousPeppers`, and re-peppers on
   *  next successful login. */
  pepperVersion: number;
  /** Retired peppers by version, so a hash made under an older one still
   *  verifies (and is re-peppered on that login). Drop a version only once no
   *  row carries it. */
  previousPeppers?: Record<number, string>;
  /** Base URL for the links in transactional mail (`https://app.example.com`). */
  appUrl: string;
  /**
   * Whether session cookies are `Secure` and `__Host-`-prefixed. Must be true in
   * production; false only on a plain-http dev origin, where a `__Host-` cookie
   * would be silently refused by the browser and every login would appear to
   * succeed and do nothing.
   */
  cookieSecure: boolean;
  /**
   * Rotate the session identifier on sliding renewal and after a password or
   * MFA change on the current session. When on, `resolveSession` may return a
   * `rotated` token the host MUST set as the new cookie, and `changePassword`
   * returns the rotated session for the kept token. Off by default so hosts that
   * ignore the return values keep working; turn it on once yours re-sets the
   * cookie.
   */
  rotateSessions?: boolean;
  /** How recent a session's credential proof must be for MFA enrolment via a
   *  session token. Default ten minutes. */
  reauthWindowMs?: number;
  /** How long rows in `identity.events` are kept by `sweepExpired` /
   *  `events.sweep`. Default ninety days. */
  eventRetentionMs?: number;
  /**
   * Optional breached-password screen, asked on signup, reset and change.
   * `passwordBreached(fetch)` builds one (k-anonymity, injectable fetch); any
   * function returning a count works. A non-zero count is a `weak_password`
   * failure. Omitted, no screening happens and nothing is fetched.
   */
  breachedPasswords?: (password: string) => Promise<number>;
  /**
   * Whether new accounts may be created, asked on BOTH doors into
   * `identity.users`: `signup`, and the new-user branch of `linkOrCreate`.
   * Existing accounts sign in either way — closing registration locks the
   * door, it does not evict anyone.
   *
   * Omitted means `'open'`, so a host that has never set it is unaffected. A
   * function is asked per attempt, which is what lets the answer come from a
   * row a superadmin can change without a deploy.
   */
  registration?: RegistrationSetting;
}

// --- registration (a seam) --------------------------------------------------

/** What is being attempted, for the `registration` policy to judge. */
export interface RegistrationAttempt {
  /** Normalised, lowercased. */
  email: string;
  /** Which door: a password signup, or the new-user branch of social sign-in. */
  via: 'password' | 'oidc';
  /** The invite the caller presented, if any. Never validated by this kit. */
  invite?: string;
}

export type RegistrationDecision =
  | { allow: true }
  /** Shown to the person who tried, so write it for them. */
  | { allow: false; reason: string };

export type RegistrationPolicy = (attempt: RegistrationAttempt) => Promise<RegistrationDecision> | RegistrationDecision;

/**
 * `'open'` (the default), `'closed'`, or a function for anything conditional —
 * invite-only, an allow-list, a flag read from the database per attempt.
 */
export type RegistrationSetting = 'open' | 'closed' | RegistrationPolicy;

// --- mail (a seam) ----------------------------------------------------------

/** A composed transactional message. The library writes the body — its shape is
 *  a security property — and the host delivers it. */
export interface Message {
  to: string;
  subject: string;
  /** Plain text. Short and transactional; an HTML layer is the host's choice. */
  body: string;
}

/**
 * The transport seam. The library composes every message (identically on the
 * "address exists" and "address does not" branches, which is what makes the
 * flows enumeration-safe) and calls `send`; which relay carries it is the host's.
 */
export interface MailSender {
  send(message: Message): Promise<void>;
}

// --- users and sessions -----------------------------------------------------

export interface User {
  id: UserId;
  email: string;
  emailDisplay: string;
  name: string | null;
  emailVerifiedAt: Date | null;
  deletionRequestedAt: Date | null;
  createdAt: Date;
}

export interface SessionMeta {
  ipAddress?: string | null;
  userAgent?: string | null;
}

export interface ResolvedSession {
  tokenHash: string;
  userId: UserId;
  expiresAt: Date;
  absoluteExpiresAt: Date;
  /** When the holder last proved a credential on this session. */
  authenticatedAt: Date;
  /** Present only when `rotateSessions` is on and this read renewed the session:
   *  the token was rotated and the host must set `rotated.token` as the cookie.
   *  `tokenHash` above is already the new hash. */
  rotated?: { token: string; expiresAt: Date };
}

export interface SessionSummary {
  tokenHash: string;
  ipAddress: string | null;
  userAgent: string | null;
  createdAt: Date;
  lastSeenAt: Date;
  expiresAt: Date;
}

// --- results ----------------------------------------------------------------

export interface SignupInput {
  email: string;
  password: string;
  name?: string;
  /** The caller's IP, if the host has it — used only as a rate-limit key. */
  ipAddress?: string | null;
  /**
   * An invite the caller presented. This kit never validates it — it has no
   * invite store — it only hands it to the `registration` policy, which is how
   * an invite-only host lets this one attempt through a closed door.
   */
  invite?: string;
}

export type LoginResult =
  | { kind: 'session'; token: string; expiresAt: Date }
  /** The password was correct but a confirmed second factor is required. The
   *  pending token is redeemed by identity-kit/mfa's verifyTotp/verifyRecoveryCode.
   *  Only ever returned when a `SecondFactor` hook is wired into the instance. */
  | { kind: 'mfa_required'; pendingToken: string }
  | { kind: 'failed' }
  | { kind: 'backoff'; retryAfterSeconds: number };

/**
 * The hook the MFA module plugs into login. Given a user who has just passed the
 * password check, it returns a pending-login token if that user has a confirmed
 * second factor, or null if not. Kept as an interface so the core never imports
 * the MFA module — an app without MFA wires nothing and login never blocks.
 */
export interface SecondFactor {
  pendingFor(userId: UserId, now: Date): Promise<string | null>;
}

export type ResetResult = { kind: 'done' } | { kind: 'weak_password'; message: string } | { kind: 'invalid' };
