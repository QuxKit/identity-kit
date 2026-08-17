// The identity surface, bound to one executor, config and mail transport.
//
// `createIdentity` is a factory, not a singleton: config is an argument and
// never a module global, so two instances (a test and a worker) can hold
// different peppers and different databases in one process. The free functions
// each module exports are still the API; this binds the executor, clock and
// config over them for the common case where an application has one of each.

import { type Accounts, createAccounts } from './accounts.ts';
import { createCredentials } from './credentials.ts';
import { createMailer } from './mail.ts';
import {
  clearedSessionCookie,
  cookieName,
  listSessions,
  resolveSession,
  revokeAllSessions,
  revokeSession,
  sessionCookie,
  sweepExpiredSessions,
} from './sessions.ts';
import type {
  Clock,
  IdentityConfig,
  Logger,
  MailSender,
  ResolvedSession,
  SecondFactor,
  SessionSummary,
  SqlExecutor,
  UserId,
} from './types.ts';

export interface IdentityOptions {
  db: SqlExecutor;
  config: IdentityConfig;
  /** Where transactional mail goes. The library composes every message. */
  mail: MailSender;
  clock?: Clock;
  logger?: Logger;
  /** Wire identity-kit/mfa's hook here to make login require a second factor. */
  secondFactor?: SecondFactor;
}

export interface Identity extends Accounts {
  // --- sessions ---
  resolveSession(token: string, now?: Date): Promise<ResolvedSession | null>;
  revokeSession(tokenHash: string): Promise<void>;
  revokeAllSessions(userId: UserId, exceptTokenHash?: string): Promise<number>;
  listSessions(userId: UserId): Promise<SessionSummary[]>;
  sweepExpiredSessions(now?: Date): Promise<number>;
  // --- cookies (config-driven; the host may ignore these and set its own) ---
  cookieName(): string;
  sessionCookie(token: string, expiresAt: Date, now?: Date): string;
  clearedSessionCookie(): string;
}

export function createIdentity(opts: IdentityOptions): Identity {
  const { db, config } = opts;
  const clock: Clock = opts.clock ?? (() => new Date());
  const credentials = createCredentials(config);
  const mailer = createMailer(config, opts.mail);
  const accounts = createAccounts({
    db,
    config,
    credentials,
    mailer,
    clock,
    logger: opts.logger,
    secondFactor: opts.secondFactor,
  });

  return {
    ...accounts,
    resolveSession: (token, now) => resolveSession(db, token, now ?? clock()),
    revokeSession: (tokenHash) => revokeSession(db, tokenHash),
    revokeAllSessions: (userId, except) => revokeAllSessions(db, userId, except),
    listSessions: (userId) => listSessions(db, userId),
    sweepExpiredSessions: (now) => sweepExpiredSessions(db, now ?? clock()),
    cookieName: () => cookieName(config),
    sessionCookie: (token, expiresAt, now) => sessionCookie(config, token, expiresAt, now ?? clock()),
    clearedSessionCookie: () => clearedSessionCookie(config),
  };
}
