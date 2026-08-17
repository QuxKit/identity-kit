// The rate-limit seam, and two token-bucket implementations of it.
//
// A limiter is `hit(key, cost) -> { allowed, retryAfterMs }`. The library asks
// it in front of the paths an attacker pays nothing for and the server pays an
// argon2 for: signup, login, reset request, verification resend, MFA verify.
// Keys are `<action>:<subject>`; the action prefix picks the rule, so one
// limiter with one rule table covers every path.
//
// Two implementations ship. The Postgres one is the default inside
// createIdentity — one INSERT … ON CONFLICT DO UPDATE … RETURNING per hit, so
// many workers share one exact count. The memory one is for tests and single-
// process hosts. Pass `rateLimiter: null` to turn limiting off.

import type { Clock, SqlExecutor } from './types.ts';

export interface RateLimitDecision {
  allowed: boolean;
  /** 0 when allowed; otherwise how long until one token is back. */
  retryAfterMs: number;
}

export interface RateLimiter {
  hit(key: string, cost?: number): Promise<RateLimitDecision>;
}

/** A token bucket: `limit` tokens refill over `windowMs`, capacity `limit`. */
export interface RateLimitRule {
  limit: number;
  windowMs: number;
}

export type RateLimitAction = 'signup' | 'login' | 'password_reset' | 'verification_resend' | 'mfa_verify';

export type RateLimitRules = Record<RateLimitAction | 'default', RateLimitRule>;

const MINUTE = 60_000;
const HOUR = 60 * MINUTE;

/**
 * Sane defaults. Signup and reset are keyed by address (and IP when the host
 * passes one); login by address + IP together, so an attacker cannot lock a
 * victim out from a distance nor spray one IP across many accounts freely.
 */
export const DEFAULT_RATE_LIMITS: RateLimitRules = {
  signup: { limit: 10, windowMs: HOUR },
  login: { limit: 10, windowMs: 5 * MINUTE },
  password_reset: { limit: 5, windowMs: HOUR },
  verification_resend: { limit: 5, windowMs: HOUR },
  mfa_verify: { limit: 10, windowMs: MINUTE },
  default: { limit: 60, windowMs: MINUTE },
};

export const ruleFor = (rules: RateLimitRules, key: string): RateLimitRule => {
  const action = key.slice(0, key.indexOf(':')) as RateLimitAction;
  return rules[action] ?? rules.default;
};

export const withDefaults = (rules?: Partial<RateLimitRules>): RateLimitRules => ({ ...DEFAULT_RATE_LIMITS, ...rules });

/** Build a limiter key. The parts are joined with a separator that cannot occur
 *  in a normalised email, so `a@x|1.2.3.4` cannot be confused with another pair. */
export const limiterKey = (action: RateLimitAction, ...parts: readonly (string | null | undefined)[]): string =>
  `${action}:${parts.filter((p): p is string => typeof p === 'string' && p.length > 0).join('|')}`;

const retryAfter = (rule: RateLimitRule, tokens: number, cost: number): number =>
  Math.max(1, Math.ceil(((cost - tokens) * rule.windowMs) / rule.limit));

// --- memory ------------------------------------------------------------------

export interface MemoryRateLimiterOptions {
  rules?: Partial<RateLimitRules>;
  clock?: Clock;
}

/** In-process. For tests and single-process hosts; a multi-worker deployment
 *  wants the Postgres one, or every worker gets its own budget. */
export function createMemoryRateLimiter(opts: MemoryRateLimiterOptions = {}): RateLimiter & { reset(): void } {
  const rules = withDefaults(opts.rules);
  const clock: Clock = opts.clock ?? (() => new Date());
  const buckets = new Map<string, { tokens: number; updatedAt: number }>();
  return {
    async hit(key, cost = 1) {
      const rule = ruleFor(rules, key);
      if (cost > rule.limit) return { allowed: false, retryAfterMs: rule.windowMs };
      const now = clock().getTime();
      const b = buckets.get(key) ?? { tokens: rule.limit, updatedAt: now };
      const elapsed = Math.max(0, now - b.updatedAt);
      const tokens = Math.min(rule.limit, b.tokens + (elapsed * rule.limit) / rule.windowMs);
      if (tokens >= cost) {
        buckets.set(key, { tokens: tokens - cost, updatedAt: now });
        return { allowed: true, retryAfterMs: 0 };
      }
      buckets.set(key, { tokens, updatedAt: now });
      return { allowed: false, retryAfterMs: retryAfter(rule, tokens, cost) };
    },
    reset: () => buckets.clear(),
  };
}

// --- postgres ----------------------------------------------------------------

export interface PgRateLimiterOptions {
  db: SqlExecutor;
  rules?: Partial<RateLimitRules>;
  clock?: Clock;
}

/**
 * Backed by `identity.rate_limits` (sql/005_hardening.sql). One statement per
 * hit: the upsert refills the bucket for the time elapsed and charges the cost
 * only when there is enough — its WHERE clause makes a denied hit leave the row
 * untouched — and the trailing SELECT reports the balance either way.
 */
export function createPgRateLimiter(opts: PgRateLimiterOptions): RateLimiter {
  const rules = withDefaults(opts.rules);
  const clock: Clock = opts.clock ?? (() => new Date());
  return {
    async hit(key, cost = 1) {
      const rule = ruleFor(rules, key);
      if (cost > rule.limit) return { allowed: false, retryAfterMs: rule.windowMs };
      const now = clock();
      const perMs = rule.limit / rule.windowMs;
      // $1 key, $2 capacity, $3 cost, $4 now, $5 refill per ms
      const rows = await opts.db.query<{ tokens: number; allowed: boolean }>(
        `WITH refilled AS (
           SELECT LEAST($2::float8, tokens + $5::float8 * GREATEST(0, EXTRACT(EPOCH FROM ($4::timestamptz - updated_at)) * 1000)) AS tokens
             FROM identity.rate_limits WHERE key = $1
         ), charged AS (
           INSERT INTO identity.rate_limits AS r (key, tokens, updated_at)
           VALUES ($1, $2::float8 - $3::float8, $4)
           ON CONFLICT (key) DO UPDATE
             SET tokens = LEAST($2::float8, r.tokens + $5::float8 * GREATEST(0, EXTRACT(EPOCH FROM ($4::timestamptz - r.updated_at)) * 1000)) - $3::float8,
                 updated_at = $4
             WHERE LEAST($2::float8, r.tokens + $5::float8 * GREATEST(0, EXTRACT(EPOCH FROM ($4::timestamptz - r.updated_at)) * 1000)) >= $3::float8
           RETURNING tokens
         )
         SELECT tokens, true AS allowed FROM charged
         UNION ALL
         SELECT tokens, false AS allowed FROM refilled WHERE NOT EXISTS (SELECT 1 FROM charged)`,
        [key, rule.limit, cost, now, perMs],
      );
      const row = rows[0];
      if (!row) return { allowed: false, retryAfterMs: rule.windowMs };
      if (row.allowed) return { allowed: true, retryAfterMs: 0 };
      return { allowed: false, retryAfterMs: retryAfter(rule, Number(row.tokens), cost) };
    },
  };
}
