// identity-kit/http — the endpoints, once, framework-neutral.
//
// Every host writes the same twenty handlers over the library and each
// re-invents the cookie plumbing, the error → status mapping and CSRF. So the
// handlers live here as one function of a plain request shape:
//
//   (req: { method, path, headers, body, ip }) => { status, headers, body }
//
// No framework is imported. Three thin adapters (`nodeListener`,
// `expressHandler`, `honoHandler`) translate the request/response of the
// frameworks most hosts use, typed against minimal local interfaces so nothing
// is pulled in at runtime; a host with something else writes ten lines.
//
// The session cookie is what `createIdentity` already produces; a bearer token
// (`Authorization: Bearer <session token>`) is accepted for SPAs that keep the
// token themselves. CSRF is a double-submit token beside the session cookie,
// opt-in (`csrf: true`) — `SameSite=Lax` already blocks cross-site POST, so
// this is defence in depth for hosts that want it.

import { randomBytes, timingSafeEqual } from 'node:crypto';
import type { IncomingMessage, ServerResponse } from 'node:http';

import type { ApiKeys } from './apikeys.ts';
import { IdentityError, type IdentityErrorCode } from './errors.ts';
import type { Identity } from './instance.ts';
import type { Magic } from './magic.ts';
import type { Mfa } from './mfa.ts';
import type { AuthenticationResponseJSON, Passkeys, RegistrationResponseJSON } from './passkeys.ts';
import { sha256 } from './tokens.ts';
import type { Clock, IdentityConfig, SessionMeta } from './types.ts';

// --- the neutral shapes ------------------------------------------------------

export interface HttpRequest {
  method: string;
  /** Path only, no query string; the builder strips `basePath`. */
  path: string;
  /** Lower-cased names. */
  headers: Record<string, string | string[] | undefined>;
  /** Parsed JSON, or the raw JSON string, or undefined. */
  body?: unknown;
  ip?: string | null;
}

export interface HttpResponse {
  status: number;
  /** `set-cookie` may carry several values. */
  headers: Record<string, string | string[]>;
  /** JSON-serialisable; `null` for no body. */
  body: unknown;
}

export type Handler = (req: HttpRequest) => Promise<HttpResponse>;

export interface RoutesOptions {
  identity: Identity;
  config: IdentityConfig;
  mfa?: Mfa;
  apiKeys?: ApiKeys;
  magic?: Magic;
  passkeys?: Passkeys;
  /** Mounted under this prefix (`/auth`). Default none. */
  basePath?: string;
  /** Require the double-submit CSRF token on every non-GET request. Off by
   *  default (`SameSite=Lax` covers cross-site POST). */
  csrf?: boolean;
  clock?: Clock;
}

export interface Routes {
  /** Every route; `null` when the path is not one of ours (fall through). */
  handle(req: HttpRequest): Promise<HttpResponse | null>;
  /** The paths this instance answers, for a router that wants to register them. */
  paths: readonly string[];
  csrf: Csrf;
}

// --- csrf: double submit -----------------------------------------------------

export interface Csrf {
  cookieName(): string;
  /** A fresh token and the Set-Cookie carrying it. Send the token in the page
   *  (or a `GET /csrf` response); the client echoes it as `x-csrf-token`. */
  issue(): { token: string; cookie: string };
  /** Header (or body `_csrf`) equals cookie, in constant time. */
  verify(req: HttpRequest): boolean;
}

export function createCsrf(config: IdentityConfig): Csrf {
  const name = config.cookieSecure ? '__Host-csrf' : 'csrf';
  return {
    cookieName: () => name,
    issue() {
      const token = randomBytes(32).toString('base64url');
      // Not HttpOnly on purpose: a script must read it to echo it. SameSite=Strict
      // is fine here — the token is only ever sent by our own pages' scripts.
      const parts = [`${name}=${token}`, 'SameSite=Strict', 'Path=/', 'Max-Age=43200'];
      if (config.cookieSecure) parts.push('Secure');
      return { token, cookie: parts.join('; ') };
    },
    verify(req) {
      const fromCookie = cookies(req)[name];
      const header = headerValue(req, 'x-csrf-token');
      const body = objectBody(req);
      const presented = header ?? (typeof body?._csrf === 'string' ? body._csrf : undefined);
      if (!fromCookie || !presented) return false;
      const a = Buffer.from(fromCookie);
      const b = Buffer.from(presented);
      return a.length === b.length && timingSafeEqual(a, b);
    },
  };
}

// --- request helpers ---------------------------------------------------------

const headerValue = (req: HttpRequest, name: string): string | undefined => {
  const v = req.headers[name];
  return Array.isArray(v) ? v[0] : v;
};

/** Parse the Cookie header. Values are taken verbatim (tokens are base64url). */
export function cookies(req: HttpRequest): Record<string, string> {
  const out: Record<string, string> = {};
  const raw = headerValue(req, 'cookie');
  if (!raw) return out;
  for (const part of raw.split(';')) {
    const i = part.indexOf('=');
    if (i < 0) continue;
    const k = part.slice(0, i).trim();
    if (k && !(k in out)) out[k] = part.slice(i + 1).trim();
  }
  return out;
}

const objectBody = (req: HttpRequest): Record<string, unknown> | null => {
  let body = req.body;
  if (typeof body === 'string') {
    if (body.trim() === '') return null;
    try {
      body = JSON.parse(body);
    } catch {
      return null;
    }
  }
  return body !== null && typeof body === 'object' && !Array.isArray(body) ? (body as Record<string, unknown>) : null;
};

const str = (body: Record<string, unknown> | null, key: string): string | undefined => {
  const v = body?.[key];
  return typeof v === 'string' ? v : undefined;
};

const metaOf = (req: HttpRequest): SessionMeta => ({
  ipAddress: req.ip ?? null,
  userAgent: headerValue(req, 'user-agent') ?? null,
});

const json = (status: number, body: unknown, headers: Record<string, string | string[]> = {}): HttpResponse => ({
  status,
  headers: body === null ? headers : { 'content-type': 'application/json; charset=utf-8', ...headers },
  body,
});

const STATUS: Partial<Record<IdentityErrorCode, number>> = {
  weak_password: 400,
  bad_credentials: 403,
  no_password: 400,
  not_found: 404,
  rate_limited: 429,
  reauth_required: 401,
  enrolment_not_started: 409,
  invalid_code: 400,
  invalid_challenge: 400,
  passkey_verification_failed: 400,
  passkey_counter_regression: 403,
  unknown_provider: 404,
  // Forbidden, not 400: the request is well formed and the server is refusing
  // it — and the refusal is about the server's state, never this address.
  registration_closed: 403,
};

/** Map an IdentityError to a response; anything else propagates. */
export function errorResponse(e: unknown): HttpResponse {
  if (!IdentityError.is(e)) throw e;
  const { failure } = e;
  const headers: Record<string, string> = {};
  if (failure.code === 'rate_limited') headers['retry-after'] = String(Math.ceil(failure.retryAfterMs / 1000));
  // `key` can carry an email; it stays server-side.
  const { key: _key, ...safe } = failure as typeof failure & { key?: string };
  return json(STATUS[failure.code] ?? 400, { error: safe.code, ...safe }, headers);
}

// --- the builder -------------------------------------------------------------

export function routes(opts: RoutesOptions): Routes {
  const { identity, config } = opts;
  const clock: Clock = opts.clock ?? (() => new Date());
  const base = (opts.basePath ?? '').replace(/\/+$/, '');
  const csrf = createCsrf(config);

  const sessionToken = (req: HttpRequest): string | null => {
    const auth = headerValue(req, 'authorization');
    if (auth?.toLowerCase().startsWith('bearer ')) return auth.slice(7).trim() || null;
    return cookies(req)[identity.cookieName()] ?? null;
  };

  /** Resolve the caller's session; `rotated` cookie is returned to be set. */
  const authed = async (req: HttpRequest, now: Date) => {
    const token = sessionToken(req);
    if (!token) return null;
    const session = await identity.resolveSession(token, now);
    if (!session) return null;
    const setCookie = session.rotated
      ? [identity.sessionCookie(session.rotated.token, session.rotated.expiresAt, now)]
      : [];
    return { token, session, setCookie };
  };

  const unauthorised = () => json(401, { error: 'unauthenticated' });

  const loginResponse = (
    r:
      | { kind: 'session'; token: string; expiresAt: Date }
      | { kind: 'mfa_required'; pendingToken: string }
      | { kind: 'failed' }
      | { kind: 'invalid' }
      | { kind: 'restart' }
      | { kind: 'backoff'; retryAfterSeconds: number },
    now: Date,
  ): HttpResponse => {
    switch (r.kind) {
      case 'session':
        return json(
          200,
          { kind: 'session', expiresAt: r.expiresAt.toISOString() },
          { 'set-cookie': [identity.sessionCookie(r.token, r.expiresAt, now)] },
        );
      case 'mfa_required':
        return json(200, { kind: 'mfa_required', pendingToken: r.pendingToken });
      case 'backoff':
        return json(
          429,
          { kind: 'backoff', retryAfterSeconds: r.retryAfterSeconds },
          { 'retry-after': String(r.retryAfterSeconds) },
        );
      case 'restart':
        return json(401, { kind: 'restart' });
      default:
        return json(401, { kind: 'failed' });
    }
  };

  const need = (b: Record<string, unknown> | null, ...keys: string[]): HttpResponse | null => {
    for (const k of keys) {
      if (typeof b?.[k] !== 'string' || (b[k] as string).length === 0) {
        return json(400, { error: 'invalid_body', missing: k });
      }
    }
    return null;
  };

  type Route = (req: HttpRequest, body: Record<string, unknown> | null, now: Date) => Promise<HttpResponse>;
  const table = new Map<string, Route>();
  const on = (method: string, path: string, route: Route) => table.set(`${method} ${path}`, route);

  // --- accounts ---
  on('POST', '/signup', async (req, b) => {
    const bad = need(b, 'email', 'password');
    if (bad) return bad;
    await identity.signup({
      email: str(b, 'email') as string,
      password: str(b, 'password') as string,
      name: str(b, 'name'),
      ipAddress: req.ip ?? null,
      // Passed through untouched: only the host's `registration` policy knows
      // what an invite means. A closed door answers 403.
      invite: str(b, 'invite'),
    });
    return json(202, { accepted: true });
  });
  on('POST', '/verify', async (_req, b, now) => {
    const bad = need(b, 'token');
    if (bad) return bad;
    const verified = await identity.verifyEmail(str(b, 'token') as string, now);
    return json(verified ? 200 : 400, { verified });
  });
  on('POST', '/verify/resend', async (req, b) => {
    const bad = need(b, 'email');
    if (bad) return bad;
    await identity.resendVerification(str(b, 'email') as string, metaOf(req));
    return json(202, { accepted: true });
  });
  on('POST', '/login', async (req, b, now) => {
    const bad = need(b, 'email', 'password');
    if (bad) return bad;
    const r = await identity.login(
      { email: str(b, 'email') as string, password: str(b, 'password') as string },
      metaOf(req),
      now,
    );
    return loginResponse(r, now);
  });
  on('POST', '/logout', async (req) => {
    const token = sessionToken(req);
    if (token) await identity.revokeSession(sha256(token), metaOf(req));
    return json(204, null, { 'set-cookie': [identity.clearedSessionCookie()] });
  });
  on('GET', '/session', async (req, _b, now) => {
    const a = await authed(req, now);
    if (!a) return unauthorised();
    return json(
      200,
      {
        userId: a.session.userId,
        expiresAt: a.session.expiresAt.toISOString(),
        authenticatedAt: a.session.authenticatedAt.toISOString(),
      },
      a.setCookie.length ? { 'set-cookie': a.setCookie } : {},
    );
  });
  on('GET', '/csrf', async () => {
    const { token, cookie } = csrf.issue();
    return json(200, { token }, { 'set-cookie': [cookie] });
  });

  // --- passwords ---
  on('POST', '/password/reset/request', async (req, b) => {
    const bad = need(b, 'email');
    if (bad) return bad;
    await identity.requestPasswordReset(str(b, 'email') as string, metaOf(req));
    return json(202, { accepted: true });
  });
  on('POST', '/password/reset/confirm', async (req, b, now) => {
    const bad = need(b, 'token', 'password');
    if (bad) return bad;
    const r = await identity.resetPassword(str(b, 'token') as string, str(b, 'password') as string, now, metaOf(req));
    if (r.kind === 'done') return json(200, { kind: 'done' });
    if (r.kind === 'weak_password') return json(400, { kind: 'weak_password', message: r.message });
    return json(400, { kind: 'invalid' });
  });
  on('POST', '/password/change', async (req, b, now) => {
    const a = await authed(req, now);
    if (!a) return unauthorised();
    const bad = need(b, 'current', 'next');
    if (bad) return bad;
    const r = await identity.changePassword(
      a.session.userId,
      str(b, 'current') as string,
      str(b, 'next') as string,
      a.session.tokenHash,
      now,
      metaOf(req),
    );
    const setCookie = r.rotated ? [identity.sessionCookie(r.rotated.token, r.rotated.expiresAt, now)] : a.setCookie;
    return json(200, { changed: true }, setCookie.length ? { 'set-cookie': setCookie } : {});
  });

  // --- mfa ---
  if (opts.mfa) {
    const mfa = opts.mfa;
    on('POST', '/mfa/begin', async (req, b, now) => {
      const a = await authed(req, now);
      if (!a) return unauthorised();
      const password = str(b, 'password');
      const proof = password ? { password } : { sessionToken: a.token };
      const e = await mfa.beginTotpEnrolment(a.session.userId, proof, now);
      return json(200, e);
    });
    on('POST', '/mfa/confirm', async (req, b, now) => {
      const a = await authed(req, now);
      if (!a) return unauthorised();
      const bad = need(b, 'code');
      if (bad) return bad;
      const r = await mfa.confirmTotpEnrolment(
        a.session.userId,
        str(b, 'code') as string,
        now,
        a.session.tokenHash,
        metaOf(req),
      );
      const setCookie = r.rotated ? [identity.sessionCookie(r.rotated.token, r.rotated.expiresAt, now)] : [];
      return json(200, { recoveryCodes: r.recoveryCodes }, setCookie.length ? { 'set-cookie': setCookie } : {});
    });
    on('POST', '/mfa/verify', async (req, b, now) => {
      const bad = need(b, 'pendingToken', 'code');
      if (bad) return bad;
      const pending = str(b, 'pendingToken') as string;
      const code = str(b, 'code') as string;
      const r =
        b?.recovery === true
          ? await mfa.verifyRecoveryCode(pending, code, metaOf(req), now)
          : await mfa.verifyTotp(pending, code, metaOf(req), now);
      return loginResponse(r, now);
    });
    on('POST', '/mfa/remove', async (req, b, now) => {
      const a = await authed(req, now);
      if (!a) return unauthorised();
      const bad = need(b, 'password');
      if (bad) return bad;
      const r = await mfa.removeTotp(
        a.session.userId,
        str(b, 'password') as string,
        a.session.tokenHash,
        now,
        metaOf(req),
      );
      const setCookie = r.rotated ? [identity.sessionCookie(r.rotated.token, r.rotated.expiresAt, now)] : [];
      return json(200, { removed: true }, setCookie.length ? { 'set-cookie': setCookie } : {});
    });
  }

  // --- api keys (owned by the signed-in user) ---
  if (opts.apiKeys) {
    const keys = opts.apiKeys;
    on('GET', '/apikeys', async (req, _b, now) => {
      const a = await authed(req, now);
      if (!a) return unauthorised();
      return json(200, { keys: await keys.listApiKeys(a.session.userId) });
    });
    on('POST', '/apikeys', async (req, b, now) => {
      const a = await authed(req, now);
      if (!a) return unauthorised();
      const bad = need(b, 'name');
      if (bad) return bad;
      const scopes = Array.isArray(b?.scopes) ? b.scopes.filter((s): s is string => typeof s === 'string') : [];
      const environment = b?.environment === 'test' ? 'test' : 'live';
      const expiresAt = typeof b?.expiresAt === 'string' ? new Date(b.expiresAt) : undefined;
      const created = await keys.createApiKey(a.session.userId, {
        name: str(b, 'name') as string,
        scopes,
        environment,
        expiresAt: expiresAt && !Number.isNaN(expiresAt.getTime()) ? expiresAt : undefined,
        createdBy: a.session.userId,
        meta: metaOf(req),
      });
      return json(201, created);
    });
    on('DELETE', '/apikeys/:id', async (req, _b, now) => {
      const a = await authed(req, now);
      if (!a) return unauthorised();
      const id = req.path.slice('/apikeys/'.length);
      const owned = (await keys.listApiKeys(a.session.userId)).some((k) => k.id === id);
      if (!owned) return json(404, { error: 'not_found', what: `api key ${id}` });
      await keys.revokeApiKey(id, now, metaOf(req));
      return json(204, null);
    });
  }

  // --- magic links ---
  if (opts.magic) {
    const magic = opts.magic;
    on('POST', '/magic/request', async (req, b, now) => {
      const bad = need(b, 'email');
      if (bad) return bad;
      await magic.request({ email: str(b, 'email') as string, ipAddress: req.ip ?? null }, now);
      return json(202, { accepted: true });
    });
    on('POST', '/magic/consume', async (req, b, now) => {
      const bad = need(b, 'token');
      if (bad) return bad;
      return loginResponse(await magic.consume({ token: str(b, 'token') as string }, metaOf(req), now), now);
    });
  }

  // --- passkeys ---
  if (opts.passkeys) {
    const passkeys = opts.passkeys;
    on('POST', '/passkeys/register/begin', async (req, b, now) => {
      const a = await authed(req, now);
      if (!a) return unauthorised();
      const password = str(b, 'password');
      const proof = password ? { password } : { sessionToken: a.token };
      return json(200, await passkeys.registerBegin(a.session.userId, proof, now));
    });
    on('POST', '/passkeys/register/finish', async (req, b, now) => {
      const a = await authed(req, now);
      if (!a) return unauthorised();
      if (!b?.response || typeof b.response !== 'object')
        return json(400, { error: 'invalid_body', missing: 'response' });
      const summary = await passkeys.registerFinish(a.session.userId, b.response as RegistrationResponseJSON, {
        name: str(b, 'name'),
        meta: metaOf(req),
        now,
      });
      return json(201, summary);
    });
    on('GET', '/passkeys', async (req, _b, now) => {
      const a = await authed(req, now);
      if (!a) return unauthorised();
      return json(200, { passkeys: await passkeys.list(a.session.userId) });
    });
    on('DELETE', '/passkeys/:id', async (req, _b, now) => {
      const a = await authed(req, now);
      if (!a) return unauthorised();
      await passkeys.remove(
        a.session.userId,
        decodeURIComponent(req.path.slice('/passkeys/'.length)),
        metaOf(req),
        now,
      );
      return json(204, null);
    });
    on('POST', '/passkeys/authenticate/begin', async (_req, _b, now) => {
      return json(200, await passkeys.authenticateBegin({ now }));
    });
    on('POST', '/passkeys/authenticate/finish', async (req, b, now) => {
      if (!b?.response || typeof b.response !== 'object')
        return json(400, { error: 'invalid_body', missing: 'response' });
      return loginResponse(
        await passkeys.authenticateFinish(b.response as AuthenticationResponseJSON, metaOf(req), now),
        now,
      );
    });
  }

  const paths = [...new Set([...table.keys()].map((k) => k.slice(k.indexOf(' ') + 1)))].map((p) => `${base}${p}`);

  const match = (method: string, path: string): { route: Route } | 'method' | null => {
    const key = `${method} ${path}`;
    const direct = table.get(key);
    if (direct) return { route: direct };
    // parameterised: /apikeys/:id, /passkeys/:id
    for (const [k, route] of table) {
      const [m, p] = k.split(' ', 2) as [string, string];
      if (!p.endsWith('/:id')) continue;
      const prefix = p.slice(0, -3);
      if (path.startsWith(prefix) && path.length > prefix.length && !path.slice(prefix.length).includes('/')) {
        if (m === method) return { route };
      }
    }
    const known = [...table.keys()].some((k) => {
      const p = k.slice(k.indexOf(' ') + 1);
      return p === path || (p.endsWith('/:id') && path.startsWith(p.slice(0, -3)));
    });
    return known ? 'method' : null;
  };

  return {
    paths,
    csrf,
    async handle(req) {
      if (base && !req.path.startsWith(`${base}/`)) return null;
      const path = base ? req.path.slice(base.length) : req.path;
      const method = req.method.toUpperCase();
      const found = match(method, path);
      if (found === null) return null;
      if (found === 'method') return json(405, { error: 'method_not_allowed' });
      const now = clock();
      if (opts.csrf && method !== 'GET' && !csrf.verify(req)) return json(403, { error: 'csrf' });
      let body: Record<string, unknown> | null = null;
      if (req.body !== undefined && req.body !== '') {
        body = objectBody(req);
        if (body === null) return json(400, { error: 'invalid_body', missing: 'json object' });
      }
      try {
        // The route sees the path WITHOUT `basePath`, so `/apikeys/:id` can
        // slice the id off it regardless of where the router mounted us.
        return await found.route(base ? { ...req, path } : req, body, now);
      } catch (e) {
        return errorResponse(e);
      }
    },
  };
}

// --- adapters ----------------------------------------------------------------

/** Thrown by `readBody` past the cap; the listener answers 413. */
class BodyTooLarge extends Error {}

/** Read a node:http body as a string (up to `limit` bytes). A body larger than
 *  that is refused before it is buffered — an auth endpoint has no reason to
 *  accept a megabyte, and buffering one is free memory for an attacker. */
const readBody = (req: IncomingMessage, limit = 64 * 1024): Promise<string> =>
  new Promise((resolve, reject) => {
    const chunks: Buffer[] = [];
    let size = 0;
    req.on('data', (c: Buffer) => {
      size += c.length;
      if (size > limit) {
        // Stop buffering, but do NOT destroy the socket: the client must still
        // be able to read the 413 the listener is about to write.
        chunks.length = 0;
        reject(new BodyTooLarge('body too large'));
        return;
      }
      chunks.push(c);
    });
    req.on('end', () => resolve(Buffer.concat(chunks).toString('utf8')));
    req.on('error', reject);
  });

const writeNode = (res: ServerResponse, out: HttpResponse): void => {
  for (const [k, v] of Object.entries(out.headers)) res.setHeader(k, v);
  res.statusCode = out.status;
  res.end(out.body === null ? undefined : JSON.stringify(out.body));
};

/**
 * `http.createServer(nodeListener(routes))`, or call it from your own listener
 * and treat a `false` return as "not ours". The client ip is
 * `socket.remoteAddress` unless `trustProxy` reads `x-forwarded-for`.
 */
export function nodeListener(r: Routes, o: { trustProxy?: boolean; maxBodyBytes?: number } = {}) {
  return async (req: IncomingMessage, res: ServerResponse): Promise<boolean> => {
    const url = new URL(req.url ?? '/', 'http://localhost');
    let ip = req.socket?.remoteAddress ?? null;
    if (o.trustProxy) {
      const xff = req.headers['x-forwarded-for'];
      const first = (Array.isArray(xff) ? xff[0] : xff)?.split(',')[0]?.trim();
      if (first) ip = first;
    }
    let body: string | undefined;
    if (req.method !== 'GET' && req.method !== 'HEAD') {
      try {
        body = await readBody(req, o.maxBodyBytes);
      } catch (e) {
        if (!(e instanceof BodyTooLarge)) throw e;
        // Drain what is still in flight so the response can be delivered.
        req.resume();
        writeNode(res, json(413, { error: 'body_too_large' }));
        return true;
      }
    }
    const out = await r.handle({ method: req.method ?? 'GET', path: url.pathname, headers: req.headers, body, ip });
    if (!out) return false;
    writeNode(res, out);
    return true;
  };
}

/** The Express-shaped request/response, as much as the adapter needs. */
export interface ExpressLikeRequest {
  method: string;
  path: string;
  headers: Record<string, string | string[] | undefined>;
  body?: unknown;
  ip?: string;
}
export interface ExpressLikeResponse {
  status(code: number): ExpressLikeResponse;
  set(name: string, value: string | string[]): ExpressLikeResponse;
  json(body: unknown): unknown;
  end(): unknown;
}

/** `app.use(expressHandler(routes))` (after `express.json()`). Calls `next()`
 *  when the path is not ours. */
export function expressHandler(r: Routes) {
  return async (req: ExpressLikeRequest, res: ExpressLikeResponse, next: (err?: unknown) => void): Promise<void> => {
    try {
      const out = await r.handle({
        method: req.method,
        path: req.path,
        headers: req.headers,
        body: req.body,
        ip: req.ip ?? null,
      });
      if (!out) return next();
      for (const [k, v] of Object.entries(out.headers)) res.set(k, v);
      res.status(out.status);
      if (out.body === null) res.end();
      else res.json(out.body);
    } catch (e) {
      next(e);
    }
  };
}

/** The Hono-shaped context, as much as the adapter needs. */
export interface HonoLikeContext {
  req: {
    method: string;
    path: string;
    header(): Record<string, string>;
    text(): Promise<string>;
  };
  header(name: string, value: string, opts?: { append?: boolean }): void;
  json(body: unknown, status?: number): unknown;
  body(data: null, status?: number): unknown;
  /** Hono's `getConnInfo(c)` result, if the host wires it in. */
  ip?: string | null;
}

/** `app.all('/auth/*', honoHandler(routes))`. Returns `undefined` (so `next()`
 *  can run) when the path is not ours. */
export function honoHandler(r: Routes) {
  return async (c: HonoLikeContext, next?: () => Promise<void>): Promise<unknown> => {
    const method = c.req.method;
    const body = method === 'GET' || method === 'HEAD' ? undefined : await c.req.text();
    const headers = Object.fromEntries(Object.entries(c.req.header()).map(([k, v]) => [k.toLowerCase(), v]));
    const out = await r.handle({ method, path: c.req.path, headers, body, ip: c.ip ?? null });
    if (!out) return next ? next() : undefined;
    for (const [k, v] of Object.entries(out.headers)) {
      if (Array.isArray(v)) for (const item of v) c.header(k, item, { append: true });
      else c.header(k, v);
    }
    return out.body === null ? c.body(null, out.status) : c.json(out.body, out.status);
  };
}
