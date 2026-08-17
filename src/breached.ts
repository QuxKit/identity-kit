// Breached-password screening, by k-anonymity.
//
// NIST SP 800-63B asks for two things: no composition rules (which is why
// `passwordProblem` only enforces a length floor), and screening candidates
// against known-breached lists. This is the second half, and it is opt-in
// because a library must not decide to make a network call on its own — the
// `fetch` is injected, so the host chooses the endpoint, the timeout, the proxy
// and whether it happens at all.
//
// The password never leaves the process. SHA-1 of the candidate is computed
// locally; only the first FIVE hex characters are sent; the API answers with
// every suffix in that bucket (about 800 of them) and the match is made here.
// SHA-1 is not a security choice — it is the range API's index, and the whole
// point is that the value sent is far too short to identify anything.
//
//   const breached = passwordBreached(fetch);
//   createIdentity({ ..., config: { ..., breachedPasswords: breached } });
//
// Availability is deliberate: when the API is unreachable the answer is "not
// known to be breached", because a third party being down must not stop people
// signing in or changing a password to something better. `strict: true` inverts
// that for a deployment that would rather fail closed.

import { createHash } from 'node:crypto';

/** The one method the library calls. Returns the number of times the password
 *  appears in the corpus (0 = not found). */
export type BreachedPasswordCheck = (password: string) => Promise<number>;

/** The slice of `fetch` this needs — a host can pass a wrapper with a timeout,
 *  a proxy agent, or a cache. */
export type FetchLike = (
  url: string,
  init?: { headers?: Record<string, string>; signal?: AbortSignal },
) => Promise<{
  ok: boolean;
  status: number;
  text(): Promise<string>;
}>;

export interface BreachedPasswordOptions {
  /** The range endpoint. Default Have I Been Pwned's. A self-hosted mirror of
   *  the same shape works unchanged. */
  endpoint?: string;
  /** Fail closed when the API cannot be reached (throws the underlying error).
   *  Default false: an unreachable third party does not block a login. */
  strict?: boolean;
  /** Ask the API to pad its response with decoy suffixes, so the response size
   *  does not leak how many hashes share the prefix. Default true. */
  padding?: boolean;
  /** Milliseconds before the request is abandoned. Default 2500. */
  timeoutMs?: number;
}

const DEFAULT_ENDPOINT = 'https://api.pwnedpasswords.com/range';
const DEFAULT_TIMEOUT_MS = 2500;

/**
 * Build the check. `fetchImpl` is required — passing the global `fetch`
 * explicitly is the point: it is visible in the host's code that this makes a
 * network call.
 */
export function passwordBreached(fetchImpl: FetchLike, opts: BreachedPasswordOptions = {}): BreachedPasswordCheck {
  const endpoint = (opts.endpoint ?? DEFAULT_ENDPOINT).replace(/\/+$/, '');
  const padding = opts.padding !== false;
  const timeoutMs = opts.timeoutMs ?? DEFAULT_TIMEOUT_MS;

  return async (password) => {
    const digest = createHash('sha1').update(password, 'utf8').digest('hex').toUpperCase();
    const prefix = digest.slice(0, 5);
    const suffix = digest.slice(5);

    let body: string;
    const controller = new AbortController();
    const timer = setTimeout(() => controller.abort(), timeoutMs);
    try {
      const headers: Record<string, string> = { 'user-agent': 'quxkit-identity-kit' };
      if (padding) headers['add-padding'] = 'true';
      const res = await fetchImpl(`${endpoint}/${prefix}`, { headers, signal: controller.signal });
      if (!res.ok) throw new Error(`breach range API responded ${res.status}`);
      body = await res.text();
    } catch (error) {
      // Fail open by default. A password screen that goes down must not become
      // an outage of signup, reset and password change all at once.
      if (opts.strict) throw error;
      return 0;
    } finally {
      clearTimeout(timer);
    }

    for (const line of body.split('\n')) {
      const separator = line.indexOf(':');
      if (separator < 0) continue;
      if (line.slice(0, separator).trim().toUpperCase() !== suffix) continue;
      const count = Number.parseInt(line.slice(separator + 1).trim(), 10);
      // A padded response carries decoys with a count of 0; those are not hits.
      return Number.isFinite(count) ? count : 0;
    }
    return 0;
  };
}
