// identity-kit/oidc — Sign in with Google, Apple, or any OpenID Connect provider.
//
// The protocol is NOT hand-rolled: discovery, PKCE, state, nonce, code exchange
// and ID-token validation are openid-client's, a vetted implementation. What
// identity-kit owns is the one part that is application-specific and a takeover
// vector if wrong — the account-linking policy in oidc-link.ts. Everything here
// is the thin wiring between the two.
//
// The flow, and where the host holds state:
//
//   const { url, state, nonce, codeVerifier } = await oidc.begin('google');
//   // stash state/nonce/codeVerifier in the user's session; redirect to url
//   // ...provider redirects back to your callback...
//   const { outcome } = await oidc.complete('google', req.url, { state, nonce, codeVerifier });
//   if (outcome.kind === 'ok') mintSessionFor(outcome.userId);   // via the identity core
//
// `complete` deliberately does NOT mint a session — the host decides what a new
// vs linked user gets (onboarding, a welcome), and session minting is the
// identity core's job (createSession). OAuth stands in for the password, not for
// the whole login.

import * as oauth from 'openid-client';

import { IdentityError } from './errors.ts';
import { type LinkResult, linkOrCreate, type ProviderClaims } from './oidc-link.ts';
import type { Clock, SqlExecutor } from './types.ts';

export interface OidcProvider {
  /** The issuer URL — `https://accounts.google.com`, `https://appleid.apple.com`. */
  issuer: string;
  clientId: string;
  /** The client secret. For Apple this is the signed JWT client secret the host
   *  generates; identity-kit takes it as an already-formed string. */
  clientSecret?: string;
  redirectUri: string;
  /** Defaults to `openid email profile`. `email` is required — this schema cannot
   *  create a user without one. */
  scopes?: readonly string[];
}

export interface OidcOptions {
  db: SqlExecutor;
  providers: Record<string, OidcProvider>;
  clock?: Clock;
}

export interface BeginResult {
  /** Redirect the browser here. */
  url: string;
  /** Stash these until the callback — they bind this request to its response and
   *  are what make it CSRF- and replay-safe. */
  state: string;
  nonce: string;
  codeVerifier: string;
}

export interface VerifiedClaims {
  subject: string;
  email: string | null;
  emailVerified: boolean;
}

export interface OidcResult {
  outcome: LinkResult;
  claims: VerifiedClaims;
}

export interface Oidc {
  begin(provider: string): Promise<BeginResult>;
  complete(
    provider: string,
    callbackUrl: string,
    checks: { state: string; nonce: string; codeVerifier: string },
  ): Promise<OidcResult>;
}

export function createOidc(opts: OidcOptions): Oidc {
  const clock: Clock = opts.clock ?? (() => new Date());
  // Discovery is a network round trip; cache the Configuration per provider.
  const configs = new Map<string, Promise<oauth.Configuration>>();

  const providerConfig = (name: string): OidcProvider => {
    const p = opts.providers[name];
    if (!p) throw new IdentityError({ code: 'unknown_provider', provider: name });
    return p;
  };

  const discover = (name: string): Promise<oauth.Configuration> => {
    let c = configs.get(name);
    if (!c) {
      const p = providerConfig(name);
      c = oauth.discovery(new URL(p.issuer), p.clientId, p.clientSecret);
      configs.set(name, c);
    }
    return c;
  };

  return {
    async begin(name) {
      const p = providerConfig(name);
      const config = await discover(name);
      const codeVerifier = oauth.randomPKCECodeVerifier();
      const codeChallenge = await oauth.calculatePKCECodeChallenge(codeVerifier);
      const state = oauth.randomState();
      const nonce = oauth.randomNonce();
      const url = oauth.buildAuthorizationUrl(config, {
        redirect_uri: p.redirectUri,
        scope: (p.scopes ?? ['openid', 'email', 'profile']).join(' '),
        state,
        nonce,
        code_challenge: codeChallenge,
        code_challenge_method: 'S256',
      });
      return { url: url.href, state, nonce, codeVerifier };
    },

    async complete(name, callbackUrl, checks) {
      const config = await discover(name);
      // openid-client verifies the state, the nonce, the PKCE binding and the ID
      // token's signature, issuer and audience — the checks that, skipped, are
      // the account-takeover bugs.
      const tokens = await oauth.authorizationCodeGrant(config, new URL(callbackUrl), {
        expectedState: checks.state,
        expectedNonce: checks.nonce,
        pkceCodeVerifier: checks.codeVerifier,
      });
      const idClaims = tokens.claims();
      if (!idClaims) throw new IdentityError({ code: 'no_id_token' });

      const email = typeof idClaims.email === 'string' ? idClaims.email : null;
      // Google sends a boolean; Apple sends the string "true". Coerce both.
      const emailVerified = idClaims.email_verified === true || idClaims.email_verified === 'true';
      const claims: VerifiedClaims = { subject: idClaims.sub, email, emailVerified };

      const providerClaims: ProviderClaims = {
        provider: name,
        subject: claims.subject,
        email: claims.email,
        emailVerified: claims.emailVerified,
      };
      const outcome = await linkOrCreate(opts.db, providerClaims, clock());
      return { outcome, claims };
    },
  };
}

export type { LinkResult, ProviderClaims } from './oidc-link.ts';
export { linkOrCreate } from './oidc-link.ts';
