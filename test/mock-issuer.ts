// A minimal OpenID Provider, in process, for the OIDC tests.
//
// It exists so `oidc.begin` / `oidc.complete` are exercised end to end —
// discovery, the authorization redirect, PKCE, the code exchange and an RS256
// ID token verified against a published JWK — without a network, a fixture, or
// a new dependency. Everything is `node:crypto` and `node:http`.
//
// It is a test double, not a product: it issues a code for whoever asks and
// verifies exactly the things the client is supposed to send, because those are
// the assertions. Where a real provider would be lenient, this one is not.

import {
  createHash,
  createPrivateKey,
  createPublicKey,
  createSign,
  generateKeyPairSync,
  randomBytes,
} from 'node:crypto';
import { createServer, type Server } from 'node:http';

const b64url = (input: Buffer | string): string =>
  (typeof input === 'string' ? Buffer.from(input, 'utf8') : input).toString('base64url');

export interface IssuedCode {
  code: string;
  nonce: string;
  codeChallenge: string | null;
  claims: Record<string, unknown>;
}

export interface MockIssuerOptions {
  clientId: string;
  clientSecret: string;
  /** Claims merged into every ID token (`sub` defaults to `mock-subject`). */
  claims?: Record<string, unknown>;
  /** Leave the `nonce` claim out of the ID token. */
  omitNonce?: boolean;
  /** Sign with a key that is NOT the published one. */
  wrongKey?: boolean;
  /** Return a token response with no `id_token`. */
  omitIdToken?: boolean;
}

export interface MockIssuer {
  url: string;
  /** What the authorize endpoint last received. */
  lastAuthorize: URLSearchParams | null;
  /** What the token endpoint last received. */
  lastToken: URLSearchParams | null;
  /** Codes still redeemable. */
  codes: Map<string, IssuedCode>;
  /** Drive the redirect the browser would make: returns the callback URL. */
  authorize(authorizationUrl: string): string;
  claims: Record<string, unknown>;
  close(): Promise<void>;
}

/** Start the issuer on an ephemeral port and wait until it is listening. */
export async function startMockIssuer(opts: MockIssuerOptions): Promise<MockIssuer> {
  const { privateKey, publicKey } = generateKeyPairSync('rsa', { modulusLength: 2048 });
  const other = generateKeyPairSync('rsa', { modulusLength: 2048 });
  const kid = 'mock-key-1';
  const jwk = { ...publicKey.export({ format: 'jwk' }), kid, use: 'sig', alg: 'RS256' };

  const state: MockIssuer = {
    url: '',
    lastAuthorize: null,
    lastToken: null,
    codes: new Map(),
    claims: { sub: 'mock-subject', email: 'oidc-user@example.com', email_verified: true, ...opts.claims },
    authorize: () => {
      throw new Error('not started');
    },
    close: async () => {},
  };

  const sign = (payload: Record<string, unknown>): string => {
    const header = { alg: 'RS256', typ: 'JWT', kid };
    const signingInput = `${b64url(JSON.stringify(header))}.${b64url(JSON.stringify(payload))}`;
    const signer = createSign('RSA-SHA256');
    signer.update(signingInput);
    const key = opts.wrongKey ? other.privateKey : privateKey;
    return `${signingInput}.${signer.sign(createPrivateKey(key.export({ type: 'pkcs8', format: 'pem' })), 'base64url')}`;
  };

  const server: Server = createServer(async (req, res) => {
    const url = new URL(req.url ?? '/', state.url || 'http://localhost');
    const send = (status: number, body: unknown) => {
      const json = JSON.stringify(body);
      res.writeHead(status, { 'content-type': 'application/json', 'content-length': Buffer.byteLength(json) });
      res.end(json);
    };

    if (url.pathname === '/.well-known/openid-configuration') {
      return send(200, {
        issuer: state.url,
        authorization_endpoint: `${state.url}/authorize`,
        token_endpoint: `${state.url}/token`,
        jwks_uri: `${state.url}/jwks`,
        response_types_supported: ['code'],
        subject_types_supported: ['public'],
        id_token_signing_alg_values_supported: ['RS256'],
        code_challenge_methods_supported: ['S256'],
        token_endpoint_auth_methods_supported: ['client_secret_basic', 'client_secret_post'],
      });
    }

    if (url.pathname === '/jwks') return send(200, { keys: [jwk] });

    if (url.pathname === '/token') {
      const raw = await new Promise<string>((resolve) => {
        const chunks: Buffer[] = [];
        req.on('data', (c: Buffer) => chunks.push(c));
        req.on('end', () => resolve(Buffer.concat(chunks).toString('utf8')));
      });
      const params = new URLSearchParams(raw);
      state.lastToken = params;
      // Client authentication: Basic, or the body.
      const auth = req.headers.authorization;
      const basic = auth?.startsWith('Basic ')
        ? Buffer.from(auth.slice(6), 'base64').toString('utf8').split(':')
        : null;
      const clientId = basic ? decodeURIComponent(basic[0] ?? '') : params.get('client_id');
      const clientSecret = basic ? decodeURIComponent(basic[1] ?? '') : params.get('client_secret');
      if (clientId !== opts.clientId || clientSecret !== opts.clientSecret) {
        return send(401, { error: 'invalid_client' });
      }
      const issued = state.codes.get(params.get('code') ?? '');
      if (!issued) return send(400, { error: 'invalid_grant' });
      state.codes.delete(issued.code);
      // PKCE: the verifier must hash to the challenge sent at authorize time.
      if (issued.codeChallenge) {
        const verifier = params.get('code_verifier') ?? '';
        const computed = createHash('sha256').update(verifier).digest('base64url');
        if (computed !== issued.codeChallenge) return send(400, { error: 'invalid_grant', reason: 'pkce' });
      }
      const now = Math.floor(Date.now() / 1000);
      const idToken = sign({
        iss: state.url,
        aud: opts.clientId,
        iat: now,
        exp: now + 300,
        ...(opts.omitNonce ? {} : { nonce: issued.nonce }),
        ...issued.claims,
      });
      return send(200, {
        access_token: b64url(randomBytes(24)),
        token_type: 'Bearer',
        expires_in: 300,
        ...(opts.omitIdToken ? {} : { id_token: idToken }),
      });
    }

    send(404, { error: 'not_found' });
  });

  await new Promise<void>((resolve) => server.listen(0, '127.0.0.1', resolve));
  const address = server.address();
  if (!address || typeof address !== 'object') throw new Error('mock issuer did not bind');
  state.url = `http://127.0.0.1:${address.port}`;

  state.authorize = (authorizationUrl) => {
    const url = new URL(authorizationUrl);
    state.lastAuthorize = url.searchParams;
    const code = b64url(randomBytes(18));
    state.codes.set(code, {
      code,
      nonce: url.searchParams.get('nonce') ?? '',
      codeChallenge: url.searchParams.get('code_challenge'),
      claims: state.claims,
    });
    const redirect = new URL(url.searchParams.get('redirect_uri') ?? 'https://app.test/callback');
    redirect.searchParams.set('code', code);
    const returnedState = url.searchParams.get('state');
    if (returnedState) redirect.searchParams.set('state', returnedState);
    return redirect.href;
  };
  state.close = () => new Promise<void>((resolve) => server.close(() => resolve()));
  // Referenced so the unused-binding lint does not fire on the second key pair.
  void createPublicKey(other.publicKey.export({ type: 'spki', format: 'pem' }));
  return state;
}
