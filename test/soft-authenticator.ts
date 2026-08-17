// A software WebAuthn authenticator, for the passkey tests.
//
// It does what a platform authenticator does, minus the hardware: mints a P-256
// key per credential, answers `create` with a `none`-attestation registration
// response and `get` with a signed assertion, and keeps a signature counter. It
// is deliberately configurable in the ways an attacker would be — the counter
// can be pinned or rewound, the origin or RP id lied about, user verification
// left off — so the tests can drive every refusal path.
//
// CBOR encoding comes from @simplewebauthn/server's own helpers, so the bytes
// are what the verifier expects; the crypto is node:crypto.

import { createHash, generateKeyPairSync, type KeyObject, randomBytes, sign } from 'node:crypto';
import type {
  AuthenticationResponseJSON,
  PublicKeyCredentialCreationOptionsJSON,
  PublicKeyCredentialRequestOptionsJSON,
  RegistrationResponseJSON,
} from '@simplewebauthn/server';
import { isoBase64URL, isoCBOR } from '@simplewebauthn/server/helpers';

const FLAG_UP = 0x01;
const FLAG_UV = 0x04;
const FLAG_BE = 0x08;
const FLAG_BS = 0x10;
const FLAG_AT = 0x40;

const b64 = (bytes: Uint8Array) => isoBase64URL.fromBuffer(new Uint8Array(bytes));
const sha = (data: Uint8Array | string) => new Uint8Array(createHash('sha256').update(data).digest());
const u32 = (n: number) => {
  const b = new Uint8Array(4);
  new DataView(b.buffer).setUint32(0, n, false);
  return b;
};
const concat = (...parts: Uint8Array[]) => {
  const out = new Uint8Array(parts.reduce((n, p) => n + p.length, 0));
  let o = 0;
  for (const p of parts) {
    out.set(p, o);
    o += p.length;
  }
  return out;
};

export interface StoredCredential {
  id: Uint8Array;
  privateKey: KeyObject;
  publicKey: KeyObject;
  counter: number;
  userHandle: Uint8Array;
}

export interface CeremonyOverrides {
  /** Lie about the origin in clientDataJSON. */
  origin?: string;
  /** Lie about the RP id (hash) in authenticator data. */
  rpId?: string;
  /** Claim no user verification. */
  uv?: boolean;
  /** Present exactly this counter (rewind / replay). */
  counter?: number;
  /** Which credential to assert with (defaults to the first allowed / the only one). */
  credentialId?: string;
}

export class SoftAuthenticator {
  readonly credentials = new Map<string, StoredCredential>();
  /** The AAGUID this "model" reports. */
  readonly aaguid = new Uint8Array(16).fill(0xab);

  constructor(
    readonly rpId: string,
    readonly origin: string,
  ) {}

  create(options: PublicKeyCredentialCreationOptionsJSON, over: CeremonyOverrides = {}): RegistrationResponseJSON {
    const { privateKey, publicKey } = generateKeyPairSync('ec', { namedCurve: 'P-256' });
    const id = new Uint8Array(randomBytes(32));
    const userHandle = isoBase64URL.toBuffer(options.user.id);
    const cred: StoredCredential = { id, privateKey, publicKey, counter: 0, userHandle };
    this.credentials.set(b64(id), cred);

    const jwk = publicKey.export({ format: 'jwk' });
    // COSE_Key for ES256: kty EC2(2), alg ES256(-7), crv P-256(1), x, y.
    const cose = new Map<number, number | Uint8Array>([
      [1, 2],
      [3, -7],
      [-1, 1],
      [-2, isoBase64URL.toBuffer(jwk.x as string)],
      [-3, isoBase64URL.toBuffer(jwk.y as string)],
    ]);
    const cosePublicKey = isoCBOR.encode(cose);
    const flags = FLAG_UP | FLAG_AT | FLAG_BE | FLAG_BS | (over.uv === false ? 0 : FLAG_UV);
    const idLen = new Uint8Array(2);
    new DataView(idLen.buffer).setUint16(0, id.length, false);
    const authData = concat(
      sha(over.rpId ?? this.rpId),
      new Uint8Array([flags]),
      u32(0),
      this.aaguid,
      idLen,
      id,
      cosePublicKey,
    );
    const clientDataJSON = new TextEncoder().encode(
      JSON.stringify({
        type: 'webauthn.create',
        challenge: options.challenge,
        origin: over.origin ?? this.origin,
        crossOrigin: false,
      }),
    );
    const attestationObject = isoCBOR.encode(
      new Map<string, string | Uint8Array | Map<string, never>>([
        ['fmt', 'none'],
        ['attStmt', new Map<string, never>()],
        ['authData', authData],
      ]),
    );
    return {
      id: b64(id),
      rawId: b64(id),
      type: 'public-key',
      clientExtensionResults: {},
      authenticatorAttachment: 'platform',
      response: {
        clientDataJSON: b64(clientDataJSON),
        attestationObject: b64(attestationObject),
        transports: ['internal', 'hybrid'],
      },
    };
  }

  get(options: PublicKeyCredentialRequestOptionsJSON, over: CeremonyOverrides = {}): AuthenticationResponseJSON {
    const wanted = over.credentialId ?? options.allowCredentials?.[0]?.id ?? [...this.credentials.keys()][0];
    const cred = wanted ? this.credentials.get(wanted) : undefined;
    if (!cred) throw new Error(`soft authenticator: no credential ${wanted}`);
    if (over.counter === undefined) cred.counter += 1;
    const counter = over.counter ?? cred.counter;
    const flags = FLAG_UP | FLAG_BE | FLAG_BS | (over.uv === false ? 0 : FLAG_UV);
    const authData = concat(sha(over.rpId ?? this.rpId), new Uint8Array([flags]), u32(counter));
    const clientDataJSON = new TextEncoder().encode(
      JSON.stringify({
        type: 'webauthn.get',
        challenge: options.challenge,
        origin: over.origin ?? this.origin,
        crossOrigin: false,
      }),
    );
    const signature = sign('sha256', concat(authData, sha(clientDataJSON)), {
      key: cred.privateKey,
      dsaEncoding: 'der',
    });
    return {
      id: b64(cred.id),
      rawId: b64(cred.id),
      type: 'public-key',
      clientExtensionResults: {},
      authenticatorAttachment: 'platform',
      response: {
        clientDataJSON: b64(clientDataJSON),
        authenticatorData: b64(authData),
        signature: b64(new Uint8Array(signature)),
        userHandle: b64(cred.userHandle),
      },
    };
  }
}
