// Typed failures.
//
// Same rule as the rest of the family: errors are a discriminated union, never a
// message string. A caller deciding what to show — "your current password is
// wrong" vs "that link has expired" — must not make the decision by matching
// prose that changes the first time someone improves the wording.
//
// Note what is NOT an error here: an email already being registered. That is
// never surfaced to the caller, by design — a `409 already registered` turns
// signup into an oracle for who has an account. Enumeration-safety is a property
// of the return types, so the failure that would break it has no code to throw.

export type IdentityFailure =
  | { code: 'weak_password'; reason: string }
  | { code: 'bad_credentials' }
  | { code: 'no_password' }
  /** A stored hash was made with a pepper version this process does not hold.
   *  Rotation needs the old key present; surfaced rather than failed as a wrong
   *  password so the operational cause is legible. */
  | { code: 'pepper_version'; stored: number; current: number }
  | { code: 'not_found'; what: string };

export type IdentityErrorCode = IdentityFailure['code'];

function describe(failure: IdentityFailure): string {
  switch (failure.code) {
    case 'weak_password':
      return failure.reason;
    case 'bad_credentials':
      return 'The current password is incorrect.';
    case 'no_password':
      return 'This account has no password set.';
    case 'pepper_version':
      return (
        `password hash was made with pepper version ${failure.stored}, this process holds ` +
        `version ${failure.current}. Rotation needs the old key present.`
      );
    case 'not_found':
      return `no ${failure.what}`;
  }
}

/** The one error class. Carries the union; the message is derived from it. */
export class IdentityError extends Error {
  readonly failure: IdentityFailure;
  readonly code: IdentityErrorCode;

  constructor(failure: IdentityFailure) {
    super(describe(failure));
    this.name = 'IdentityError';
    this.failure = failure;
    this.code = failure.code;
  }

  /** Narrow without instanceof, which fails across duplicated module copies. */
  static is(error: unknown): error is IdentityError {
    return error instanceof Error && error.name === 'IdentityError' && 'failure' in error;
  }

  static hasCode<C extends IdentityErrorCode>(
    error: unknown,
    code: C,
  ): error is IdentityError & { failure: Extract<IdentityFailure, { code: C }> } {
    return IdentityError.is(error) && error.code === code;
  }
}
