// Outbound mail — composed here, delivered by the host.
//
// Every flow sends on both branches (the address exists and the address does
// not), so the *shape* of what is sent is a security property of this library:
// it is what makes signup and password-reset enumeration-safe. Which relay
// carries it is not, so the transport is a seam (`MailSender`) the host fills.
//
// The bodies are plain text and short. An HTML template layer is a product
// decision, not an auth one, and belongs to the host.

import type { IdentityConfig, MailSender } from './types.ts';

export interface Mailer {
  verifyAddress(to: string, token: string): Promise<void>;
  alreadyRegistered(to: string): Promise<void>;
  resetPassword(to: string, token: string): Promise<void>;
  resetUnknownAddress(to: string): Promise<void>;
  passwordChanged(to: string): Promise<void>;
  newDeviceSignIn(to: string, where: string): Promise<void>;
  deletionRequested(to: string, token: string): Promise<void>;
  /** Used by identity-kit/mfa when a recovery code is spent. */
  recoveryCodeUsed(to: string, remaining: number): Promise<void>;
}

export function createMailer(config: IdentityConfig, sender: MailSender): Mailer {
  const link = (path: string, token: string) => `${config.appUrl}${path}?token=${encodeURIComponent(token)}`;
  const url = (path: string) => `${config.appUrl}${path}`;

  return {
    verifyAddress: (to, token) =>
      sender.send({
        to,
        subject: 'Confirm your email address',
        body:
          `Confirm this address to finish setting up your account:\n\n` +
          `${link('/verify-email', token)}\n\n` +
          `The link is valid for 24 hours. Confirming does not sign you in — ` +
          `you will be asked for your password afterwards.`,
      }),

    // Sent when someone tries to sign up with an address that already has an
    // account. This is what makes the identical response on both paths honest:
    // the person who forgot they had an account gets something more useful than
    // "already registered", and a probe learns nothing.
    alreadyRegistered: (to) =>
      sender.send({
        to,
        subject: 'Someone tried to create an account with this address',
        body:
          `This address already has an account, so no new one was created.\n\n` +
          `Sign in:  ${url('/login')}\n` +
          `Forgot your password:  ${url('/reset')}\n\n` +
          `If this was not you, no action is needed.`,
      }),

    resetPassword: (to, token) =>
      sender.send({
        to,
        subject: 'Reset your password',
        body:
          `Reset your password:\n\n${link('/reset-password', token)}\n\n` +
          `The link is valid for 15 minutes and can be used once. If you did not ` +
          `ask for it, someone knows your email address and nothing more.`,
      }),

    // Deliberately sent to an address with no account. Safe, because it goes
    // only to the address itself, and it closes the loop for someone who
    // mistyped which of their addresses they signed up with.
    resetUnknownAddress: (to) =>
      sender.send({
        to,
        subject: 'Password reset requested',
        body:
          `Someone asked to reset a password for this address, but there is no ` +
          `account here. You may have signed up with a different address.\n\n` +
          `Create an account:  ${url('/signup')}`,
      }),

    passwordChanged: (to) =>
      sender.send({
        to,
        subject: 'Your password was changed',
        body:
          `Your password has just been changed and every session has been signed ` +
          `out.\n\nIf this was not you, reset your password immediately: ${url('/reset')}`,
      }),

    newDeviceSignIn: (to, where) =>
      sender.send({
        to,
        subject: 'New sign-in to your account',
        body:
          `A new sign-in was recorded from ${where}.\n\n` +
          `If this was not you, change your password and sign out all sessions: ` +
          `${url('/settings/sessions')}`,
      }),

    deletionRequested: (to, token) =>
      sender.send({
        to,
        subject: 'Your account is scheduled for deletion',
        body:
          `Your account will be deleted in 7 days. Until then you can cancel:\n\n` +
          `${link('/cancel-deletion', token)}\n\n` +
          `If you did not request this, cancel now and change your password.`,
      }),

    recoveryCodeUsed: (to, remaining) =>
      sender.send({
        to,
        subject: 'A recovery code was used on your account',
        body:
          `A recovery code was used to sign in. ${remaining} remain.\n\n` +
          `If this was not you, your second factor is compromised: ${url('/settings/security')}`,
      }),
  };
}
