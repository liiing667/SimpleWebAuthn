import type { Base64URLString } from '../types/index.ts';
import { isoBase64URL } from '../helpers/iso/index.ts';

/**
 * A registration challenge remembered by {@link RegistrationChallengeService}.
 */
export type RegistrationChallengeRecord = {
  challenge: Base64URLString;
  userID: Base64URLString;
  /** Internal key used to group credentials for retry/exclude purposes */
  trackingKey: string;
  /**
   * Whether the RP supplied a stable user ID when generating the options. Challenges for
   * registrations that only used a randomly-generated user ID can still be made single-use, but
   * they can't be used to enforce global credential-ID uniqueness because there's no stable user
   * identity to bind the credential to.
   */
  userIDWasProvided: boolean;
  expiresAt: number;
  status: 'pending' | 'used';
};

/**
 * The result of trying to consume a registration challenge.
 *
 * `tracked: false` means the challenge wasn't issued by this process's
 * {@link RegistrationChallengeService} (for example, an RP-managed challenge). Such challenges
 * retain the library's historical behavior so that RPs which manage challenge storage themselves
 * aren't surprised by this in-process ledger.
 */
export type RegistrationChallengeConsumption =
  | { tracked: false }
  | {
    tracked: true;
    status: 'available';
    record: RegistrationChallengeRecord;
  }
  | {
    tracked: true;
    status: 'used' | 'expired';
    record: RegistrationChallengeRecord;
  };

/**
 * A credential ID that has already been consumed for registration.
 */
export type RegistrationCredentialRecord = {
  credentialID: Base64URLString;
  userID?: Base64URLString;
  trackingKey: string;
  userIDWasProvided: boolean;
  transports?: string[];
  expiresAt: number;
};

export type RegistrationCredentialConsumption =
  | { consumed: true; record: RegistrationCredentialRecord }
  | { consumed: false; record: RegistrationCredentialRecord };

interface RegistrationChallengeService {
  /**
   * Remember a challenge issued by `generateRegistrationOptions()`. The challenge can be
   * consumed exactly once by `verifyRegistrationResponse()`.
   */
  rememberChallenge(opts: {
    challenge: string;
    userID: Base64URLString;
    trackingKey?: string;
    userIDWasProvided: boolean;
    timeoutMS?: number;
  }): void;
  /**
   * Atomically consume a registration challenge.
   *
   * The pending -> used transition happens synchronously, before
   * `verifyRegistrationResponse()` performs any additional async work. This ensures that
   * concurrent submissions of the same challenge can't each begin verification.
   */
  consumeChallenge(challenge: string): RegistrationChallengeConsumption;
  /**
   * Atomically consume a credential ID. A credential ID can only be registered once, even if an
   * attacker pairs the same authenticator data with a fresh registration challenge for another
   * account.
   */
  consumeCredential(opts: {
    credentialID: string;
    userID?: Base64URLString;
    trackingKey?: string;
    userIDWasProvided?: boolean;
    transports?: string[];
  }): RegistrationCredentialConsumption;
  /**
   * Look up a previously consumed credential ID without consuming it.
   */
  getCredential(credentialID: string): RegistrationCredentialRecord | undefined;
  /**
   * Return credential IDs that have already been consumed for a specific user. This lets
   * `generateRegistrationOptions()` keep them in `excludeCredentials` even when the RP hasn't
   * finished saving the credential yet (for example, after a save timeout).
   */
  getCredentialsForUser(trackingKey: string): RegistrationCredentialRecord[];
  /**
   * Forget all remembered challenges and consumed credential IDs. Primarily useful in tests and
   * for long-running processes that intentionally want to start from a clean slate.
   */
  reset(): void;
}

/** How long a used challenge or credential ID is remembered for replay detection */
const REPLAY_RETENTION_MS = 24 * 60 * 60 * 1000;
/** A small floor keeps very short WebAuthn timeouts from making registrations needlessly flaky */
const MIN_CHALLENGE_LIFETIME_MS = 5 * 60 * 1000;

class BaseRegistrationChallengeService implements RegistrationChallengeService {
  private challenges = new Map<string, RegistrationChallengeRecord>();
  private credentials = new Map<string, RegistrationCredentialRecord>();

  rememberChallenge(opts: {
    challenge: string;
    userID: Base64URLString;
    trackingKey?: string;
    userIDWasProvided: boolean;
    timeoutMS?: number;
  }): void {
    const { challenge, userID, trackingKey, userIDWasProvided, timeoutMS } = opts;

    this.pruneExpired();

    const challengeKey = this.normalize(challenge);
    const timeout = typeof timeoutMS === 'number' && Number.isFinite(timeoutMS)
      ? timeoutMS
      : 60_000;

    // Never revive a challenge that has already been consumed. A caller that reuses a custom
    // challenge must not get a second usable registration window out of it.
    if (this.challenges.get(challengeKey)?.status === 'used') {
      return;
    }

    this.challenges.set(challengeKey, {
      challenge: challengeKey,
      userID: this.normalize(userID),
      trackingKey: trackingKey ?? `user:${this.normalize(userID)}`,
      userIDWasProvided,
      expiresAt: Date.now() + Math.max(timeout, MIN_CHALLENGE_LIFETIME_MS),
      status: 'pending',
    });
  }

  consumeChallenge(challenge: string): RegistrationChallengeConsumption {
    this.pruneExpired();

    const challengeKey = this.normalize(challenge);
    const record = this.challenges.get(challengeKey);
    if (!record) {
      return { tracked: false };
    }

    if (record.status === 'used') {
      return { tracked: true, status: 'used', record };
    }

    if (Date.now() > record.expiresAt) {
      record.status = 'used';
      record.expiresAt = Date.now() + REPLAY_RETENTION_MS;
      return { tracked: true, status: 'expired', record };
    }

    record.status = 'used';
    // Keep a tombstone around so a replay of this challenge is rejected even after its original
    // WebAuthn timeout has elapsed
    record.expiresAt = Date.now() + REPLAY_RETENTION_MS;
    return { tracked: true, status: 'available', record };
  }

  consumeCredential(opts: {
    credentialID: string;
    userID?: Base64URLString;
    trackingKey?: string;
    userIDWasProvided?: boolean;
    transports?: string[];
  }): RegistrationCredentialConsumption {
    const {
      credentialID,
      userID,
      trackingKey,
      userIDWasProvided = false,
      transports,
    } = opts;

    this.pruneExpired();

    const credentialKey = this.normalize(credentialID);
    const existing = this.credentials.get(credentialKey);
    if (existing) {
      return { consumed: false, record: existing };
    }

    const record: RegistrationCredentialRecord = {
      credentialID: credentialKey,
      userID: userID ? this.normalize(userID) : undefined,
      trackingKey: trackingKey ?? (userID ? `user:${this.normalize(userID)}` : credentialKey),
      userIDWasProvided,
      transports: transports ? [...transports] : undefined,
      expiresAt: Date.now() + REPLAY_RETENTION_MS,
    };
    this.credentials.set(credentialKey, record);

    return { consumed: true, record };
  }

  getCredential(credentialID: string): RegistrationCredentialRecord | undefined {
    this.pruneExpired();
    return this.credentials.get(this.normalize(credentialID));
  }

  getCredentialsForUser(trackingKey: string): RegistrationCredentialRecord[] {
    this.pruneExpired();

    const normalized = this.normalize(trackingKey);
    const credentials: RegistrationCredentialRecord[] = [];
    for (const record of this.credentials.values()) {
      if (record.trackingKey === trackingKey || record.userID === normalized) {
        credentials.push(record);
      }
    }

    return credentials;
  }

  reset(): void {
    this.challenges.clear();
    this.credentials.clear();
  }

  /**
   * Normalize base64url values so a padded and unpadded representation of the same value share a
   * single ledger entry.
   */
  private normalize(value: string): string {
    return isoBase64URL.trimPadding(value);
  }

  private pruneExpired(): void {
    const now = Date.now();
    for (const [key, record] of this.challenges) {
      // Keep expired records as tombstones while they're still within the replay-retention
      // window. `consumeChallenge()` needs to see them to reject a replay.
      if (record.expiresAt + REPLAY_RETENTION_MS < now) {
        this.challenges.delete(key);
      }
    }
    for (const [key, record] of this.credentials) {
      if (record.expiresAt + REPLAY_RETENTION_MS < now) {
        this.credentials.delete(key);
      }
    }
  }
}

/**
 * A small in-process ledger that makes registration challenges and credential IDs single-use.
 *
 * WebAuthn's `"none"` attestation format doesn't sign `clientDataJSON`, so an attacker who
 * captures an attestation object can pair it with a fresh challenge and replay it during another
 * account's registration. Likewise, a client that times out while trying to save a valid
 * registration may retry and cause a second authenticator credential to be created. Consuming the
 * challenge as soon as it matches, and consuming the resulting credential ID exactly once, keeps
 * both flows idempotent.
 *
 * This service intentionally mirrors the shape of `SettingsService`: it's a process-local
 * singleton that works out of the box, while RPs that run multiple server instances should also
 * enforce challenge and credential-ID uniqueness in their shared database.
 */
export const RegistrationChallengeService: RegistrationChallengeService =
  new BaseRegistrationChallengeService();
