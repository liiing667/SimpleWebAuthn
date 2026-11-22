import type { Base64URLString } from '../types/index.ts';
import { isoBase64URL } from '../helpers/iso/index.ts';

export type RegistrationChallengeRecord = {
  challenge: Base64URLString;
  userID?: Base64URLString;
  createdAt: number;
  expiresAt: number;
  status: 'pending' | 'used' | 'expired';
};

export type RegistrationChallengeConsumption =
  | { tracked: false }
  | {
    tracked: true;
    status: 'available' | 'used' | 'expired';
    record: RegistrationChallengeRecord;
  };

const REPLAY_RETENTION_MS = 24 * 60 * 60 * 1000;
const MIN_CHALLENGE_LIFETIME_MS = 5 * 60 * 1000;

/**
 * A small in-process ledger that makes registration challenges single-use and remembers the
 * user ID they were generated for. This lets `verifyRegistrationResponse()` return the same
 * credential owner that will later be used by authentication.
 */
class BaseRegistrationChallengeService {
  private readonly records = new Map<string, RegistrationChallengeRecord>();

  rememberChallenge(opts: {
    challenge: string;
    userID?: Base64URLString;
    timeoutMS?: number;
  }): void {
    this.pruneExpired();

    const existing = this.records.get(opts.challenge);
    if (existing?.status === 'used') {
      return;
    }

    const timeout = typeof opts.timeoutMS === 'number' && Number.isFinite(opts.timeoutMS)
      ? opts.timeoutMS
      : 60_000;
    this.records.set(opts.challenge, {
      challenge: opts.challenge,
      userID: opts.userID ? isoBase64URL.trimPadding(opts.userID) : undefined,
      createdAt: Date.now(),
      expiresAt: Date.now() + Math.max(timeout, MIN_CHALLENGE_LIFETIME_MS),
      status: 'pending',
    });
  }

  consumeChallenge(challenge: string): RegistrationChallengeConsumption {
    this.pruneExpired();

    const record = this.records.get(challenge);
    if (!record) {
      return { tracked: false };
    }

    if (record.status === 'used') {
      return { tracked: true, status: 'used', record };
    }

    if (record.status === 'expired' || Date.now() > record.expiresAt) {
      record.status = 'expired';
      record.expiresAt = Date.now() + REPLAY_RETENTION_MS;
      return { tracked: true, status: 'expired', record };
    }

    record.status = 'used';
    record.expiresAt = Date.now() + REPLAY_RETENTION_MS;
    return { tracked: true, status: 'available', record };
  }

  getChallenge(challenge: string): RegistrationChallengeRecord | undefined {
    this.pruneExpired();
    return this.records.get(challenge);
  }

  reset(): void {
    this.records.clear();
  }

  /** Alias for {@link reset}. */
  restart(): void {
    this.reset();
  }

  private pruneExpired(): void {
    const now = Date.now();
    for (const [key, record] of this.records) {
      if (record.expiresAt + REPLAY_RETENTION_MS < now) {
        this.records.delete(key);
      }
    }
  }
}

/**
 * Process-local registration challenge ledger.
 */
export const RegistrationChallengeService = new BaseRegistrationChallengeService();
