import type { Base64URLString } from '../types/index.ts';
import { isoBase64URL, isoCrypto } from '../helpers/iso/index.ts';
import { toHash } from '../helpers/toHash.ts';

/**
 * The identity information frozen when authentication options are generated.
 */
export type AuthenticationChallengeBinding = {
  /** Credential IDs the RP offered via `allowCredentials`, if any. */
  credentialIDs?: Base64URLString[];
  /** The owner of each offered credential, when the RP knows it. */
  credentialOwners?: Record<string, Base64URLString>;
  /** User identities accepted for this challenge. */
  userIDs?: Base64URLString[];
  /**
   * Whether verification must be able to prove which user the response belongs to. This is set
   * automatically when the RP provides owner/user identity information.
   */
  requireUserBinding?: boolean;
};

export type AuthenticationChallengeStatus =
  | 'pending'
  | 'used'
  | 'cancelled'
  | 'expired';

export type AuthenticationChallengeEnvelope = {
  v: 1;
  /** Process generation that issued the challenge. */
  g: number;
  /** Random public nonce used to identify the challenge. */
  n: Base64URLString;
  /** Random record tag checked against the stored record. */
  t: Base64URLString;
  /** The caller-provided challenge before it was wrapped. */
  c: Base64URLString;
};

export type AuthenticationChallengeRecord = {
  /** The challenge value the client was asked to sign, including any envelope. */
  challenge: Base64URLString;
  /** The caller-provided challenge that is wrapped by {@link challenge}. */
  baseChallenge: Base64URLString;
  /** Digest used by audit reports. The raw challenge is never exposed in a report. */
  challengeID: Base64URLString;
  rpID: string;
  generation: number;
  createdAt: number;
  expiresAt: number;
  status: AuthenticationChallengeStatus;
  binding: AuthenticationChallengeBinding;
  envelope?: AuthenticationChallengeEnvelope;
  consumedBy?: {
    credentialID: Base64URLString;
    userID?: Base64URLString;
    userHandle?: Base64URLString;
  };
};

export type AuthenticationChallengeConsumptionStatus =
  | 'available'
  | 'used'
  | 'expired'
  | 'cancelled'
  | 'missing'
  | 'stale_generation';

export type AuthenticationChallengeConsumption = {
  /**
   * False means the challenge was not issued by this process. Such legacy challenges retain the
   * library's historical stateless behavior.
   */
  tracked: boolean;
  status: AuthenticationChallengeConsumptionStatus;
  record?: AuthenticationChallengeRecord;
  challengeID: Base64URLString;
  generation?: number;
};

/** Replay tombstones are retained long enough to reject late retries. */
const REPLAY_RETENTION_MS = 24 * 60 * 60 * 1000;
/** Avoid expiring a challenge while a user is still completing the browser ceremony. */
const MIN_CHALLENGE_LIFETIME_MS = 5 * 60 * 1000;
/** Bound memory use in long-running processes. */
const MAX_RECORDS = 10_000;

function randomGeneration(): number {
  return Date.now() + Math.floor(Math.random() * 1_000_000);
}

async function randomBase64URL(byteLength: number): Promise<Base64URLString> {
  const bytes = new Uint8Array(byteLength);
  await isoCrypto.getRandomValues(bytes);
  return isoBase64URL.fromBuffer(bytes);
}

function decodeEnvelope(
  challenge: string,
): AuthenticationChallengeEnvelope | undefined {
  try {
    const decoded = JSON.parse(isoBase64URL.toUTF8String(challenge));
    if (
      decoded &&
      decoded.v === 1 &&
      typeof decoded.g === 'number' &&
      typeof decoded.n === 'string' &&
      typeof decoded.t === 'string' &&
      typeof decoded.c === 'string'
    ) {
      return decoded as AuthenticationChallengeEnvelope;
    }
  } catch {
    // Not one of our envelopes.
  }

  return undefined;
}

function encodeEnvelope(envelope: AuthenticationChallengeEnvelope): Base64URLString {
  return isoBase64URL.fromUTF8String(JSON.stringify(envelope));
}

/**
 * A process-local ledger of authentication challenges and the user/credential identities they
 * were issued for.
 *
 * SimpleWebAuthn does not own an RP's session database, but it can make the challenge ->
 * verification handoff safe. A challenge issued with identity binding is wrapped in an opaque
 * envelope so it cannot be replayed after a process restart, and it can only be consumed once.
 * RPs running multiple server instances should enforce the same unique-consumption rule in their
 * shared session/challenge store.
 */
class BaseAuthenticationChallengeService {
  private readonly records = new Map<string, AuthenticationChallengeRecord>();
  private _generation = randomGeneration();

  get generation(): number {
    return this._generation;
  }

  get currentGeneration(): number {
    return this._generation;
  }

  /**
   * Issue a challenge. When any user/credential identity is supplied, the returned challenge is
   * an opaque envelope containing the process generation so a stale challenge cannot be used
   * after a restart.
   */
  async issueChallenge(opts: {
    challenge: string;
    rpID: string;
    binding?: AuthenticationChallengeBinding;
    timeoutMS?: number;
    bindGeneration?: boolean;
  }): Promise<Base64URLString> {
    const binding = this.normalizeBinding(opts.binding);
    const bindGeneration = opts.bindGeneration ?? this.hasBinding(binding);
    const challengeID = isoBase64URL.fromBuffer(await toHash(opts.challenge));
    const generation = this._generation;
    const expiresAt = this.expiryFor(opts.timeoutMS);
    const baseChallenge = opts.challenge;

    let challenge: Base64URLString = baseChallenge;
    let envelope: AuthenticationChallengeEnvelope | undefined;
    if (bindGeneration) {
      envelope = {
        v: 1,
        g: generation,
        n: await randomBase64URL(16),
        t: await randomBase64URL(32),
        c: baseChallenge,
      };
      challenge = encodeEnvelope(envelope);
    }

    const record: AuthenticationChallengeRecord = {
      challenge,
      baseChallenge,
      challengeID,
      rpID: opts.rpID,
      generation,
      createdAt: Date.now(),
      expiresAt,
      status: 'pending',
      binding,
      envelope,
    };

    this.pruneExpired();
    this.enforceCapacity();
    this.invalidateBaseChallenge(baseChallenge);
    this.records.set(challenge, record);

    return challenge;
  }

  /**
   * Remember a caller-managed challenge without wrapping it. Used for stateless/legacy flows so
   * the challenge can still be consumed exactly once within this process.
   */
  rememberChallenge(opts: {
    challenge: string;
    rpID: string;
    binding?: AuthenticationChallengeBinding;
    timeoutMS?: number;
  }): Promise<AuthenticationChallengeRecord> {
    this.pruneExpired();
    this.enforceCapacity();

    const existing = this.records.get(opts.challenge);
    if (existing?.status === 'used' || existing?.status === 'cancelled') {
      return Promise.resolve(existing);
    }
    if (existing?.status === 'pending' && Date.now() > existing.expiresAt) {
      existing.status = 'expired';
      return Promise.resolve(existing);
    }

    const record: AuthenticationChallengeRecord = {
      challenge: opts.challenge,
      baseChallenge: opts.challenge,
      challengeID: isoBase64URL.fromUTF8String(opts.challenge),
      rpID: opts.rpID,
      generation: this._generation,
      createdAt: Date.now(),
      expiresAt: this.expiryFor(opts.timeoutMS),
      status: 'pending',
      binding: this.normalizeBinding(opts.binding),
    };

    this.invalidateBaseChallenge(opts.challenge);
    this.records.set(opts.challenge, record);
    return toHash(opts.challenge).then((hash) => {
      record.challengeID = isoBase64URL.fromBuffer(hash);
      return record;
    });
  }

  /**
   * Atomically consume a challenge. The pending -> used transition is synchronous, so concurrent
   * submissions cannot both start verification.
   */
  consumeChallenge(challenge: string): AuthenticationChallengeConsumption {
    this.pruneExpired();

    const record = this.records.get(challenge);
    if (!record) {
      const envelope = decodeEnvelope(challenge);
      if (!envelope) {
        return {
          tracked: false,
          status: 'available',
          challengeID: isoBase64URL.fromUTF8String(challenge),
        };
      }

      const challengeID = isoBase64URL.fromUTF8String(envelope.c);
      if (envelope.g !== this._generation) {
        return {
          tracked: true,
          status: 'stale_generation',
          challengeID,
          generation: envelope.g,
        };
      }

      return {
        tracked: true,
        status: 'missing',
        challengeID,
        generation: envelope.g,
      };
    }

    if (record.envelope) {
      const envelope = decodeEnvelope(challenge);
      if (
        !envelope ||
        envelope.g !== record.generation ||
        envelope.t !== record.envelope.t ||
        envelope.c !== record.baseChallenge
      ) {
        return {
          tracked: true,
          status: 'missing',
          record,
          challengeID: record.challengeID,
          generation: record.generation,
        };
      }
    }

    if (record.status === 'used') {
      return {
        tracked: true,
        status: 'used',
        record,
        challengeID: record.challengeID,
        generation: record.generation,
      };
    }

    if (record.status === 'cancelled') {
      return {
        tracked: true,
        status: 'cancelled',
        record,
        challengeID: record.challengeID,
        generation: record.generation,
      };
    }

    if (record.status === 'expired' || Date.now() > record.expiresAt) {
      record.status = 'used';
      record.expiresAt = Date.now() + REPLAY_RETENTION_MS;
      return {
        tracked: true,
        status: 'expired',
        record,
        challengeID: record.challengeID,
        generation: record.generation,
      };
    }

    record.status = 'used';
    record.expiresAt = Date.now() + REPLAY_RETENTION_MS;
    return {
      tracked: true,
      status: 'available',
      record,
      challengeID: record.challengeID,
      generation: record.generation,
    };
  }

  /**
   * Attach the identity that actually consumed a challenge. Called after the one-time transition
   * so audit reports can show which credential/user won a concurrent race.
   */
  recordConsumption(
    challenge: string,
    consumedBy: {
      credentialID: Base64URLString;
      userID?: Base64URLString;
      userHandle?: Base64URLString;
    },
  ): void {
    const record = this.records.get(challenge);
    if (record) {
      record.consumedBy = { ...consumedBy };
    }
  }

  /**
   * Cancel a still-pending challenge. A used challenge cannot be revived.
   */
  cancelChallenge(challenge: string, _reason?: string): boolean {
    const record = this.records.get(challenge);
    if (!record || record.status !== 'pending') {
      return false;
    }

    record.status = 'cancelled';
    return true;
  }

  getChallenge(challenge: string): AuthenticationChallengeRecord | undefined {
    this.pruneExpired();
    return this.records.get(challenge);
  }

  /**
   * Forget all in-process state and advance the generation. This is also used by tests to model
   * a process restart: envelopes issued before the reset are rejected.
   */
  reset(): void {
    this.records.clear();
    this._generation = Math.max(this._generation + 1, randomGeneration());
  }

  /** Alias for {@link reset}, useful when modeling a process restart. */
  restart(): void {
    this.reset();
  }

  private normalizeBinding(
    binding?: AuthenticationChallengeBinding,
  ): AuthenticationChallengeBinding {
    const credentialIDs = binding?.credentialIDs?.map((id) => isoBase64URL.trimPadding(id));
    const credentialOwners: Record<string, Base64URLString> = {};
    for (const [credentialID, owner] of Object.entries(binding?.credentialOwners ?? {})) {
      if (owner) {
        credentialOwners[isoBase64URL.trimPadding(credentialID)] = owner;
      }
    }

    const userIDs = binding?.userIDs?.filter((id) => !!id);
    return {
      credentialIDs: credentialIDs && credentialIDs.length > 0 ? credentialIDs : undefined,
      credentialOwners: Object.keys(credentialOwners).length > 0 ? credentialOwners : undefined,
      userIDs: userIDs && userIDs.length > 0 ? userIDs : undefined,
      requireUserBinding: binding?.requireUserBinding,
    };
  }

  private hasBinding(binding: AuthenticationChallengeBinding): boolean {
    return !!(
      binding.credentialIDs?.length ||
      binding.userIDs?.length ||
      Object.keys(binding.credentialOwners ?? {}).length ||
      binding.requireUserBinding
    );
  }

  /**
   * Re-issuing the same caller-supplied challenge must invalidate any older envelope for that
   * challenge. Otherwise two generations could remain usable and a client could pick between
   * their different bound identities.
   */
  private invalidateBaseChallenge(baseChallenge: string): void {
    for (const record of this.records.values()) {
      if (record.baseChallenge === baseChallenge && record.status === 'pending') {
        record.status = 'cancelled';
      }
    }
  }

  private expiryFor(timeoutMS?: number): number {
    const timeout = typeof timeoutMS === 'number' && Number.isFinite(timeoutMS)
      ? timeoutMS
      : 60_000;
    return Date.now() + Math.max(timeout, MIN_CHALLENGE_LIFETIME_MS);
  }

  private pruneExpired(): void {
    const now = Date.now();
    for (const [key, record] of this.records) {
      if (record.expiresAt + REPLAY_RETENTION_MS < now) {
        this.records.delete(key);
      }
    }
  }

  private enforceCapacity(): void {
    if (this.records.size < MAX_RECORDS) {
      return;
    }

    const oldest = [...this.records.entries()]
      .sort(([, a], [, b]) => a.createdAt - b.createdAt)
      .slice(0, Math.max(1, this.records.size - MAX_RECORDS + 1));
    for (const [key] of oldest) {
      this.records.delete(key);
    }
  }
}

/**
 * Process-local authentication challenge ledger.
 */
export const AuthenticationChallengeService = new BaseAuthenticationChallengeService();
