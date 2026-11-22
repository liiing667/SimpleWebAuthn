import type { Base64URLString } from '../types/index.ts';
import type {
  ChallengeAudit,
  VerificationStage,
  WebAuthnCeremony,
} from '../types/audit.ts';
import { isoBase64URL, isoCrypto, isoUint8Array } from '../helpers/iso/index.ts';
import {
  type SimpleWebAuthnLogger,
  buildLoggerAllMethods,
} from '../helpers/logging.ts';
import { originsMatch, rpIDsMatch } from '../helpers/canonicalizeOrigin.ts';
import { SERVICE_STATE, ServiceStateTracker } from './helpers/serviceStateTracker.ts';

/**
 * The context an RP can freeze when it asks SimpleWebAuthn to generate a challenge.
 *
 * Only `origin`/`origins`/`expectedOrigin` and `rpID` are needed for the basic binding. Setting
 * `tenant` additionally binds the challenge to one tenant/account/session identity, and requires
 * the verifier to supply the same tenant before the response can be consumed.
 */
export type ChallengeContextInput = {
  /** Origin, or origins, from which this challenge may be completed */
  origin?: string | string[];
  /** Alias for `origin` */
  origins?: string | string[];
  /** Alias for `origin` */
  expectedOrigin?: string | string[];
  /** Alias for `origin` */
  expectedOrigins?: string | string[];
  /** RP ID this challenge belongs to */
  rpID?: string;
  /** Alias for `rpID` */
  expectedRPID?: string;
  /** Tenant/account/session identity this challenge belongs to */
  tenant?: string;
  /** Alias for `tenant` */
  tenantID?: string;
  /** Alias for `tenant` */
  tenantId?: string;
  /** Optional user identity associated with the ceremony */
  userID?: Base64URLString;
};

/**
 * A normalized, frozen challenge context.
 */
export type NormalizedChallengeContext = {
  origins: string[];
  rpID: string;
  tenant?: string;
  userID?: Base64URLString;
};

export type ChallengeStatus =
  | 'available'
  | 'untracked'
  | 'missing'
  | 'ambiguous'
  | 'integrity'
  | 'stale_generation'
  | 'ceremony_mismatch'
  | 'cancelled'
  | 'expired'
  | 'used'
  | 'origin_mismatch'
  | 'rp_id_mismatch'
  | 'tenant_missing'
  | 'tenant_mismatch';

/**
 * A challenge previously issued (or explicitly remembered) by this process.
 */
export type ChallengeContextRecord = {
  /** Audit-friendly identifier for the challenge; never the raw challenge itself */
  challengeID: string;
  /** The exact challenge value the client was asked to sign */
  challenge: string;
  ceremony: WebAuthnCeremony;
  context: NormalizedChallengeContext;
  generation: number;
  createdAt: number;
  expiresAt: number;
  status: 'pending' | 'used' | 'cancelled' | 'expired';
  cancelReason?: string;
  usedAt?: number;
  usedBy?: {
    origin?: string;
    rpID?: string;
    tenant?: string;
  };
  /** Additional accepted spellings of the original caller-provided challenge */
  challengeAliases?: string[];
  envelope?: ChallengeEnvelope;
};

export type ChallengeConsumption = {
  /**
   * Whether this challenge was issued by this service. Legacy, caller-managed challenges are
   * reported as `tracked: false` and retain the historical stateless behavior.
   */
  tracked: boolean;
  status: ChallengeStatus;
  /** Present when `tracked` is true, even for most rejection statuses */
  record?: ChallengeContextRecord;
  challengeID: string;
  /** Challenge generation from the record, or the current generation for untracked values */
  generation?: number;
};

export type ChallengeEnvelope = {
  v: 1;
  /** Ceremony shorthand: "a" for authentication, "r" for registration */
  k: 'a' | 'r';
  /** Service generation that issued the challenge */
  g: number;
  /** Unguessable record handle */
  n: Base64URLString;
  /** Random binding tag stored in the record and compared when the challenge is presented */
  t: Base64URLString;
  /** Original caller-provided challenge, if any */
  c?: Base64URLString;
};

type DecodedEnvelope =
  | { status: 'not_envelope' }
  | { status: 'invalid' }
  | { status: 'valid'; envelope: ChallengeEnvelope };

export type ChallengeContextService = {
  /**
   * Create an opaque challenge that carries a link to the frozen context.
   *
   * WebAuthn treats challenges as opaque bytes, so wrapping the random challenge in an envelope
   * doesn't change the ceremony. The envelope lets the verifier distinguish:
   *
   * - a challenge issued by this process (and therefore subject to origin/RP/tenant binding)
   * - a caller-managed legacy challenge (still accepted statelessly by default)
   * - a challenge from a previous process generation (rejected after a restart)
   */
  issueChallenge(opts: {
    ceremony: WebAuthnCeremony;
    challenge: string;
    context: NormalizedChallengeContext;
    timeoutMS?: number;
    challengeAliases?: string[];
  }): Promise<string>;

  /**
   * Remember a challenge without wrapping it. This is useful for RPs that already persist
   * challenges and for tests that exercise the binding checks with an existing fixture.
   */
  rememberChallenge(opts: {
    challenge: string;
    ceremony: WebAuthnCeremony;
    context: NormalizedChallengeContext;
    timeoutMS?: number;
    challengeAliases?: string[];
    /** Set by `issueChallenge()` when the challenge is an envelope */
    envelope?: ChallengeEnvelope;
  }): ChallengeContextRecord;

  /**
   * Atomically consume a challenge and validate its frozen context.
   *
   * The pending -> used transition happens synchronously before this method returns. A challenge
   * that has been presented once is never presented to the async signature/attestation verifier
   * again, even if the first presentation fails a later context check.
   */
  consumeChallenge(opts: {
    challenge: string;
    ceremony: WebAuthnCeremony;
    origin?: string;
    rpID?: string;
    tenant?: string;
    requireContext?: boolean;
  }): ChallengeConsumption;

  /**
   * Mark a challenge as cancelled. A later verification using it is rejected with a
   * `challenge_cancellation` audit stage.
   */
  cancelChallenge(challenge: string, reason?: string): boolean;

  /**
   * Look up a challenge without consuming it.
   */
  getChallenge(challenge: string): ChallengeContextRecord | undefined;

  /**
   * Forget all in-process state and advance the generation. This simulates a process restart:
   * challenges issued before the reset can no longer be consumed, while newly generated
   * challenges continue to work.
   */
  reset(reason?: string): void;

  /** Current service generation */
  readonly generation: number;
  /** Alias for `generation` */
  readonly currentGeneration: number;

  /** Current service state */
  readonly state: SERVICE_STATE;
};

/** How long a used/cancelled challenge is kept for replay and audit purposes */
const REPLAY_RETENTION_MS = 24 * 60 * 60 * 1000;
/** Upper bound on in-process challenge records to keep a hostile client from exhausting memory */
const MAX_RECORDS = 10_000;
/** Magic prefix that identifies an envelope created by this library */
const ENVELOPE_MAGIC = 'SWA1';

/**
 * A process-local ledger of challenge contexts.
 *
 * SimpleWebAuthn itself doesn't own an RP's session storage, but it can make the challenge ->
 * verification handoff safe. This ledger is intentionally in-process by default (like
 * `SettingsService`); RPs that run multiple server instances should use their shared database (or
 * a custom implementation) to enforce the same unique-consumption rule across instances.
 */
export class BaseChallengeContextService implements ChallengeContextService {
  private readonly records = new Map<string, ChallengeContextRecord>();
  private readonly aliasIndex = new Map<string, Set<ChallengeContextRecord>>();
  private readonly tracker: ServiceStateTracker;

  constructor(logger?: SimpleWebAuthnLogger) {
    this.tracker = new ServiceStateTracker(
      'ChallengeContextService',
      buildLoggerAllMethods(logger ?? {}),
    );
    this.tracker.set(SERVICE_STATE.READY);
  }

  get generation(): number {
    return this.tracker.generation;
  }

  get currentGeneration(): number {
    return this.tracker.generation;
  }

  get state(): SERVICE_STATE {
    return this.tracker.current;
  }

  async issueChallenge(opts: {
    ceremony: WebAuthnCeremony;
    challenge: string;
    context: NormalizedChallengeContext;
    timeoutMS?: number;
    challengeAliases?: string[];
  }): Promise<string> {
    const { ceremony, challenge, context, timeoutMS, challengeAliases } = opts;
    const aliases = [...(challengeAliases ?? [])];
    if (!aliases.includes(challenge)) {
      aliases.push(challenge);
    }

    const nonce = await randomBase64URL(16);
    const tag = await randomBase64URL(32);
    const envelope: ChallengeEnvelope = {
      v: 1,
      k: ceremony === 'authentication' ? 'a' : 'r',
      g: this.generation,
      n: nonce,
      t: tag,
      c: challenge,
    };

    const wrappedChallenge = encodeEnvelope(envelope);
    this.rememberChallenge({
      challenge: wrappedChallenge,
      ceremony,
      context,
      timeoutMS,
      challengeAliases: aliases,
      envelope,
    });

    return wrappedChallenge;
  }

  rememberChallenge(opts: {
    challenge: string;
    ceremony: WebAuthnCeremony;
    context: NormalizedChallengeContext;
    timeoutMS?: number;
    challengeAliases?: string[];
    envelope?: ChallengeEnvelope;
  }): ChallengeContextRecord {
    const { challenge, ceremony, context, timeoutMS, challengeAliases } = opts;
    const decodedEnvelope = decodeEnvelope(challenge);
    const envelope = opts.envelope ??
      (decodedEnvelope.status === 'valid' ? decodedEnvelope.envelope : undefined);

    this.pruneExpired();

    const existing = this.findRecord(challenge);
    if (existing) {
      // Never revive or rebind a challenge that is already known to this process. This covers
      // callers that reuse a custom challenge string after consumption, cancellation, expiry, or
      // a failed cross-tenant attempt.
      return existing;
    }
    if (decodedEnvelope.status === 'not_envelope') {
      const existingByOriginalChallenge = this.findRecordByValue(challenge);
      if (existingByOriginalChallenge.record) {
        return existingByOriginalChallenge.record;
      }
    }

    const timeout = typeof timeoutMS === 'number' && Number.isFinite(timeoutMS)
      ? Math.max(timeoutMS, 1)
      : 60_000;
    const now = Date.now();
    const record: ChallengeContextRecord = {
      challengeID: challengeIDFor(challenge),
      challenge,
      ceremony,
      context: {
        origins: [...context.origins],
        rpID: context.rpID,
        tenant: context.tenant,
        userID: context.userID,
      },
      generation: this.generation,
      createdAt: now,
      expiresAt: now + timeout,
      status: 'pending',
      challengeAliases: challengeAliases ? [...challengeAliases] : undefined,
      envelope,
    };

    this.records.set(this.recordKey(challenge), record);
    this.indexRecord(record);
    if (this.records.size > MAX_RECORDS) {
      this.evictOldest();
    }
    return record;
  }

  consumeChallenge(opts: {
    challenge: string;
    ceremony: WebAuthnCeremony;
    origin?: string;
    rpID?: string;
    tenant?: string;
    requireContext?: boolean;
  }): ChallengeConsumption {
    this.pruneExpired();

    const { challenge, ceremony, origin, rpID, tenant, requireContext = false } = opts;
    const decodedEnvelope = decodeEnvelope(challenge);
    const match = this.findRecordByValue(challenge);
    const record = match.record;
    const challengeID = record?.challengeID ?? challengeIDFor(challenge);

    if (!record) {
      if (match.ambiguous) {
        return {
          tracked: true,
          status: 'ambiguous',
          challengeID,
        };
      }

      if (decodedEnvelope.status === 'invalid') {
        return {
          tracked: true,
          status: 'integrity',
          challengeID,
        };
      }

      if (decodedEnvelope.status === 'valid') {
        // The challenge was issued by this library, but the record is gone. This happens after
        // a reset/restart, after the record's retention window, or when a caller mixes state
        // between processes. Never silently fall back to stateless verification for these.
        return {
          tracked: true,
          status: 'stale_generation',
          challengeID,
          generation: decodedEnvelope.envelope.g,
        };
      }

      if (requireContext) {
        return {
          tracked: true,
          status: 'missing',
          challengeID,
        };
      }

      return { tracked: false, status: 'untracked', challengeID };
    }

    if (record.generation !== this.generation) {
      return {
        tracked: true,
        status: 'stale_generation',
        record,
        challengeID,
        generation: record.generation,
      };
    }

    if (record.ceremony !== ceremony) {
      return {
        tracked: true,
        status: 'ceremony_mismatch',
        record,
        challengeID,
        generation: record.generation,
      };
    }

    if (record.status === 'cancelled') {
      return {
        tracked: true,
        status: 'cancelled',
        record,
        challengeID,
        generation: record.generation,
      };
    }

    if (record.status === 'used') {
      return {
        tracked: true,
        status: 'used',
        record,
        challengeID,
        generation: record.generation,
      };
    }

    if (record.status === 'expired' || Date.now() >= record.expiresAt) {
      record.status = 'expired';
      record.expiresAt = Date.now() + REPLAY_RETENTION_MS;
      return {
        tracked: true,
        status: 'expired',
        record,
        challengeID,
        generation: record.generation,
      };
    }

    if (decodedEnvelope.status === 'invalid') {
      return {
        tracked: true,
        status: 'integrity',
        record,
        challengeID,
        generation: record.generation,
      };
    }

    if (decodedEnvelope.status === 'valid') {
      if (!record.envelope || decodedEnvelope.envelope.n !== record.envelope.n) {
        return {
          tracked: true,
          status: 'integrity',
          record,
          challengeID,
          generation: record.generation,
        };
      }

      if (decodedEnvelope.envelope.t !== record.envelope.t) {
        return {
          tracked: true,
          status: 'integrity',
          record,
          challengeID,
          generation: record.generation,
        };
      }
    }

    /**
     * Consume before checking origin/RP ID/tenant. This is the core single-use fence: an
     * attacker who presents a challenge from tenant A to tenant B, or who replays a response,
     * gets exactly one attempt and cannot leave the challenge available for a second reader.
     */
    record.status = 'used';
    record.usedAt = Date.now();
    record.expiresAt = record.usedAt + REPLAY_RETENTION_MS;
    record.usedBy = { origin, rpID, tenant };

    if (origin !== undefined && record.context.origins.length > 0) {
      if (!record.context.origins.some((expected) => originsMatch(origin, expected))) {
        return {
          tracked: true,
          status: 'origin_mismatch',
          record,
          challengeID,
          generation: record.generation,
        };
      }
    }

    if (rpID !== undefined && !rpIDsMatch(rpID, record.context.rpID)) {
      return {
        tracked: true,
        status: 'rp_id_mismatch',
        record,
        challengeID,
        generation: record.generation,
      };
    }

    if (record.context.tenant !== undefined) {
      if (tenant === undefined) {
        return {
          tracked: true,
          status: 'tenant_missing',
          record,
          challengeID,
          generation: record.generation,
        };
      }

      if (tenant !== record.context.tenant) {
        return {
          tracked: true,
          status: 'tenant_mismatch',
          record,
          challengeID,
          generation: record.generation,
        };
      }
    }

    return {
      tracked: true,
      status: 'available',
      record,
      challengeID,
      generation: record.generation,
    };
  }

  cancelChallenge(challenge: string, reason?: string): boolean {
    this.pruneExpired();

    const match = this.findRecordByValue(challenge);
    if (!match.record || match.ambiguous) {
      return false;
    }
    const record = match.record;

    if (record.status === 'used') {
      return false;
    }

    record.status = 'cancelled';
    record.cancelReason = reason;
    record.expiresAt = Date.now() + REPLAY_RETENTION_MS;
    return true;
  }

  getChallenge(challenge: string): ChallengeContextRecord | undefined {
    this.pruneExpired();
    const match = this.findRecordByValue(challenge);
    return match.ambiguous ? undefined : match.record;
  }

  reset(reason?: string): void {
    this.records.clear();
    this.aliasIndex.clear();
    this.tracker.advanceGeneration(reason ?? 'challenge state reset');
  }

  private findRecord(challenge: string): ChallengeContextRecord | undefined {
    const byChallenge = this.records.get(this.recordKey(challenge));
    if (byChallenge) {
      return byChallenge;
    }

    const decoded = decodeEnvelope(challenge);
    if (decoded.status === 'valid') {
      for (const record of this.records.values()) {
        if (record.envelope?.n === decoded.envelope.n) {
          return record;
        }
      }
    }

    return undefined;
  }

  /**
   * Find a record by the exact presented challenge, falling back to the original challenge a
   * caller supplied before it was wrapped in an envelope. The fallback keeps pre-envelope
   * fixtures and custom challenge verifiers working while the record stays authoritative for the
   * frozen origin/RP ID/tenant.
   */
  private findRecordByValue(
    challenge: string,
  ): { record?: ChallengeContextRecord; ambiguous: boolean } {
    const direct = this.findRecord(challenge);
    if (direct) {
      return { record: direct, ambiguous: false };
    }

    const byOriginalChallenge = this.aliasIndex.get(challenge);
    if (byOriginalChallenge?.size === 1) {
      return { record: [...byOriginalChallenge][0], ambiguous: false };
    }

    return { ambiguous: (byOriginalChallenge?.size ?? 0) > 1 };
  }

  private recordKey(challenge: string): string {
    const decoded = decodeEnvelope(challenge);
    if (decoded.status === 'valid') {
      return `nonce:${decoded.envelope.n}`;
    }

    return `challenge:${challenge}`;
  }

  private pruneExpired(): void {
    const now = Date.now();
    for (const [key, record] of this.records) {
      // Keep records for one retention window after their effective expiry so replays can still
      // be distinguished from completely unknown challenges.
      if (now > record.expiresAt + REPLAY_RETENTION_MS) {
        this.unindexRecord(record);
        this.records.delete(key);
      }
    }
  }

  private evictOldest(): void {
    let oldestKey: string | undefined;
    let oldestCreatedAt = Number.POSITIVE_INFINITY;

    for (const [key, record] of this.records) {
      if (record.createdAt < oldestCreatedAt) {
        oldestCreatedAt = record.createdAt;
        oldestKey = key;
      }
    }

    if (oldestKey !== undefined) {
      const record = this.records.get(oldestKey);
      if (record) {
        this.unindexRecord(record);
      }
      this.records.delete(oldestKey);
    }
  }

  private indexRecord(record: ChallengeContextRecord): void {
    for (const alias of this.aliasesFor(record)) {
      const records = this.aliasIndex.get(alias) ?? new Set<ChallengeContextRecord>();
      records.add(record);
      this.aliasIndex.set(alias, records);
    }
  }

  private unindexRecord(record: ChallengeContextRecord): void {
    for (const alias of this.aliasesFor(record)) {
      const records = this.aliasIndex.get(alias);
      if (!records) {
        continue;
      }
      records.delete(record);
      if (records.size === 0) {
        this.aliasIndex.delete(alias);
      }
    }
  }

  private aliasesFor(record: ChallengeContextRecord): string[] {
    const aliases = new Set<string>([record.challenge, ...(record.challengeAliases ?? [])]);
    if (record.envelope?.c) {
      aliases.add(record.envelope.c);
    }
    return [...aliases];
  }
}

/**
 * Normalize the flexible input accepted by generate options into the canonical context stored in
 * the ledger.
 */
export function normalizeChallengeContext(
  input: ChallengeContextInput | undefined,
  fallbackRPID: string,
): NormalizedChallengeContext | undefined {
  if (!input) {
    return undefined;
  }

  const originInput = input.origin ?? input.origins ?? input.expectedOrigin ??
    input.expectedOrigins;
  let origins: string[] = [];
  if (typeof originInput === 'string') {
    origins = [originInput];
  } else if (Array.isArray(originInput)) {
    origins = originInput.filter((origin) => typeof origin === 'string');
  }

  const tenant = input.tenant ?? input.tenantID ?? input.tenantId;
  const rpID = input.rpID ?? input.expectedRPID ?? fallbackRPID;

  return {
    origins,
    rpID,
    tenant,
    userID: input.userID,
  };
}

/**
 * Build a complete audit report for a rejection.
 */
export function buildChallengeAudit(opts: {
  ceremony: WebAuthnCeremony;
  stage: VerificationStage;
  location: string;
  reason: string;
  actualOrigin?: string;
  expectedOrigins?: string[];
  callerExpectedOrigins?: string[];
  actualRPID?: string;
  expectedRPID?: string;
  callerExpectedRPIDs?: string[];
  tenant?: string;
  challengeTenant?: string;
  challengeID?: string;
  generation?: number;
  currentGeneration?: number;
}): ChallengeAudit {
  return {
    ceremony: opts.ceremony,
    stage: opts.stage,
    location: opts.location,
    reason: opts.reason,
    actualOrigin: opts.actualOrigin,
    expectedOrigins: opts.expectedOrigins ?? [],
    callerExpectedOrigins: opts.callerExpectedOrigins,
    actualRPID: opts.actualRPID,
    expectedRPID: opts.expectedRPID,
    callerExpectedRPIDs: opts.callerExpectedRPIDs,
    tenant: opts.tenant,
    challengeTenant: opts.challengeTenant,
    challengeID: opts.challengeID,
    generation: opts.generation,
    currentGeneration: opts.currentGeneration,
    timestamp: new Date().toISOString(),
  };
}

export function challengeIDFor(challenge: string): string {
  // A short, deterministic handle for audit logs. This is not a security boundary; the record
  // lookup and envelope tag are what actually prevent substitution.
  const bytes = isoUint8Array.fromUTF8String(challenge);
  const digest = new Uint8Array(12);
  let hash = 0x811c9dc5;
  for (let i = 0; i < bytes.length; i++) {
    hash ^= bytes[i];
    hash = Math.imul(hash, 0x01000193) >>> 0;
  }
  for (let i = 0; i < digest.length; i++) {
    digest[i] = (hash >>> ((i % 4) * 8)) & 0xff;
    hash = Math.imul(hash ^ (i + 1), 0x01000193) >>> 0;
  }
  return isoBase64URL.fromBuffer(digest);
}

function encodeEnvelope(envelope: ChallengeEnvelope): string {
  const bytes = isoUint8Array.concat([
    isoUint8Array.fromUTF8String(ENVELOPE_MAGIC),
    isoUint8Array.fromUTF8String(JSON.stringify(envelope)),
  ]);

  return isoBase64URL.fromBuffer(bytes);
}

function decodeEnvelope(challenge: string): DecodedEnvelope {
  if (!isoBase64URL.isBase64URL(challenge)) {
    return { status: 'not_envelope' };
  }

  let bytes: Uint8Array;
  try {
    bytes = isoBase64URL.toBuffer(challenge);
  } catch {
    return { status: 'not_envelope' };
  }

  if (bytes.length <= ENVELOPE_MAGIC.length) {
    return { status: 'not_envelope' };
  }

  const prefix = isoUint8Array.toUTF8String(bytes.slice(0, ENVELOPE_MAGIC.length));
  if (prefix !== ENVELOPE_MAGIC) {
    return { status: 'not_envelope' };
  }

  let parsed: unknown;
  try {
    parsed = JSON.parse(isoUint8Array.toUTF8String(bytes.slice(ENVELOPE_MAGIC.length)));
  } catch {
    return { status: 'invalid' };
  }

  if (!isChallengeEnvelope(parsed)) {
    return { status: 'invalid' };
  }

  return { status: 'valid', envelope: parsed };
}

function isChallengeEnvelope(value: unknown): value is ChallengeEnvelope {
  if (!value || typeof value !== 'object') {
    return false;
  }

  const envelope = value as Partial<ChallengeEnvelope>;
  return envelope.v === 1 &&
    (envelope.k === 'a' || envelope.k === 'r') &&
    typeof envelope.g === 'number' &&
    typeof envelope.n === 'string' &&
    typeof envelope.t === 'string';
}

async function randomBase64URL(length: number): Promise<Base64URLString> {
  const bytes = new Uint8Array(length);
  await isoCrypto.getRandomValues(bytes);
  return isoBase64URL.fromBuffer(bytes);
}

/**
 * The default process-local challenge ledger.
 */
export const ChallengeContextService: ChallengeContextService =
  new BaseChallengeContextService();

/**
 * Create an isolated ledger, primarily for tests and for RPs that want separate state per tenant
 * within one process.
 */
export function createChallengeContextService(
  logger?: SimpleWebAuthnLogger,
): ChallengeContextService {
  return new BaseChallengeContextService(logger);
}

/** Backwards-friendly aliases for consumers that think in terms of sessions. */
export const AuthenticationChallengeService = ChallengeContextService;
export const SessionChallengeService = ChallengeContextService;

/**
 * Cancel a challenge, for example when a page is unloaded or a client-side router abandons the
 * current ceremony. A later verification using the challenge is rejected with a
 * `challenge_cancellation` audit stage.
 */
export function cancelAuthenticationChallenge(challenge: string, reason?: string): boolean {
  return ChallengeContextService.cancelChallenge(challenge, reason);
}

export function cancelRegistrationChallenge(challenge: string, reason?: string): boolean {
  return ChallengeContextService.cancelChallenge(challenge, reason);
}
