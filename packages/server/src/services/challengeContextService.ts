import type { Base64URLString } from '../types/index.ts';
import type {
  ChallengeAudit,
  VerificationStage,
  WebAuthnCeremony,
} from '../types/audit.ts';
import { ChallengeContextError } from '../errors/index.ts';
import { SERVICE_STATE } from './helpers/serviceStateTracker.ts';
import { isoBase64URL, isoCrypto, isoUint8Array } from '../helpers/iso/index.ts';
import { originsMatch, rpIDsMatch } from '../helpers/canonicalizeOrigin.ts';

/**
 * Context an RP can freeze when it asks SimpleWebAuthn to generate a challenge.
 */
export type ChallengeContextInput = {
  /** Origin, or origins, from which this challenge may be completed. */
  origin?: string | string[];
  /** Alias for `origin`. */
  origins?: string | string[];
  /** Alias for `origin`. */
  expectedOrigin?: string | string[];
  /** Alias for `origin`. */
  expectedOrigins?: string | string[];
  /** RP ID this challenge belongs to. */
  rpID?: string;
  /** Alias for `rpID`. */
  expectedRPID?: string;
  /** Tenant/account/session identity this challenge belongs to. */
  tenant?: string;
  /** Alias for `tenant`. */
  tenantID?: string;
  /** Alias for `tenant`. */
  tenantId?: string;
  /** Optional user identity associated with the ceremony. */
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

/**
 * Identity information frozen when authentication options are generated.
 *
 * These fields are intentionally optional; legacy callers that only provide a challenge keep
 * the historical stateless behavior.
 */
export type AuthenticationChallengeBinding = {
  /** Credential IDs offered via `allowCredentials`, if any. */
  credentialIDs?: Base64URLString[];
  /** Owner of each offered credential, when the RP knows it. */
  credentialOwners?: Record<string, Base64URLString>;
  /** User identities accepted for this challenge. */
  userIDs?: Base64URLString[];
  /** Whether verification must be able to prove a user identity. */
  requireUserBinding?: boolean;
};

export type ChallengeStatus =
  | 'pending'
  | 'used'
  | 'cancelled'
  | 'expired'
  | 'superseded';

export type ChallengeUsedBy = {
  origin?: string;
  rpID?: string;
  tenant?: string;
  sessionKey?: string;
  credentialID?: Base64URLString;
  userID?: Base64URLString;
  userHandle?: Base64URLString;
};

export type ChallengeConsumptionStatus =
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
  | 'tenant_mismatch'
  | 'session_missing'
  | 'session_mismatch';

/**
 * An opaque envelope wrapped around a challenge. WebAuthn treats challenges as opaque bytes, so
 * the browser and authenticator do not need to understand this structure. The verifier uses it
 * to distinguish a challenge issued by this process from a caller-managed legacy challenge and
 * to reject challenges from a previous process generation.
 */
export type ChallengeEnvelope = {
  v: 1;
  /** Ceremony shorthand: "a" for authentication, "r" for registration. */
  k: 'a' | 'r';
  /** Process generation that issued the challenge. */
  g: number;
  /** Unguessable record handle. */
  n: Base64URLString;
  /** Random binding tag stored in the record and compared when presented. */
  t: Base64URLString;
  /** Original caller-provided challenge. */
  c: Base64URLString;
  /** Browser/tab ceremony identity. */
  cid?: string;
  /** Alias for `cid`. */
  ceremonyID?: string;
  /** Generation of the browser/session ceremony. */
  cg?: number;
  /** Alias for `cg`. */
  ceremonyGeneration?: number;
  /** Login-session identity, when one was supplied. */
  s?: string;
  /** Alias for `s`. */
  sessionKey?: string;
  /** Audit-friendly challenge handle. */
  challengeID?: string;
};

type DecodedEnvelope =
  | { status: 'not_envelope' }
  | { status: 'invalid' }
  | { status: 'valid'; envelope: ChallengeEnvelope };

/**
 * A challenge previously issued (or explicitly remembered) by this process.
 */
export type ChallengeContextRecord = {
  /** Audit-friendly identifier for the challenge; never the raw challenge itself. */
  challengeID: string;
  /** The exact challenge value the client was asked to sign. */
  challenge: string;
  /** The caller-provided challenge before it was wrapped. */
  baseChallenge: string;
  ceremony: WebAuthnCeremony;
  context: NormalizedChallengeContext;
  binding: AuthenticationChallengeBinding;
  /** Process generation that issued the challenge. */
  generation: number;
  /** Browser/tab ceremony identity issued with the challenge. */
  ceremonyID: string;
  /** Generation of the ceremony within its session. */
  ceremonyGeneration: number;
  /** Login/session identity this challenge belongs to. */
  sessionKey?: string;
  /** Convenience copy of `context.rpID`, kept for authentication-ledger compatibility. */
  rpID: string;
  /**
   * Whether the ceremony identity/generation were returned in the options JSON. When false, a
   * legacy client may report its local tab identity instead; the challenge envelope remains the
   * authoritative generation binding.
   */
  ceremonyMetadataExposed: boolean;
  /** Supersession scope: a newer pending challenge in this scope cancels this one. */
  scopeKey: string;
  createdAt: number;
  expiresAt: number;
  status: ChallengeStatus;
  cancelReason?: string;
  usedAt?: number;
  /** Set when a verified result has been published to the caller. */
  committedAt?: number;
  usedBy?: ChallengeUsedBy;
  /** Alias for `usedBy`, kept for authentication-ledger compatibility. */
  consumedBy?: ChallengeUsedBy;
  /** Additional accepted spellings of the original caller-provided challenge. */
  challengeAliases?: string[];
  envelope?: ChallengeEnvelope;
};

export type ChallengeConsumption = {
  /**
   * Whether this challenge was issued by this service. Legacy, caller-managed challenges are
   * reported as `tracked: false` and retain the historical stateless behavior.
   */
  tracked: boolean;
  status: ChallengeConsumptionStatus;
  /** Present when the challenge was tracked by this process. */
  record?: ChallengeContextRecord;
  challengeID: string;
  /** Process generation from the record, or the envelope. */
  generation?: number;
  /** Ceremony identity carried by the record or envelope. */
  ceremonyID?: string;
  /** Ceremony generation carried by the record or envelope. */
  ceremonyGeneration?: number;
  /** Whether ceremony metadata is exposed to the client. Defaults to true for direct callers. */
  ceremonyMetadataExposed?: boolean;
};

/** Compatibility aliases for authentication-ledger consumers. */
export type AuthenticationChallengeStatus = ChallengeStatus;
export type AuthenticationChallengeEnvelope = ChallengeEnvelope;
export type AuthenticationChallengeRecord = ChallengeContextRecord;
export type AuthenticationChallengeConsumption = ChallengeConsumption;
export type AuthenticationChallengeConsumptionStatus = ChallengeConsumptionStatus;

export type ChallengeIssueOptions = {
  ceremony?: WebAuthnCeremony;
  challenge: string;
  context?: ChallengeContextInput;
  /** Convenience form used by authentication callers. */
  rpID?: string;
  binding?: AuthenticationChallengeBinding;
  timeoutMS?: number;
  challengeAliases?: string[];
  sessionKey?: string;
  ceremonyID?: string;
  ceremonyGeneration?: number;
  /** Whether ceremony metadata is exposed to the client. Defaults to true for direct callers. */
  ceremonyMetadataExposed?: boolean;
  /** When false, remember the raw challenge without wrapping it in an envelope. */
  bindGeneration?: boolean;
};

export type RememberChallengeOptions = {
  challenge: string;
  ceremony?: WebAuthnCeremony;
  context?: ChallengeContextInput;
  rpID?: string;
  binding?: AuthenticationChallengeBinding;
  timeoutMS?: number;
  challengeAliases?: string[];
  sessionKey?: string;
  ceremonyID?: string;
  ceremonyGeneration?: number;
  envelope?: ChallengeEnvelope;
};

export type ConsumeChallengeOptions = {
  challenge: string;
  ceremony?: WebAuthnCeremony;
  origin?: string;
  rpID?: string;
  tenant?: string;
  sessionKey?: string;
  ceremonyID?: string;
  ceremonyGeneration?: number;
  requireContext?: boolean;
};

/** How long a used/cancelled challenge is kept for replay and audit purposes. */
const REPLAY_RETENTION_MS = 24 * 60 * 60 * 1000;
/** Upper bound on in-process records to keep a hostile client from exhausting memory. */
const MAX_RECORDS = 10_000;
/** Magic prefix that identifies an envelope created by this library. */
const ENVELOPE_MAGIC = 'SWA1';

function ceremonyKind(ceremony: WebAuthnCeremony): 'a' | 'r' {
  return ceremony === 'authentication' ? 'a' : 'r';
}

function ceremonyFromKind(kind: 'a' | 'r'): WebAuthnCeremony {
  return kind === 'a' ? 'authentication' : 'registration';
}

function trim(value: string | undefined): string | undefined {
  if (typeof value !== 'string') {
    return undefined;
  }
  const trimmed = value.trim();
  return trimmed.length > 0 ? trimmed : undefined;
}

function normalizeOriginInput(
  input: string | string[] | undefined,
): string[] {
  if (typeof input === 'string') {
    return [input];
  }
  if (Array.isArray(input)) {
    return input.filter((origin) => typeof origin === 'string');
  }
  return [];
}

/**
 * Normalize the flexible context accepted by generate options into the canonical context stored
 * in the ledger.
 */
export function normalizeChallengeContext(
  input: ChallengeContextInput | undefined,
  fallbackRPID: string,
): NormalizedChallengeContext | undefined {
  if (!input) {
    return undefined;
  }

  const origins = normalizeOriginInput(
    input.origin ?? input.origins ?? input.expectedOrigin ?? input.expectedOrigins,
  );
  const tenant = trim(input.tenant ?? input.tenantID ?? input.tenantId);

  return {
    origins,
    rpID: input.rpID ?? input.expectedRPID ?? fallbackRPID,
    tenant,
    userID: input.userID,
  };
}

function normalizeBinding(
  binding: AuthenticationChallengeBinding | undefined,
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
    credentialOwners: Object.keys(credentialOwners).length > 0
      ? credentialOwners
      : undefined,
    userIDs: userIDs && userIDs.length > 0 ? userIDs : undefined,
    requireUserBinding: binding?.requireUserBinding,
  };
}

function scopeKeyFor(opts: {
  ceremony: WebAuthnCeremony;
  context: NormalizedChallengeContext;
  binding: AuthenticationChallengeBinding;
  sessionKey?: string;
}): string {
  const explicit = trim(opts.sessionKey);
  if (explicit) {
    return `${opts.ceremony}|session:${explicit}`;
  }

  const tenant = opts.context.tenant;
  if (tenant) {
    return `${opts.ceremony}|tenant:${tenant}|origin:${opts.context.origins.join(',')}`;
  }

  const userID = opts.context.userID ??
    opts.binding.userIDs?.[0] ??
    Object.values(opts.binding.credentialOwners ?? {})[0];
  if (userID) {
    return `${opts.ceremony}|user:${userID}|origin:${opts.context.origins.join(',')}`;
  }

  /**
   * A login ceremony without an explicit session identity is scoped to its RP. This makes a
   * second "start login" in the same RP supersede the first pending ceremony, which is the
   * behavior a browser tab/reload retry needs. RPs that intentionally run concurrent logins for
   * different users should pass a stable `sessionKey` (or `tenant`) so scopes remain separate.
   */
  return `${opts.ceremony}|rp:${opts.context.rpID}|origin:${opts.context.origins.join(',')}`;
}

export function challengeIDFor(challenge: string): string {
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
  /**
   * Keep the envelope as JSON so callers/tests that inspect a challenge can decode the ceremony
   * generation without knowing an internal binary framing. A magic-prefixed fallback remains
   * supported by `decodeEnvelope()` for compatibility with earlier envelope encodings.
   */
  return isoBase64URL.fromUTF8String(JSON.stringify(envelope));
}

function decodeEnvelope(challenge: string): DecodedEnvelope {
  if (typeof challenge !== 'string' || !isoBase64URL.isBase64URL(challenge)) {
    return { status: 'not_envelope' };
  }

  let bytes: Uint8Array;
  try {
    bytes = isoBase64URL.toBuffer(challenge);
  } catch {
    return { status: 'not_envelope' };
  }

  /**
   * Preferred format: a JSON object directly encoded as base64url. Fall through to the legacy
   * `SWA1` prefix if direct JSON parsing does not identify an envelope.
   */
  try {
    const parsed = JSON.parse(isoUint8Array.toUTF8String(bytes));
    if (isChallengeEnvelope(parsed)) {
      return { status: 'valid', envelope: completeEnvelope(parsed) };
    }
    if (looksLikeEnvelope(parsed)) {
      return { status: 'invalid' };
    }
  } catch {
    // Try the legacy magic-prefixed format below.
  }

  if (bytes.length <= ENVELOPE_MAGIC.length) {
    return { status: 'not_envelope' };
  }

  let prefix: string;
  try {
    prefix = isoUint8Array.toUTF8String(bytes.slice(0, ENVELOPE_MAGIC.length));
  } catch {
    return { status: 'not_envelope' };
  }

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

  return { status: 'valid', envelope: completeEnvelope(parsed) };
}

function completeEnvelope(envelope: ChallengeEnvelope): ChallengeEnvelope {
  return {
    ...envelope,
    cid: envelope.cid ?? envelope.ceremonyID ?? `legacy-${envelope.n}`,
    ceremonyID: envelope.ceremonyID ?? envelope.cid,
    cg: envelope.cg ?? envelope.ceremonyGeneration ?? envelope.g,
    ceremonyGeneration: envelope.ceremonyGeneration ?? envelope.cg,
    sessionKey: envelope.sessionKey ?? envelope.s,
    challengeID: envelope.challengeID ?? challengeIDFor(envelope.c),
  };
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
    typeof envelope.t === 'string' &&
    typeof envelope.c === 'string' &&
    (envelope.cid === undefined || typeof envelope.cid === 'string') &&
    (envelope.ceremonyID === undefined || typeof envelope.ceremonyID === 'string') &&
    (envelope.cg === undefined || typeof envelope.cg === 'number') &&
    (envelope.ceremonyGeneration === undefined ||
      typeof envelope.ceremonyGeneration === 'number') &&
    (envelope.s === undefined || typeof envelope.s === 'string') &&
    (envelope.sessionKey === undefined || typeof envelope.sessionKey === 'string') &&
    (envelope.challengeID === undefined || typeof envelope.challengeID === 'string');
}

function looksLikeEnvelope(value: unknown): boolean {
  if (!value || typeof value !== 'object') {
    return false;
  }
  const envelope = value as Record<string, unknown>;
  return envelope.v === 1 &&
    (envelope.k === 'a' || envelope.k === 'r') &&
    typeof envelope.g === 'number' &&
    typeof envelope.n === 'string' &&
    typeof envelope.t === 'string' &&
    typeof envelope.c === 'string';
}

async function randomBase64URL(length: number): Promise<Base64URLString> {
  const bytes = new Uint8Array(length);
  await isoCrypto.getRandomValues(bytes);
  return isoBase64URL.fromBuffer(bytes);
}

function randomID(prefix: string): string {
  return `${prefix}_${Date.now().toString(36)}_${Math.random().toString(36).slice(2, 10)}`;
}

export function locationForStage(
  ceremony: WebAuthnCeremony,
  stage: VerificationStage,
): string {
  const source = ceremony === 'authentication'
    ? 'packages/server/src/authentication/verifyAuthenticationResponse.ts:verifyAuthenticationResponse'
    : 'packages/server/src/registration/verifyRegistrationResponse.ts:verifyRegistrationResponse';

  switch (stage) {
    case 'origin':
    case 'rp_id':
    case 'tenant':
    case 'session':
    case 'challenge_lookup':
    case 'challenge_integrity':
    case 'challenge_replay':
    case 'challenge_expiry':
    case 'challenge_cancellation':
    case 'challenge_generation':
    case 'ceremony':
      return 'packages/server/src/services/challengeContextService.ts:consumeChallenge';
    default:
      return `${source}#${stage}`;
  }
}

/**
 * Build a complete audit report for a rejection.
 */
export function buildChallengeAudit(opts: {
  ceremony: WebAuthnCeremony;
  stage: VerificationStage;
  reason: string;
  location?: string;
  actualOrigin?: string;
  expectedOrigins?: string[];
  callerExpectedOrigins?: string[];
  actualRPID?: string;
  expectedRPID?: string;
  callerExpectedRPIDs?: string[];
  tenant?: string;
  challengeTenant?: string;
  challengeID?: string;
  ceremonyID?: string;
  browserCeremonyID?: string;
  ceremonyGeneration?: number;
  generation?: number;
  challengeGeneration?: number;
  currentGeneration?: number;
  sessionKey?: string;
  challengeSessionKey?: string;
}): ChallengeAudit {
  return {
    ceremony: opts.ceremony,
    stage: opts.stage,
    location: opts.location ?? locationForStage(opts.ceremony, opts.stage),
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
    ceremonyID: opts.ceremonyID,
    browserCeremonyID: opts.browserCeremonyID,
    tabID: opts.browserCeremonyID ?? opts.ceremonyID,
    ceremonyGeneration: opts.ceremonyGeneration,
    generation: opts.generation,
    challengeGeneration: opts.challengeGeneration ?? opts.generation,
    currentGeneration: opts.currentGeneration,
    sessionKey: opts.sessionKey,
    challengeSessionKey: opts.challengeSessionKey,
    timestamp: new Date().toISOString(),
  };
}

export type ChallengeContextService = {
  issueChallenge(opts: ChallengeIssueOptions): Promise<string>;
  rememberChallenge(opts: RememberChallengeOptions): ChallengeContextRecord;
  consumeChallenge(
    opts: string | ConsumeChallengeOptions,
  ): ChallengeConsumption;
  recordConsumption(
    challenge: string,
    consumedBy: ChallengeUsedBy,
  ): void;
  cancelChallenge(challenge: string, reason?: string): boolean;
  cancelSession(sessionKey: string, reason?: string): number;
  cancelCeremony(ceremonyID: string, reason?: string): number;
  getChallenge(challenge: string): ChallengeContextRecord | undefined;
  reset(reason?: string): void;
  restart(reason?: string): void;
  readonly generation: number;
  readonly currentGeneration: number;
  /** Most recent ceremony/session generation observed by this ledger. */
  readonly ceremonyGeneration: number;
  /** Alias for `ceremonyGeneration`. */
  readonly currentCeremonyGeneration: number;
  readonly state: SERVICE_STATE;
};

/**
 * A process-local ledger of challenge/ceremony generations.
 *
 * SimpleWebAuthn does not own an RP's session database, but it can make the challenge ->
 * verification -> session handoff safe. The ledger is intentionally in-process by default (like
 * `SettingsService`); RPs running multiple server instances should persist the same challenge and
 * ceremony generation in their shared session store or provide a custom implementation.
 */
export class BaseChallengeContextService implements ChallengeContextService {
  private readonly records = new Map<string, ChallengeContextRecord>();
  private readonly aliasIndex = new Map<string, Set<ChallengeContextRecord>>();
  private readonly sessionGenerations = new Map<string, number>();
  private readonly retiredCeremonies = new Map<string, ChallengeStatus>();
  private readonly retiredSessionByChallenge = new Map<string, ChallengeContextRecord>();
  private _generation = 1;
  private _ceremonySequence = 0;

  constructor(_logger?: unknown) {
    // Logger is accepted for API compatibility; this in-process ledger has no lifecycle logs.
  }

  get generation(): number {
    return this._generation;
  }

  get currentGeneration(): number {
    return this._generation;
  }

  get ceremonyGeneration(): number {
    return this._ceremonySequence;
  }

  get currentCeremonyGeneration(): number {
    return this._ceremonySequence;
  }

  get state(): SERVICE_STATE {
    return SERVICE_STATE.READY;
  }

  async issueChallenge(opts: ChallengeIssueOptions): Promise<string> {
    const ceremony = opts.ceremony ?? 'authentication';
    const binding = normalizeBinding(opts.binding);
    const context = normalizeChallengeContext(
      opts.context ?? (opts.rpID ? { rpID: opts.rpID } : undefined),
      opts.rpID ?? '',
    ) ?? {
      origins: [],
      rpID: opts.rpID ?? '',
    };

    const sessionKey = trim(opts.sessionKey);
    const ceremonyID = trim(opts.ceremonyID) ?? (await randomBase64URL(16));
    const ceremonyGeneration = opts.ceremonyGeneration ??
      this.nextCeremonyGeneration(sessionKey ?? ceremonyID);
    const baseChallenge = opts.challenge;
    const bindGeneration = opts.bindGeneration ?? true;

    const existingEnvelope = decodeEnvelope(baseChallenge);
    if (existingEnvelope.status === 'valid') {
      const reason =
        'A previously issued ceremony challenge cannot be reused to start a new ceremony';
      throw new ChallengeContextError({
        message: reason,
        code: 'CHALLENGE_STALE_GENERATION',
        audit: buildChallengeAudit({
          ceremony,
          stage: 'challenge_generation',
          reason,
          expectedOrigins: context.origins,
          expectedRPID: context.rpID || undefined,
          challengeTenant: context.tenant,
          challengeID: challengeIDFor(baseChallenge),
          ceremonyID: existingEnvelope.envelope.cid,
          ceremonyGeneration: existingEnvelope.envelope.cg,
          generation: existingEnvelope.envelope.g,
          currentGeneration: this._generation,
          sessionKey,
        }),
      });
    }

    if (opts.ceremonyGeneration !== undefined) {
      const retired = this.findRetiredCeremony(
        ceremonyID,
        opts.ceremonyGeneration,
        baseChallenge,
      );
      if (retired) {
        const error = new Error(
          `Ceremony ${ceremonyID} generation ${opts.ceremonyGeneration} was already ` +
            `${retired.status} and cannot be restarted by retry`,
        );
        const code = retired.status === 'used'
          ? 'CHALLENGE_ALREADY_USED'
          : 'CHALLENGE_CANCELLED';
        throw new ChallengeContextError({
          message: error.message,
          code,
          cause: error,
          audit: buildChallengeAudit({
            ceremony,
            stage: retired.status === 'used' ? 'challenge_replay' : 'challenge_cancellation',
            reason: error.message,
            expectedOrigins: retired.context.origins,
            expectedRPID: retired.context.rpID || undefined,
            challengeTenant: retired.context.tenant,
            challengeID: retired.challengeID,
            ceremonyID: retired.ceremonyID,
            ceremonyGeneration: retired.ceremonyGeneration,
            generation: retired.generation,
            currentGeneration: this._generation,
            sessionKey,
            challengeSessionKey: retired.sessionKey,
          }),
        });
      }
    }

    let challenge = baseChallenge;
    let envelope: ChallengeEnvelope | undefined;
    if (bindGeneration) {
      envelope = {
        v: 1,
        k: ceremonyKind(ceremony),
        g: this._generation,
        n: await randomBase64URL(16),
        t: await randomBase64URL(32),
        c: baseChallenge,
        cid: ceremonyID,
        ceremonyID,
        cg: ceremonyGeneration,
        ceremonyGeneration,
        s: sessionKey,
        sessionKey,
        challengeID: challengeIDFor(baseChallenge),
      };
      challenge = encodeEnvelope(envelope);
    }

    const record: ChallengeContextRecord = {
      challengeID: challengeIDFor(baseChallenge),
      challenge,
      baseChallenge,
      ceremony,
      context: {
        origins: [...context.origins],
        rpID: context.rpID,
        tenant: context.tenant,
        userID: context.userID,
      },
      binding,
      generation: this._generation,
      ceremonyID,
      ceremonyGeneration,
      sessionKey,
      rpID: context.rpID,
      ceremonyMetadataExposed: opts.ceremonyMetadataExposed ?? true,
      scopeKey: scopeKeyFor({ ceremony, context, binding, sessionKey }),
      createdAt: Date.now(),
      expiresAt: this.expiryFor(opts.timeoutMS),
      status: 'pending',
      challengeAliases: opts.challengeAliases
        ? [...opts.challengeAliases]
        : undefined,
      envelope,
    };

    this.pruneExpired();
    this.enforceCapacity();
    this.invalidateSuperseded(record);
    this.records.set(this.recordKey(challenge), record);
    this.indexRecord(record);

    return challenge;
  }

  rememberChallenge(opts: RememberChallengeOptions): ChallengeContextRecord {
    this.pruneExpired();
    this.enforceCapacity();

    const decodedEnvelope = decodeEnvelope(opts.challenge);
    const envelope = opts.envelope
      ? completeEnvelope(opts.envelope)
      : (decodedEnvelope.status === 'valid' ? decodedEnvelope.envelope : undefined);
    const baseChallenge = envelope?.c ?? opts.challenge;
    const ceremony = envelope
      ? ceremonyFromKind(envelope.k)
      : (opts.ceremony ?? 'authentication');
    const context = normalizeChallengeContext(
      opts.context ?? (opts.rpID ? { rpID: opts.rpID } : undefined),
      opts.rpID ?? '',
    ) ?? {
      origins: [],
      rpID: opts.rpID ?? '',
    };
    const binding = normalizeBinding(opts.binding);
    const sessionKey = trim(opts.sessionKey) ?? trim(envelope?.s);
    const ceremonyID = trim(opts.ceremonyID) ?? envelope?.cid ??
      randomID('ceremony');
    const ceremonyGeneration = opts.ceremonyGeneration ?? envelope?.cg ??
      this.nextCeremonyGeneration(sessionKey ?? ceremonyID);

    if (opts.ceremonyGeneration !== undefined) {
      const retired = this.findRetiredCeremony(
        ceremonyID,
        opts.ceremonyGeneration,
        baseChallenge,
      );
      if (retired) {
        return retired;
      }
    }

    const existing = this.findRecordByValue(opts.challenge);
    if (existing.record) {
      // Never revive or rebind a challenge that is already known to this process. This covers
      // callers that reuse a custom challenge string after consumption or cancellation.
      return existing.record;
    }
    if (existing.ambiguous) {
      throw new Error(
        `Challenge "${opts.challenge}" matches more than one outstanding ceremony`,
      );
    }

    const staleEnvelope = envelope !== undefined && envelope.g !== this._generation;
    const record: ChallengeContextRecord = {
      challengeID: challengeIDFor(baseChallenge),
      challenge: opts.challenge,
      baseChallenge,
      ceremony,
      context: {
        origins: [...context.origins],
        rpID: context.rpID,
        tenant: context.tenant,
        userID: context.userID,
      },
      binding,
      generation: this._generation,
      ceremonyID,
      ceremonyGeneration,
      sessionKey,
      rpID: context.rpID,
      ceremonyMetadataExposed: opts.ceremonyMetadataExposed ?? false,
      scopeKey: scopeKeyFor({ ceremony, context, binding, sessionKey }),
      createdAt: Date.now(),
      expiresAt: this.expiryFor(opts.timeoutMS),
      status: staleEnvelope ? 'cancelled' : 'pending',
      cancelReason: staleEnvelope ? 'challenge belongs to a previous process generation' : undefined,
      challengeAliases: opts.challengeAliases ? [...opts.challengeAliases] : undefined,
      envelope,
    };

    if (!staleEnvelope) {
      this.invalidateSuperseded(record);
      this.records.set(this.recordKey(opts.challenge), record);
      this.indexRecord(record);
    }
    return record;
  }

  consumeChallenge(
    challengeOrOpts: string | ConsumeChallengeOptions,
  ): ChallengeConsumption {
    this.pruneExpired();
    const opts: ConsumeChallengeOptions = typeof challengeOrOpts === 'string'
      ? { challenge: challengeOrOpts }
      : challengeOrOpts;
    const {
      challenge,
      ceremony,
      origin,
      rpID,
      tenant,
      sessionKey,
      ceremonyID,
      ceremonyGeneration,
      requireContext = false,
    } = opts;

    const decodedEnvelope = decodeEnvelope(challenge);
    const match = this.findRecordByValue(challenge);
    const record = match.record;
    const challengeID = record?.challengeID ?? challengeIDFor(challenge);
    const generation = record?.generation ??
      (decodedEnvelope.status === 'valid' ? decodedEnvelope.envelope.g : undefined);
    const recordCeremonyID = record?.ceremonyID ??
      (decodedEnvelope.status === 'valid' ? decodedEnvelope.envelope.cid : undefined);
    const recordCeremonyGeneration = record?.ceremonyGeneration ??
      (decodedEnvelope.status === 'valid' ? decodedEnvelope.envelope.cg : undefined);

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
        /**
         * The challenge was issued by this library, but the record is gone. This happens after a
         * reset/restart, after the retention window, or when a caller mixes state between
         * processes. Never silently fall back to stateless verification for these.
         */
        return {
          tracked: true,
          status: 'stale_generation',
          challengeID: challengeIDFor(decodedEnvelope.envelope.c),
          generation: decodedEnvelope.envelope.g,
          ceremonyID: decodedEnvelope.envelope.cid,
          ceremonyGeneration: decodedEnvelope.envelope.cg,
        };
      }

      const retiredSession = this.retiredSessionByChallenge.get(
        challengeIDFor(challenge),
      );
      if (retiredSession) {
        if (sessionKey === undefined) {
          return {
            tracked: true,
            status: 'session_missing',
            record: retiredSession,
            challengeID,
            generation: retiredSession.generation,
            ceremonyID: retiredSession.ceremonyID,
            ceremonyGeneration: retiredSession.ceremonyGeneration,
          };
        }
        if (sessionKey !== retiredSession.sessionKey) {
          return {
            tracked: true,
            status: 'session_mismatch',
            record: retiredSession,
            challengeID,
            generation: retiredSession.generation,
            ceremonyID: retiredSession.ceremonyID,
            ceremonyGeneration: retiredSession.ceremonyGeneration,
          };
        }
        return {
          tracked: true,
          status: retiredSession.status === 'used' ? 'used' : 'cancelled',
          record: retiredSession,
          challengeID,
          generation: retiredSession.generation,
          ceremonyID: retiredSession.ceremonyID,
          ceremonyGeneration: retiredSession.ceremonyGeneration,
        };
      }

      if (requireContext) {
        return {
          tracked: true,
          status: 'missing',
          challengeID,
        };
      }

      return {
        tracked: false,
        status: 'untracked',
        challengeID,
      };
    }

    if (record.generation !== this._generation) {
      return {
        tracked: true,
        status: 'stale_generation',
        record,
        challengeID,
        generation: record.generation,
        ceremonyID: record.ceremonyID,
        ceremonyGeneration: record.ceremonyGeneration,
      };
    }

    if (ceremony !== undefined && record.ceremony !== ceremony) {
      return {
        tracked: true,
        status: 'ceremony_mismatch',
        record,
        challengeID,
        generation,
        ceremonyID: recordCeremonyID,
        ceremonyGeneration: recordCeremonyGeneration,
      };
    }

    if (record.status === 'cancelled' || record.status === 'superseded') {
      return {
        tracked: true,
        status: 'cancelled',
        record,
        challengeID,
        generation,
        ceremonyID: recordCeremonyID,
        ceremonyGeneration: recordCeremonyGeneration,
      };
    }

    if (record.status === 'used') {
      return {
        tracked: true,
        status: 'used',
        record,
        challengeID,
        generation,
        ceremonyID: recordCeremonyID,
        ceremonyGeneration: recordCeremonyGeneration,
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
        generation,
        ceremonyID: recordCeremonyID,
        ceremonyGeneration: recordCeremonyGeneration,
      };
    }

    if (decodedEnvelope.status === 'invalid') {
      return {
        tracked: true,
        status: 'integrity',
        record,
        challengeID,
        generation,
        ceremonyID: recordCeremonyID,
        ceremonyGeneration: recordCeremonyGeneration,
      };
    }

    if (decodedEnvelope.status === 'valid' && record.envelope) {
      if (
        decodedEnvelope.envelope.n !== record.envelope.n ||
        decodedEnvelope.envelope.t !== record.envelope.t ||
        decodedEnvelope.envelope.c !== record.envelope.c
      ) {
        if (
          decodedEnvelope.envelope.g !== record.generation ||
          decodedEnvelope.envelope.c !== record.envelope.c
        ) {
          return {
            tracked: true,
            status: 'stale_generation',
            record,
            challengeID,
            generation: decodedEnvelope.envelope.g,
            ceremonyID: decodedEnvelope.envelope.cid,
            ceremonyGeneration: decodedEnvelope.envelope.cg,
          };
        }
        return {
          tracked: true,
          status: 'integrity',
          record,
          challengeID,
          generation,
          ceremonyID: recordCeremonyID,
          ceremonyGeneration: recordCeremonyGeneration,
        };
      }
    }

    /**
     * Consume before checking ceremony/session/origin/RP ID/tenant. This is the core single-use
     * fence: an attacker who presents a challenge from another tab/session/tenant, or who replays
     * a response, gets exactly one attempt and cannot leave the challenge available for a second
     * reader.
     */
    record.status = 'used';
    record.usedAt = Date.now();
    record.expiresAt = record.usedAt + REPLAY_RETENTION_MS;
    const usedBy: ChallengeUsedBy = { origin, rpID, tenant, sessionKey };
    record.usedBy = usedBy;
    record.consumedBy = { ...usedBy };
    this.retiredCeremonies.set(
      this.ceremonyKey(
        record.ceremonyID,
        record.ceremonyGeneration,
        record.baseChallenge,
      ),
      'used',
    );

    if (
      record.ceremonyMetadataExposed &&
      ceremonyID !== undefined &&
      record.ceremonyID !== ceremonyID
    ) {
      return {
        tracked: true,
        status: 'ceremony_mismatch',
        record,
        challengeID,
        generation,
        ceremonyID: recordCeremonyID,
        ceremonyGeneration: recordCeremonyGeneration,
      };
    }

    if (
      record.ceremonyMetadataExposed &&
      ceremonyGeneration !== undefined &&
      record.ceremonyGeneration !== ceremonyGeneration &&
      record.generation !== ceremonyGeneration
    ) {
      return {
        tracked: true,
        status: 'stale_generation',
        record,
        challengeID,
        generation,
        ceremonyID: recordCeremonyID,
        ceremonyGeneration: recordCeremonyGeneration,
      };
    }

    if (record.sessionKey !== undefined) {
      if (sessionKey === undefined) {
        return {
          tracked: true,
          status: 'session_missing',
          record,
          challengeID,
          generation,
          ceremonyID: recordCeremonyID,
          ceremonyGeneration: recordCeremonyGeneration,
        };
      }
      if (sessionKey !== record.sessionKey) {
        return {
          tracked: true,
          status: 'session_mismatch',
          record,
          challengeID,
          generation,
          ceremonyID: recordCeremonyID,
          ceremonyGeneration: recordCeremonyGeneration,
        };
      }
    }

    if (origin !== undefined && record.context.origins.length > 0) {
      if (!record.context.origins.some((expected) => originsMatch(origin, expected))) {
        return {
          tracked: true,
          status: 'origin_mismatch',
          record,
          challengeID,
          generation,
          ceremonyID: recordCeremonyID,
          ceremonyGeneration: recordCeremonyGeneration,
        };
      }
    }

    if (
      rpID !== undefined &&
      record.context.rpID.length > 0 &&
      !rpIDsMatch(rpID, record.context.rpID)
    ) {
      return {
        tracked: true,
        status: 'rp_id_mismatch',
        record,
        challengeID,
        generation,
        ceremonyID: recordCeremonyID,
        ceremonyGeneration: recordCeremonyGeneration,
      };
    }

    if (record.context.tenant !== undefined) {
      if (tenant === undefined) {
        return {
          tracked: true,
          status: 'tenant_missing',
          record,
          challengeID,
          generation,
          ceremonyID: recordCeremonyID,
          ceremonyGeneration: recordCeremonyGeneration,
        };
      }

      if (tenant !== record.context.tenant) {
        return {
          tracked: true,
          status: 'tenant_mismatch',
          record,
          challengeID,
          generation,
          ceremonyID: recordCeremonyID,
          ceremonyGeneration: recordCeremonyGeneration,
        };
      }
    }

    return {
      tracked: true,
      status: 'available',
      record,
      challengeID,
      generation,
      ceremonyID: recordCeremonyID,
      ceremonyGeneration: recordCeremonyGeneration,
    };
  }

  recordConsumption(
    challenge: string,
    consumedBy: ChallengeUsedBy,
  ): void {
    const record = this.findRecordByValue(challenge).record;
    if (record) {
      record.usedBy = { ...(record.usedBy ?? {}), ...consumedBy };
      record.consumedBy = { ...(record.consumedBy ?? {}), ...consumedBy };
    }
  }

  cancelChallenge(challenge: string, reason?: string): boolean {
    this.pruneExpired();

    const match = this.findRecordByValue(challenge);
    if (!match.record || match.ambiguous) {
      return false;
    }
    const record = match.record;

    if (record.status === 'used' || record.status === 'cancelled') {
      return false;
    }

    record.status = 'cancelled';
    record.cancelReason = reason;
    record.expiresAt = Date.now() + REPLAY_RETENTION_MS;
    this.retiredCeremonies.set(
      this.ceremonyKey(
        record.ceremonyID,
        record.ceremonyGeneration,
        record.baseChallenge,
      ),
      'cancelled',
    );
    return true;
  }

  cancelSession(sessionKey: string, reason?: string): number {
    return this.cancelWhere(
      (record) => record.sessionKey === sessionKey && record.status === 'pending',
      reason ?? `session ${sessionKey} cancelled`,
    );
  }

  cancelCeremony(ceremonyID: string, reason?: string): number {
    return this.cancelWhere(
      (record) => record.ceremonyID === ceremonyID && record.status === 'pending',
      reason ?? `ceremony ${ceremonyID} cancelled`,
    );
  }

  getChallenge(challenge: string): ChallengeContextRecord | undefined {
    this.pruneExpired();
    const match = this.findRecordByValue(challenge);
    return match.ambiguous ? undefined : match.record;
  }

  reset(_reason?: string): void {
    for (const record of this.records.values()) {
      if (record.status === 'pending') {
        record.status = 'cancelled';
        record.cancelReason = 'challenge ledger reset/restarted';
      }
      this.retiredCeremonies.set(
        this.ceremonyKey(
          record.ceremonyID,
          record.ceremonyGeneration,
          record.baseChallenge,
        ),
        record.status,
      );
      if (record.sessionKey !== undefined) {
        this.retiredSessionByChallenge.set(
          challengeIDFor(record.baseChallenge),
          record,
        );
      }
    }
    this.records.clear();
    this.aliasIndex.clear();
    this.sessionGenerations.clear();
    this._generation += 1;
    this._ceremonySequence += 1;
  }

  restart(reason?: string): void {
    this.reset(reason ?? 'simulated process restart');
  }

  private nextCeremonyGeneration(scope: string): number {
    const next = (this.sessionGenerations.get(scope) ?? this._ceremonySequence) + 1;
    this.sessionGenerations.set(scope, next);
    this._ceremonySequence = Math.max(this._ceremonySequence, next);
    return next;
  }

  private cancelWhere(
    predicate: (record: ChallengeContextRecord) => boolean,
    reason: string,
  ): number {
    let cancelled = 0;
    for (const record of this.records.values()) {
      if (!predicate(record)) {
        continue;
      }
      record.status = 'cancelled';
      record.cancelReason = reason;
      record.expiresAt = Date.now() + REPLAY_RETENTION_MS;
      this.retiredCeremonies.set(
        this.ceremonyKey(
          record.ceremonyID,
          record.ceremonyGeneration,
          record.baseChallenge,
        ),
        'cancelled',
      );
      cancelled += 1;
    }
    return cancelled;
  }

  private invalidateSuperseded(next: ChallengeContextRecord): void {
    for (const record of this.records.values()) {
      const supersedable = record.status === 'pending' ||
        (record.status === 'used' && record.committedAt === undefined);
      if (record === next || !supersedable) {
        continue;
      }
      if (
        record.scopeKey === next.scopeKey ||
        record.baseChallenge === next.baseChallenge ||
        (!!next.sessionKey &&
          record.sessionKey !== undefined &&
          record.sessionKey === next.sessionKey) ||
        record.ceremonyID === next.ceremonyID
      ) {
        record.status = 'cancelled';
        record.cancelReason = 'superseded by a newer ceremony';
        record.expiresAt = Date.now() + REPLAY_RETENTION_MS;
        this.retiredCeremonies.set(
          this.ceremonyKey(
            record.ceremonyID,
            record.ceremonyGeneration,
            record.baseChallenge,
          ),
          'cancelled',
        );
      }
    }
  }

  private ceremonyKey(
    ceremonyID: string,
    ceremonyGeneration: number,
    baseChallenge: string,
  ): string {
    return `${ceremonyID}:${ceremonyGeneration}:${challengeIDFor(baseChallenge)}`;
  }

  private findRetiredCeremony(
    ceremonyID: string,
    ceremonyGeneration: number,
    baseChallenge: string,
  ): ChallengeContextRecord | undefined {
    const retiredStatus = this.retiredCeremonies.get(
      this.ceremonyKey(ceremonyID, ceremonyGeneration, baseChallenge),
    );
    if (retiredStatus) {
      return {
        challengeID: challengeIDFor(baseChallenge),
        challenge: baseChallenge,
        baseChallenge,
        ceremony: 'authentication',
        context: { origins: [], rpID: '' },
        binding: {},
        generation: this._generation,
        ceremonyID,
        ceremonyGeneration,
        rpID: '',
        ceremonyMetadataExposed: true,
        scopeKey: '',
        createdAt: 0,
        expiresAt: 0,
        status: retiredStatus,
      };
    }
    for (const record of this.records.values()) {
      if (
        record.ceremonyID === ceremonyID &&
        record.ceremonyGeneration >= ceremonyGeneration &&
        (record.status === 'used' ||
          record.status === 'cancelled' ||
          record.status === 'superseded')
      ) {
        return record;
      }
    }
    return undefined;
  }

  private findRecord(challenge: string): ChallengeContextRecord | undefined {
    const direct = this.records.get(this.recordKey(challenge));
    if (direct) {
      return direct;
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
   * frozen ceremony/context.
   */
  private findRecordByValue(
    challenge: string,
  ): { record?: ChallengeContextRecord; ambiguous: boolean } {
    const direct = this.findRecord(challenge);
    if (direct) {
      return { record: direct, ambiguous: false };
    }

    const aliases = this.aliasIndex.get(challenge);
    if (aliases?.size === 1) {
      return { record: [...aliases][0], ambiguous: false };
    }
    if ((aliases?.size ?? 0) > 1) {
      return { ambiguous: true };
    }

    return { ambiguous: false };
  }

  private recordKey(challenge: string): string {
    const decoded = decodeEnvelope(challenge);
    if (decoded.status === 'valid') {
      return `nonce:${decoded.envelope.n}`;
    }
    return `challenge:${challenge}`;
  }

  private aliasesFor(record: ChallengeContextRecord): string[] {
    const aliases = new Set<string>([
      record.challenge,
      record.baseChallenge,
      ...(record.challengeAliases ?? []),
    ]);
    if (record.envelope?.c) {
      aliases.add(record.envelope.c);
    }
    return [...aliases];
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

  private enforceCapacity(): void {
    if (this.records.size < MAX_RECORDS) {
      return;
    }

    const oldest = [...this.records.entries()]
      .sort(([, a], [, b]) => a.createdAt - b.createdAt)
      .slice(0, Math.max(1, this.records.size - MAX_RECORDS + 1));
    for (const [key, record] of oldest) {
      this.unindexRecord(record);
      this.records.delete(key);
    }
  }

  private expiryFor(timeoutMS?: number): number {
    const timeout = typeof timeoutMS === 'number' && Number.isFinite(timeoutMS)
      ? timeoutMS
      : 60_000;
    return Date.now() + Math.max(timeout, 1);
  }
}

/**
 * The default process-local challenge ledger.
 */
export const ChallengeContextService: ChallengeContextService =
  new BaseChallengeContextService();

/** Aliases for consumers that think in terms of authentication sessions. */
export const AuthenticationChallengeService = ChallengeContextService;
export const SessionChallengeService = ChallengeContextService;

/** Create an isolated ledger, primarily for tests or per-tenant server state. */
export function createChallengeContextService(logger?: unknown): ChallengeContextService {
  return new BaseChallengeContextService(logger);
}

export function createAuthenticationChallengeService(logger?: unknown): ChallengeContextService {
  return new BaseChallengeContextService(logger);
}

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

/**
 * Cancel every pending challenge issued for a browser/tab ceremony identity. RPs can call this
 * from a page-unload/visibilitychange endpoint so a result produced by the closed tab cannot be
 * submitted after a reload.
 */
export function cancelAuthenticationCeremony(
  ceremonyID: string,
  reason?: string,
): number {
  return ChallengeContextService.cancelCeremony(ceremonyID, reason);
}

/** Cancel every pending challenge bound to a login session. */
export function cancelAuthenticationSession(
  sessionKey: string,
  reason?: string,
): number {
  return ChallengeContextService.cancelSession(sessionKey, reason);
}
