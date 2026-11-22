import {
  ChallengeContextError,
  type SimpleWebAuthnErrorCode,
} from '../errors/index.ts';
import type {
  ChallengeAudit,
  VerificationStage,
  WebAuthnCeremony,
} from '../types/audit.ts';
import {
  buildChallengeAudit,
  ChallengeContextService,
  type ChallengeConsumption,
  type ChallengeContextRecord,
} from '../services/challengeContextService.ts';
import { originsMatch, rpIDsMatch } from './canonicalizeOrigin.ts';

export { locationForStage } from '../services/challengeContextService.ts';

export const AUTHENTICATION_SOURCE =
  'packages/server/src/authentication/verifyAuthenticationResponse.ts:verifyAuthenticationResponse';
export const REGISTRATION_SOURCE =
  'packages/server/src/registration/verifyRegistrationResponse.ts:verifyRegistrationResponse';

export function asArray(value: string | string[]): string[] {
  return Array.isArray(value) ? [...value] : [value];
}

export function ceremonyLabel(ceremony: WebAuthnCeremony): string {
  return ceremony === 'authentication' ? 'Authentication' : 'Registration';
}

export function codeForStage(stage: VerificationStage): SimpleWebAuthnErrorCode {
  switch (stage) {
    case 'origin':
      return 'UNEXPECTED_ORIGIN';
    case 'rp_id':
      return 'UNEXPECTED_RP_ID';
    case 'tenant':
      return 'UNEXPECTED_TENANT';
    case 'session':
      return 'UNEXPECTED_SESSION';
    case 'ceremony':
      return 'CEREMONY_KIND_MISMATCH';
    case 'challenge_integrity':
      return 'CHALLENGE_CONTEXT_INVALID';
    case 'challenge_lookup':
      return 'CHALLENGE_CONTEXT_MISSING';
    case 'challenge_expiry':
      return 'CHALLENGE_EXPIRED';
    case 'challenge_replay':
      return 'CHALLENGE_ALREADY_USED';
    case 'challenge_cancellation':
      return 'CHALLENGE_CANCELLED';
    case 'challenge_generation':
      return 'CHALLENGE_STALE_GENERATION';
    default:
      return 'BAD_ARGUMENT';
  }
}

/**
 * Re-check the challenge generation immediately before publishing a successful result. A reset
 * or restart that happens while signature/attestation/metadata work is in flight must not let the
 * old candidate be committed to a new session.
 */
export function assertChallengeGenerationCurrent(opts: {
  record: ChallengeContextRecord;
  ceremony: WebAuthnCeremony;
  actualOrigin: string;
  actualRPID: string;
  sessionTenant?: string;
  sessionKey?: string;
  currentGeneration?: number;
  browserCeremonyID?: string;
  auditContext?: Partial<ChallengeAudit>;
}): void {
  const currentGeneration = opts.currentGeneration ?? ChallengeContextService.generation;
  if (opts.record.generation === currentGeneration) {
    return;
  }

  const reason =
    `${ceremonyLabel(opts.ceremony)} challenge generation ${opts.record.generation} is no ` +
    `longer current (${currentGeneration}); refusing to publish a stale session`;
  throw new ChallengeContextError({
    message: reason,
    code: 'CHALLENGE_STALE_GENERATION',
    audit: buildChallengeAudit({
      ...(opts.auditContext ?? {}),
      ceremony: opts.ceremony,
      stage: 'commit',
      location:
        `${opts.ceremony === 'authentication' ? AUTHENTICATION_SOURCE : REGISTRATION_SOURCE}#commit`,
      reason,
      actualOrigin: opts.actualOrigin,
      actualRPID: opts.actualRPID,
      expectedOrigins: opts.record.context.origins,
      expectedRPID: opts.record.context.rpID || undefined,
      tenant: opts.sessionTenant,
      challengeTenant: opts.record.context.tenant,
      challengeID: opts.record.challengeID,
      ceremonyID: opts.record.ceremonyID,
      browserCeremonyID: opts.browserCeremonyID,
      ceremonyGeneration: opts.record.ceremonyGeneration,
      generation: opts.record.generation,
      currentGeneration,
      sessionKey: opts.sessionKey,
      challengeSessionKey: opts.record.sessionKey,
    }),
  });
}

/**
 * Turn a `ChallengeContextService.consumeChallenge()` rejection into an error carrying the
 * actual presented identity and the exact rejection stage.
 */
export function challengeConsumptionError(opts: {
  consumption: ChallengeConsumption;
  ceremony: WebAuthnCeremony;
  actualOrigin?: string;
  actualRPID?: string;
  tenant?: string;
  sessionKey?: string;
  browserCeremonyID?: string;
  callerExpectedOrigins?: string[];
  callerExpectedRPIDs?: string[];
  audit?: Partial<ChallengeAudit>;
}): ChallengeContextError {
  const {
    consumption,
    ceremony,
    actualOrigin,
    actualRPID,
    tenant,
    sessionKey,
    browserCeremonyID,
    callerExpectedOrigins,
    callerExpectedRPIDs,
    audit,
  } = opts;
  const { status, record, challengeID } = consumption;

  let code: SimpleWebAuthnErrorCode = 'CHALLENGE_CONTEXT_INVALID';
  let stage: VerificationStage = 'challenge_lookup';
  let reason = `${ceremonyLabel(ceremony)} challenge could not be accepted`;

  switch (status) {
    case 'missing':
      code = 'CHALLENGE_CONTEXT_MISSING';
      stage = 'challenge_lookup';
      reason =
        `${ceremonyLabel(ceremony)} challenge was not issued by this process; regenerate the options before retrying`;
      break;
    case 'ambiguous':
      code = 'CHALLENGE_CONTEXT_INVALID';
      stage = 'challenge_lookup';
      reason =
        `${ceremonyLabel(ceremony)} challenge matches more than one outstanding ceremony; regenerate the options`;
      break;
    case 'integrity':
      code = 'CHALLENGE_CONTEXT_INVALID';
      stage = 'challenge_integrity';
      reason =
        `${ceremonyLabel(ceremony)} challenge envelope was malformed or did not match its issued record`;
      break;
    case 'stale_generation':
      code = 'CHALLENGE_STALE_GENERATION';
      stage = consumption.record ? 'challenge_generation' : 'challenge_lookup';
      reason =
        `${ceremonyLabel(ceremony)} challenge belongs to an older ceremony generation; regenerate the options`;
      break;
    case 'ceremony_mismatch':
      code = 'CEREMONY_KIND_MISMATCH';
      stage = 'ceremony';
      reason =
        `${ceremonyLabel(ceremony)} challenge was issued for ${record?.ceremony ?? 'another ceremony'}`;
      break;
    case 'cancelled':
      code = 'CHALLENGE_CANCELLED';
      stage = 'challenge_cancellation';
      reason = `${ceremonyLabel(ceremony)} challenge was cancelled${
        record?.cancelReason ? `: ${record.cancelReason}` : ''
      }`;
      break;
    case 'expired':
      code = 'CHALLENGE_EXPIRED';
      stage = 'challenge_expiry';
      reason = `${ceremonyLabel(ceremony)} challenge has expired`;
      break;
    case 'used':
      code = 'CHALLENGE_ALREADY_USED';
      stage = 'challenge_replay';
      reason = `${ceremonyLabel(ceremony)} challenge has already been used`;
      break;
    case 'origin_mismatch':
      code = 'UNEXPECTED_ORIGIN';
      stage = 'origin';
      reason = `Unexpected response origin "${actualOrigin}", challenge was bound to: ${
        record?.context.origins.join(', ') ?? ''
      }`;
      break;
    case 'rp_id_mismatch':
      code = 'UNEXPECTED_RP_ID';
      stage = 'rp_id';
      reason = `Unexpected response RP ID "${actualRPID}", challenge was bound to "${
        record?.context.rpID ?? ''
      }"`;
      break;
    case 'tenant_missing':
      code = 'UNEXPECTED_TENANT';
      stage = 'tenant';
      reason =
        `${ceremonyLabel(ceremony)} challenge is bound to tenant "${
          record?.context.tenant ?? ''
        }", but no tenant was supplied`;
      break;
    case 'tenant_mismatch':
      code = 'UNEXPECTED_TENANT';
      stage = 'tenant';
      reason =
        `${ceremonyLabel(ceremony)} response tenant "${tenant ?? ''}" does not match ` +
        `the challenge tenant "${record?.context.tenant ?? ''}"`;
      break;
    case 'session_missing':
      code = 'UNEXPECTED_SESSION';
      stage = 'session';
      reason =
        `${ceremonyLabel(ceremony)} challenge belongs to session "${record?.sessionKey ?? ''}", ` +
        'but no session identity was supplied';
      break;
    case 'session_mismatch':
      code = 'UNEXPECTED_SESSION';
      stage = 'session';
      reason =
        `${ceremonyLabel(ceremony)} response session "${sessionKey ?? ''}" does not match ` +
        `the challenge session "${record?.sessionKey ?? ''}"`;
      break;
    case 'untracked':
    case 'available':
      break;
  }

  return new ChallengeContextError({
    message: reason,
    code,
    audit: buildChallengeAudit({
      ...(audit ?? {}),
      ceremony,
      stage,
      reason,
      actualOrigin,
      actualRPID,
      expectedOrigins: record?.context.origins ?? [],
      callerExpectedOrigins,
      expectedRPID: record?.context.rpID || undefined,
      callerExpectedRPIDs,
      tenant,
      challengeTenant: record?.context.tenant,
      challengeID,
      ceremonyID: consumption.ceremonyID ?? record?.ceremonyID,
      browserCeremonyID,
      ceremonyGeneration: consumption.ceremonyGeneration ?? record?.ceremonyGeneration,
      generation: consumption.generation ?? record?.generation,
      currentGeneration: ChallengeContextService.generation,
      sessionKey,
      challengeSessionKey: record?.sessionKey,
    }),
  });
}

/**
 * Validate the response's actual origin/RP ID/tenant against the context frozen at challenge
 * generation. This runs after the RP ID has been matched from authenticator data so the audit
 * report can include the actual origin and RP ID.
 */
export function assertChallengeResponseContext(opts: {
  record: ChallengeContextRecord;
  ceremony: WebAuthnCeremony;
  actualOrigin: string;
  actualRPID: string;
  sessionTenant?: string;
  sessionKey?: string;
  browserCeremonyID?: string;
  callerExpectedOrigins?: string[];
  callerExpectedRPIDs?: string[];
  auditContext?: Partial<ChallengeAudit>;
  currentGeneration?: number;
}): void {
  const {
    record,
    ceremony,
    actualOrigin,
    actualRPID,
    sessionTenant,
    sessionKey,
    browserCeremonyID,
    callerExpectedOrigins,
    callerExpectedRPIDs,
    auditContext,
    currentGeneration,
  } = opts;
  const audit = (stage: VerificationStage, reason: string): ChallengeAudit =>
    buildChallengeAudit({
      ...(auditContext ?? {}),
      ceremony,
      stage,
      reason,
      actualOrigin,
      actualRPID,
      expectedOrigins: record.context.origins,
      callerExpectedOrigins,
      expectedRPID: record.context.rpID || undefined,
      callerExpectedRPIDs,
      tenant: sessionTenant,
      challengeTenant: record.context.tenant,
      challengeID: record.challengeID,
      ceremonyID: record.ceremonyID,
      browserCeremonyID,
      ceremonyGeneration: record.ceremonyGeneration,
      generation: record.generation,
      currentGeneration: currentGeneration ?? ChallengeContextService.generation,
      sessionKey,
      challengeSessionKey: record.sessionKey,
    });

  if (
    record.context.origins.length > 0 &&
    !record.context.origins.some((expected) => originsMatch(actualOrigin, expected))
  ) {
    const reason =
      `Unexpected response origin "${actualOrigin}", expected one of: ` +
      `${record.context.origins.join(', ')} (${ceremonyLabel(ceremony)} challenge context)`;
    throw new ChallengeContextError({
      message: reason,
      code: 'UNEXPECTED_ORIGIN',
      audit: audit('origin', reason),
    });
  }

  if (
    record.context.rpID.length > 0 &&
    !rpIDsMatch(actualRPID, record.context.rpID)
  ) {
    const reason =
      `Unexpected response RP ID "${actualRPID}", expected "${record.context.rpID}" ` +
      `(${ceremonyLabel(ceremony)} challenge context)`;
    throw new ChallengeContextError({
      message: reason,
      code: 'UNEXPECTED_RP_ID',
      audit: audit('rp_id', reason),
    });
  }

  if (record.context.tenant !== undefined) {
    if (sessionTenant === undefined) {
      const reason =
        `${ceremonyLabel(ceremony)} challenge is bound to tenant "${record.context.tenant}", ` +
        'but no session tenant was supplied';
      throw new ChallengeContextError({
        message: reason,
        code: 'UNEXPECTED_TENANT',
        audit: audit('tenant', reason),
      });
    }
    if (sessionTenant !== record.context.tenant) {
      const reason =
        `Unexpected response tenant "${sessionTenant}", expected "${record.context.tenant}" ` +
        `(${ceremonyLabel(ceremony)} challenge context)`;
      throw new ChallengeContextError({
        message: reason,
        code: 'UNEXPECTED_TENANT',
        audit: audit('tenant', reason),
      });
    }
  }
}
