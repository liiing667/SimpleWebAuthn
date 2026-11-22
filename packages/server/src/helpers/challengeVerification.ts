import {
  ChallengeContextError,
  SimpleWebAuthnError,
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
  type ChallengeContextRecord,
  type ChallengeConsumption,
} from '../services/challengeContextService.ts';
import { originsMatch, rpIDsMatch } from './canonicalizeOrigin.ts';

export const AUTHENTICATION_SOURCE =
  'packages/server/src/authentication/verifyAuthenticationResponse.ts:verifyAuthenticationResponse';
export const REGISTRATION_SOURCE =
  'packages/server/src/registration/verifyRegistrationResponse.ts:verifyRegistrationResponse';
const CONTEXT_HELPER_SOURCE =
  'packages/server/src/helpers/challengeVerification.ts:assertChallengeResponseContext';

export function asArray(value: string | string[]): string[] {
  return Array.isArray(value) ? [...value] : [value];
}

export function ceremonyLabel(ceremony: WebAuthnCeremony): string {
  return ceremony === 'authentication' ? 'Authentication' : 'Registration';
}

/**
 * Turn a `ChallengeContextService.consumeChallenge()` rejection into an error that carries the
 * actual presented origin/RP ID/tenant and the exact rejection stage.
 */
export function challengeConsumptionError(opts: {
  consumption: ChallengeConsumption;
  ceremony: WebAuthnCeremony;
  audit: Partial<ChallengeAudit> | undefined;
}): ChallengeContextError {
  const { consumption, ceremony, audit } = opts;
  const { status, record, challengeID } = consumption;

  let code: SimpleWebAuthnErrorCode = 'CHALLENGE_CONTEXT_INVALID';
  let stage: VerificationStage = 'challenge_lookup';
  let reason = `${ceremonyLabel(ceremony)} challenge context could not be accepted`;

  switch (status) {
    case 'missing':
      code = 'CHALLENGE_CONTEXT_MISSING';
      stage = 'challenge_lookup';
      reason =
        `${ceremonyLabel(ceremony)} challenge context was not found; regenerate the options before retrying`;
      break;
    case 'ambiguous':
      code = 'CHALLENGE_CONTEXT_INVALID';
      stage = 'challenge_lookup';
      reason =
        `${ceremonyLabel(ceremony)} challenge matches more than one outstanding context; regenerate the options`;
      break;
    case 'integrity':
      code = 'CHALLENGE_CONTEXT_INVALID';
      stage = 'challenge_integrity';
      reason =
        `${ceremonyLabel(ceremony)} challenge envelope was malformed or did not match its issued record`;
      break;
    case 'stale_generation':
      code = 'CHALLENGE_STALE_GENERATION';
      stage = 'challenge_lookup';
      reason =
        `${ceremonyLabel(ceremony)} challenge belongs to generation ${consumption.generation}, ` +
        `but this process is at generation ${ChallengeContextService.generation}; regenerate the options`;
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
      reason = `Unexpected response origin "${audit?.actualOrigin}", challenge was bound to: ${
        record?.context.origins.join(', ') ?? ''
      }`;
      break;
    case 'rp_id_mismatch':
      code = 'UNEXPECTED_RP_ID';
      stage = 'rp_id';
      reason = `Unexpected response RP ID "${audit?.actualRPID}", challenge was bound to "${
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
        `${ceremonyLabel(ceremony)} response tenant "${audit?.tenant ?? ''}" does not match ` +
        `the challenge tenant "${record?.context.tenant ?? ''}"`;
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
      location: locationForStage(ceremony, stage),
      reason,
      challengeID,
      expectedOrigins: record?.context.origins ?? audit?.expectedOrigins ?? [],
      expectedRPID: record?.context.rpID ?? audit?.expectedRPID,
      challengeTenant: record?.context.tenant ?? audit?.challengeTenant,
      generation: consumption.generation ?? record?.generation,
      currentGeneration: ChallengeContextService.generation,
    }),
  });
}

export function codeForStage(stage: VerificationStage): SimpleWebAuthnErrorCode {
  switch (stage) {
    case 'origin':
      return 'UNEXPECTED_ORIGIN';
    case 'rp_id':
      return 'UNEXPECTED_RP_ID';
    case 'tenant':
      return 'UNEXPECTED_TENANT';
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
    default:
      return 'BAD_ARGUMENT';
  }
}

export function locationForStage(
  ceremony: WebAuthnCeremony,
  stage: VerificationStage,
): string {
  const source = ceremony === 'authentication' ? AUTHENTICATION_SOURCE : REGISTRATION_SOURCE;

  switch (stage) {
    case 'origin':
      return 'packages/server/src/services/challengeContextService.ts:consumeChallenge#origin';
    case 'rp_id':
      return 'packages/server/src/services/challengeContextService.ts:consumeChallenge#rp_id';
    case 'challenge_lookup':
    case 'challenge_integrity':
    case 'challenge_replay':
    case 'challenge_expiry':
    case 'challenge_cancellation':
    case 'tenant':
      return 'packages/server/src/services/challengeContextService.ts:consumeChallenge';
    default:
      return `${source}#${stage}`;
  }
}

/**
 * Validate the response's actual origin/RP ID/tenant against the context frozen at challenge
 * generation. This runs after the RP ID has been matched from authenticator data so the audit
 * report can always include the actual RP ID, even when the tenant/origin check is what fails.
 */
export function assertChallengeResponseContext(opts: {
  record: ChallengeContextRecord;
  ceremony: WebAuthnCeremony;
  actualOrigin: string;
  actualRPID: string;
  sessionTenant?: string;
  auditContext?: Partial<ChallengeAudit>;
  currentGeneration?: number;
}): void {
  const { record, ceremony, actualOrigin, actualRPID, sessionTenant, auditContext } = opts;
  const currentGeneration = opts.currentGeneration ?? ChallengeContextService.generation;

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
      audit: buildChallengeAudit({
        ...(auditContext ?? {}),
        ceremony,
        stage: 'origin',
        location: `${CONTEXT_HELPER_SOURCE}#origin`,
        reason,
        actualOrigin,
        actualRPID,
        expectedOrigins: record.context.origins,
        expectedRPID: record.context.rpID,
        tenant: sessionTenant,
        challengeTenant: record.context.tenant,
        currentGeneration,
      }),
    });
  }

  if (!rpIDsMatch(actualRPID, record.context.rpID)) {
    const reason =
      `Unexpected response RP ID "${actualRPID}", expected "${record.context.rpID}" ` +
      `(${ceremonyLabel(ceremony)} challenge context)`;
    throw new ChallengeContextError({
      message: reason,
      code: 'UNEXPECTED_RP_ID',
      audit: buildChallengeAudit({
        ...(auditContext ?? {}),
        ceremony,
        stage: 'rp_id',
        location: `${CONTEXT_HELPER_SOURCE}#rp_id`,
        reason,
        actualOrigin,
        actualRPID,
        expectedOrigins: record.context.origins,
        expectedRPID: record.context.rpID,
        tenant: sessionTenant,
        challengeTenant: record.context.tenant,
        currentGeneration,
      }),
    });
  }

  if (record.context.tenant !== undefined) {
    let reason: string | undefined;
    if (sessionTenant === undefined) {
      reason =
        `Unexpected response tenant, expected "${record.context.tenant}" ` +
        `(${ceremonyLabel(ceremony)} challenge context), but no session tenant was supplied`;
    } else if (sessionTenant !== record.context.tenant) {
      reason =
        `Unexpected response tenant "${sessionTenant}", expected "${record.context.tenant}" ` +
        `(${ceremonyLabel(ceremony)} challenge context)`;
    }

    if (reason) {
      throw new ChallengeContextError({
        message: reason,
        code: 'UNEXPECTED_TENANT',
        audit: buildChallengeAudit({
          ...(auditContext ?? {}),
          ceremony,
          stage: 'tenant',
          location: `${CONTEXT_HELPER_SOURCE}#tenant`,
          reason,
          actualOrigin,
          actualRPID,
          expectedOrigins: record.context.origins,
          expectedRPID: record.context.rpID,
          tenant: sessionTenant,
          challengeTenant: record.context.tenant,
          currentGeneration,
        }),
      });
    }
  }
}

/**
 * Re-check the challenge generation immediately before publishing a successful result. A reset or
 * restart that happens while signature/attestation/metadata work is in flight must not let the
 * old candidate be committed to a new session.
 */
export function assertChallengeGenerationCurrent(opts: {
  record: ChallengeContextRecord;
  ceremony: WebAuthnCeremony;
  actualOrigin: string;
  actualRPID: string;
  sessionTenant?: string;
  auditContext?: Partial<ChallengeAudit>;
  currentGeneration?: number;
}): void {
  const {
    record,
    ceremony,
    actualOrigin,
    actualRPID,
    sessionTenant,
    auditContext,
    currentGeneration = ChallengeContextService.generation,
  } = opts;
  if (record.generation === currentGeneration) {
    return;
  }

  const reason =
    `${ceremonyLabel(ceremony)} challenge generation ${record.generation} is no longer current ` +
    `(${currentGeneration}); refusing to publish a stale session`;
  throw new ChallengeContextError({
    message: reason,
    code: 'CHALLENGE_STALE_GENERATION',
    audit: buildChallengeAudit({
      ...(auditContext ?? {}),
      ceremony,
      stage: 'commit',
      location: `${ceremony === 'authentication' ? AUTHENTICATION_SOURCE : REGISTRATION_SOURCE}#commit`,
      reason,
      actualOrigin,
      actualRPID,
      expectedOrigins: record.context.origins,
      expectedRPID: record.context.rpID,
      tenant: sessionTenant,
      challengeTenant: record.context.tenant,
      generation: record.generation,
      currentGeneration,
    }),
  });
}

/**
 * Rethrow a verification failure with the challenge audit attached. Legacy/stateless callers are
 * left completely untouched when `auditContext` is undefined.
 */
export function rethrowWithChallengeAudit(opts: {
  error: unknown;
  ceremony: WebAuthnCeremony;
  stage: VerificationStage;
  auditContext: Partial<ChallengeAudit> | undefined;
  actualOrigin?: string;
  actualRPID?: string;
}): never {
  const { error, ceremony, stage, auditContext, actualOrigin, actualRPID } = opts;

  if (!auditContext) {
    throw error;
  }

  if (error instanceof ChallengeContextError) {
    throw error;
  }

  const err = error as Error;
  const existingAudit = error instanceof SimpleWebAuthnError ? error.audit : undefined;
  const existingCode = error instanceof SimpleWebAuthnError ? error.code : undefined;
  const finalStage = existingAudit?.stage ?? stage;
  const reason = err?.message ?? `${ceremonyLabel(ceremony)} verification failed`;

  throw new ChallengeContextError({
    message: reason,
    code: existingCode ?? codeForStage(finalStage),
    cause: error instanceof Error ? error : undefined,
    audit: buildChallengeAudit({
      ...auditContext,
      ...(existingAudit ?? {}),
      ceremony,
      stage: finalStage,
      location: existingAudit?.location ?? locationForStage(ceremony, finalStage),
      reason,
      actualOrigin: existingAudit?.actualOrigin ?? actualOrigin,
      expectedOrigins: existingAudit?.expectedOrigins ??
        auditContext.expectedOrigins ?? [],
      actualRPID: existingAudit?.actualRPID ?? actualRPID,
      currentGeneration: ChallengeContextService.generation,
    }),
  });
}
