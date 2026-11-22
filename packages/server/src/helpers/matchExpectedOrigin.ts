import { SimpleWebAuthnError } from '../errors/index.ts';
import { assertValidExpectedOrigin } from './assertValidExpectedOrigin.ts';
import { originsMatch } from './canonicalizeOrigin.ts';
import type { ChallengeAudit } from '../types/audit.ts';

/**
 * Check that the origin reported in a WebAuthn response is an expected one.
 *
 * Raises a `SimpleWebAuthnError` if not match is found.
 */
export function matchExpectedOrigin(
  origin: string,
  expectedOrigin: string | string[],
  auditContext?: Partial<ChallengeAudit>,
) {
  let _expectedOrigins: string[] = [];
  if (typeof expectedOrigin === 'string') {
    _expectedOrigins = [expectedOrigin];
  } else {
    _expectedOrigins = expectedOrigin;
  }

  for (const _origin of _expectedOrigins) {
    assertValidExpectedOrigin(_origin);
  }

  if (!_expectedOrigins.some((expected) => originsMatch(origin, expected))) {
    throw new SimpleWebAuthnError({
      message: `Unexpected response origin "${origin}", expected one of: ${
        _expectedOrigins.join(
          ', ',
        )
      }`,
      code: 'UNEXPECTED_ORIGIN',
      audit: buildOriginAudit(origin, _expectedOrigins, auditContext),
    });
  }
}

function buildOriginAudit(
  origin: string,
  expectedOrigins: string[],
  originAuditContext: Partial<ChallengeAudit> | undefined,
): ChallengeAudit | undefined {
  if (!originAuditContext) {
    return undefined;
  }

  return {
    ceremony: originAuditContext.ceremony ?? 'authentication',
    stage: 'origin',
    location: 'packages/server/src/helpers/matchExpectedOrigin.ts:matchExpectedOrigin',
    reason: `Unexpected response origin "${origin}"`,
    actualOrigin: origin,
    expectedOrigins: originAuditContext.expectedOrigins ?? expectedOrigins,
    callerExpectedOrigins: expectedOrigins,
    actualRPID: originAuditContext.actualRPID,
    expectedRPID: originAuditContext.expectedRPID,
    callerExpectedRPIDs: originAuditContext.callerExpectedRPIDs,
    tenant: originAuditContext.tenant,
    challengeTenant: originAuditContext.challengeTenant,
    challengeID: originAuditContext.challengeID,
    generation: originAuditContext.generation,
    currentGeneration: originAuditContext.currentGeneration,
    timestamp: new Date().toISOString(),
  };
}
