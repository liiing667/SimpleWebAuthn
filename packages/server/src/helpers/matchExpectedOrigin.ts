import { SimpleWebAuthnError } from '../errors/index.ts';
import { assertValidExpectedOrigin } from './assertValidExpectedOrigin.ts';
import { buildChallengeAudit } from '../services/challengeContextService.ts';
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

  if (!_expectedOrigins.includes(origin)) {
    const message = `Unexpected response origin "${origin}", expected one of: ${
      _expectedOrigins.join(', ')
    }`;
    throw new SimpleWebAuthnError({
      message,
      code: 'UNEXPECTED_ORIGIN',
      audit: auditContext
        ? buildChallengeAudit({
          ...auditContext,
          ceremony: auditContext.ceremony ?? 'authentication',
          stage: 'origin',
          location:
            'packages/server/src/helpers/matchExpectedOrigin.ts:matchExpectedOrigin',
          reason: message,
          actualOrigin: origin,
          expectedOrigins: auditContext.expectedOrigins ?? _expectedOrigins,
          callerExpectedOrigins: _expectedOrigins,
        })
        : undefined,
    });
  }
}
