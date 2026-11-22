import type { COSEALG } from '../helpers/cose.ts';
import { mapCoseAlgToWebCryptoKeyAlgName } from '../helpers/iso/isoCrypto/mapCoseAlgToWebCryptoKeyAlgName.ts';
import type { ChallengeAudit } from '../types/audit.ts';

/**
 * Base error class that helps disambiguate SimpleWebAuthn library errors from other library errors
 */
export class SimpleWebAuthnError extends Error {
  code: SimpleWebAuthnErrorCode;
  /**
   * Structured information about where and why verification was rejected.
   *
   * This is only populated for the new challenge-context checks; errors raised by legacy,
   * stateless verification calls keep their historical shape.
   */
  audit?: ChallengeAudit;
  /** Alias for `audit`, for consumers that prefer a generic error-details field */
  details?: ChallengeAudit;

  constructor({ message, code, cause, audit }: {
    message: string;
    code: SimpleWebAuthnErrorCode;
    cause?: Error;
    audit?: ChallengeAudit;
  }) {
    super(message, { cause });
    this.name = 'SimpleWebAuthnError';
    this.code = code;
    this.audit = audit;
    this.details = audit;
  }
}

/**
 * An error raised by a verification entry point after a challenge was bound to an origin, RP ID
 * and/or tenant. `audit` is always present so callers can identify the exact rejection stage and
 * the actual origin/RP ID/tenant that was presented.
 */
export class ChallengeContextError extends SimpleWebAuthnError {
  override audit: ChallengeAudit;
  override details: ChallengeAudit;

  constructor({ message, code, cause, audit }: {
    message: string;
    code: SimpleWebAuthnErrorCode;
    cause?: Error;
    audit: ChallengeAudit;
  }) {
    super({ message, code, cause, audit });
    this.name = 'ChallengeContextError';
    this.audit = audit;
    this.details = audit;
  }
}

export class PQCNotSupportedError extends SimpleWebAuthnError {
  constructor(alg: COSEALG) {
    const webCryptoAlg = mapCoseAlgToWebCryptoKeyAlgName(alg);
    const message = `This runtime's WebCrypto.subtle does not support use of ${webCryptoAlg}`;
    super({ message, code: 'RUNTIME_NO_PQC_SUPPORT' });
  }
}

export type SimpleWebAuthnErrorCode =
  | 'BAD_ARGUMENT'
  | 'RUNTIME_NO_PQC_SUPPORT'
  | 'CERTIFICATE_PATH_VERIFICATION_FAILED'
  | 'CHALLENGE_CONTEXT_INVALID'
  | 'CHALLENGE_CONTEXT_MISSING'
  | 'CHALLENGE_ALREADY_USED'
  | 'CHALLENGE_CANCELLED'
  | 'CHALLENGE_EXPIRED'
  | 'CHALLENGE_STALE_GENERATION'
  | 'CEREMONY_KIND_MISMATCH'
  | 'UNEXPECTED_TENANT'
  | 'UNEXPECTED_RP_ID'
  | 'UNEXPECTED_ORIGIN';
