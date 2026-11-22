import type { COSEALG } from '../helpers/cose.ts';
import { mapCoseAlgToWebCryptoKeyAlgName } from '../helpers/iso/isoCrypto/mapCoseAlgToWebCryptoKeyAlgName.ts';
import type { ChallengeAudit, VerificationStage } from '../types/audit.ts';

/**
 * Base error class that helps disambiguate SimpleWebAuthn library errors from other library errors
 */
export class SimpleWebAuthnError extends Error {
  code: SimpleWebAuthnErrorCode;
  /**
   * Structured information about where and why a ceremony-related verification was rejected.
   *
   * Legacy, stateless calls keep their historical error shape and leave this undefined.
   */
  audit?: ChallengeAudit;
  /** Alias for `audit`. */
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
 * Error raised when a challenge/ceremony cannot be accepted.
 *
 * Every instance carries an `audit` report that names the actual origin/RP ID/tenant, the tab
 * ceremony identity, the challenge handle and the exact rejection stage.
 */
export class ChallengeContextError extends SimpleWebAuthnError {
  override audit: ChallengeAudit;
  override details: ChallengeAudit;
  stage: VerificationStage;

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
    this.stage = audit.stage;
  }
}

/** Alias for consumers that think in terms of ceremony generations. */
export { ChallengeContextError as CeremonyVerificationError };

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
  | 'UNEXPECTED_SESSION'
  | 'UNEXPECTED_RP_ID'
  | 'UNEXPECTED_ORIGIN';
