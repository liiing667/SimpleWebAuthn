import type { COSEALG } from '../helpers/cose.ts';
import { mapCoseAlgToWebCryptoKeyAlgName } from '../helpers/iso/isoCrypto/mapCoseAlgToWebCryptoKeyAlgName.ts';

/**
 * Base error class that helps disambiguate SimpleWebAuthn library errors from other library errors
 */
export class SimpleWebAuthnError extends Error {
  code: SimpleWebAuthnErrorCode;

  constructor({ message, code, cause }: {
    message: string;
    code: SimpleWebAuthnErrorCode;
    cause?: Error;
  }) {
    super(message, { cause });
    this.name = 'SimpleWebAuthnError';
    this.code = code;
  }
}

export class PQCNotSupportedError extends SimpleWebAuthnError {
  constructor(alg: COSEALG) {
    const webCryptoAlg = mapCoseAlgToWebCryptoKeyAlgName(alg);
    const message = `This runtime's WebCrypto.subtle does not support use of ${webCryptoAlg}`;
    super({ message, code: 'RUNTIME_NO_PQC_SUPPORT' });
  }
}

/**
 * The stage at which an authentication/registration identity check was rejected.
 */
export type CredentialBindingStage =
  | 'client_data'
  | 'challenge_lookup'
  | 'challenge_integrity'
  | 'challenge_expiry'
  | 'challenge_replay'
  | 'challenge_cancellation'
  | 'credential_id'
  | 'user_handle'
  | 'user_id'
  | 'rp_id'
  | 'commit';

/**
 * Audit information attached to an identity/challenge binding failure.
 *
 * Raw user handles are intentionally omitted. `userHandleDigest` is a stable digest that lets an
 * operator correlate the rejected response with their own audit records without persisting the
 * identifying handle in an error log.
 */
export type CredentialBindingAudit = {
  stage: CredentialBindingStage;
  reason: string;
  credentialID?: string;
  credentialOwnerID?: string;
  expectedUserID?: string;
  userHandleDigest?: string;
  expectedUserHandleDigest?: string;
  challengeID?: string;
  generation?: number;
  currentGeneration?: number;
  timestamp: string;
};

/**
 * Error raised when a WebAuthn response cannot be bound to the identity frozen into its
 * challenge, or when that challenge has already been consumed.
 */
export class CredentialBindingError extends SimpleWebAuthnError {
  audit: CredentialBindingAudit;
  stage: CredentialBindingStage;

  constructor(opts: {
    message: string;
    code: SimpleWebAuthnErrorCode;
    audit: CredentialBindingAudit;
    cause?: Error;
  }) {
    const { message, code, audit, cause } = opts;
    super({ message, code, cause });
    this.name = 'CredentialBindingError';
    this.audit = audit;
    this.stage = audit.stage;
  }
}

export type SimpleWebAuthnErrorCode =
  | 'BAD_ARGUMENT'
  | 'RUNTIME_NO_PQC_SUPPORT'
  | 'CERTIFICATE_PATH_VERIFICATION_FAILED'
  | 'INVALID_CLIENT_DATA_JSON'
  | 'AUTHENTICATION_CHALLENGE_ALREADY_USED'
  | 'AUTHENTICATION_CHALLENGE_EXPIRED'
  | 'AUTHENTICATION_CHALLENGE_CANCELLED'
  | 'AUTHENTICATION_CHALLENGE_STALE'
  | 'REGISTRATION_CHALLENGE_ALREADY_USED'
  | 'REGISTRATION_CHALLENGE_EXPIRED'
  | 'UNEXPECTED_CREDENTIAL_ID'
  | 'UNEXPECTED_USER_HANDLE'
  | 'UNEXPECTED_USER_ID'
  | 'UNVERIFIED_USER_HANDLE'
  | 'UNEXPECTED_RP_ID'
  | 'UNEXPECTED_ORIGIN';
