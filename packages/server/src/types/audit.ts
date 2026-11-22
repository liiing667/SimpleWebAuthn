/**
 * The WebAuthn ceremony being verified.
 */
export type WebAuthnCeremony = 'registration' | 'authentication';

/**
 * A stage at which a verification can be accepted or rejected.
 *
 * Stages are intentionally more granular than the top-level error codes. They make it possible
 * for an RP's audit log to tell the difference between, for example, a response that was signed
 * for a different tenant and one that used a challenge that had already been consumed.
 */
export type VerificationStage =
  | 'challenge_generation'
  | 'challenge_lookup'
  | 'challenge_integrity'
  | 'challenge_expiry'
  | 'challenge_replay'
  | 'challenge_cancellation'
  | 'challenge'
  | 'ceremony'
  | 'top_origin'
  | 'origin'
  | 'rp_id'
  | 'tenant'
  | 'user_verification'
  | 'counter'
  | 'signature'
  | 'commit';

/**
 * Purpose-built audit data attached to verification errors.
 *
 * The values in this report come from the response that was actually presented (for example
 * `actualOrigin` and `actualRPID`) as well as the context that was frozen when the challenge was
 * generated. Callers should be able to write this object to their audit log without having to
 * infer which tenant/session attempted to consume the response.
 */
export type ChallengeAudit = {
  /** The ceremony that rejected the response */
  ceremony: WebAuthnCeremony;
  /** The verification stage that rejected the response */
  stage: VerificationStage;
  /** Source location of the check, in `path/file.ts:function` form */
  location: string;
  /** Human-readable reason for the rejection */
  reason: string;
  /** Origin reported by the client in `clientDataJSON` */
  actualOrigin?: string;
  /** Origin(s) bound to the challenge when it was generated */
  expectedOrigins: string[];
  /** Origin(s) expected by the caller for the current request */
  callerExpectedOrigins?: string[];
  /** RP ID matched from the response's authenticator data */
  actualRPID?: string;
  /** RP ID bound to the challenge when it was generated */
  expectedRPID?: string;
  /** RP ID(s) expected by the caller for the current request */
  callerExpectedRPIDs?: string[];
  /** Tenant of the session that attempted to consume the response */
  tenant?: string;
  /** Tenant bound to the challenge when it was generated */
  challengeTenant?: string;
  /** Digest/handle of the challenge. The raw challenge is deliberately not included. */
  challengeID?: string;
  /** Generation of the challenge */
  generation?: number;
  /** Generation of the service at the time the response was consumed */
  currentGeneration?: number;
  /** When the rejection happened */
  timestamp: string;
};

/**
 * The object a caller should use when creating the RP's final session after a successful
 * verification. Every field comes from the same verified challenge generation.
 */
export type VerifiedSessionIdentity = {
  /** Origin reported by the response that was verified */
  origin: string;
  /** RP ID reported by the response that was verified */
  rpID: string;
  /** Tenant frozen into the challenge, if any */
  tenant?: string;
  /** Handle of the consumed challenge */
  challengeID: string;
  /** Generation of the consumed challenge */
  generation?: number;
};
