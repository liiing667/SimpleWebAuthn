/**
 * The WebAuthn ceremony that produced a challenge/response pair.
 */
export type WebAuthnCeremony = 'registration' | 'authentication';

/**
 * Stage at which a ceremony verification was rejected.
 *
 * These stages are deliberately more granular than the top-level error codes so an RP's audit
 * log can distinguish, for example, a replayed challenge from one that was cancelled when a
 * newer ceremony superseded it.
 */
export type VerificationStage =
  | 'challenge_lookup'
  | 'challenge_integrity'
  | 'challenge_expiry'
  | 'challenge_replay'
  | 'challenge_cancellation'
  | 'challenge_generation'
  | 'challenge'
  | 'ceremony'
  | 'origin'
  | 'rp_id'
  | 'tenant'
  | 'session'
  | 'commit'
  | 'client_data'
  | 'credential_id'
  | 'user_handle'
  | 'signature';

/**
 * Structured information attached to ceremony-related verification errors.
 *
 * The report deliberately contains a digest/handle for the challenge and ceremony rather than
 * the raw challenge, so it is safe to write to an application audit log.
 */
export type ChallengeAudit = {
  /** Ceremony that rejected the response. */
  ceremony: WebAuthnCeremony;
  /** Verification stage that rejected the response. */
  stage: VerificationStage;
  /** Source location of the check, in `path/file.ts:function` form. */
  location: string;
  /** Human-readable reason for the rejection. */
  reason: string;
  /** Origin reported by the client in `clientDataJSON`. */
  actualOrigin?: string;
  /** Origin(s) frozen into the challenge when it was issued. */
  expectedOrigins: string[];
  /** Origin(s) expected by the caller for the current request. */
  callerExpectedOrigins?: string[];
  /** RP ID matched from the response's authenticator data. */
  actualRPID?: string;
  /** RP ID frozen into the challenge when it was issued. */
  expectedRPID?: string;
  /** RP ID(s) expected by the caller for the current request. */
  callerExpectedRPIDs?: string[];
  /** Tenant of the session that attempted to consume the response. */
  tenant?: string;
  /** Tenant frozen into the challenge. */
  challengeTenant?: string;
  /** Digest/handle of the challenge; never the raw challenge. */
  challengeID?: string;
  /** Identifier of the ceremony (tab/flow) that issued the challenge. */
  ceremonyID?: string;
  /** Browser/tab identity reported by the client, when available. */
  browserCeremonyID?: string;
  /** Tab-oriented identity: the browser tab ID when present, otherwise `ceremonyID`. */
  tabID?: string;
  /** Generation of the ceremony that issued the challenge. */
  ceremonyGeneration?: number;
  /** Process generation of the challenge ledger. */
  generation?: number;
  /** Alias for `generation`, kept for authentication-session compatibility. */
  challengeGeneration?: number;
  /** Current process generation when the response was presented. */
  currentGeneration?: number;
  /** Session/login identity that attempted to consume the challenge. */
  sessionKey?: string;
  /** Login-session identity frozen into the challenge. */
  challengeSessionKey?: string;
  /** When the rejection happened. */
  timestamp: string;
};

/**
 * Identity an RP should use when creating its final login session after a successful
 * authentication. Every field comes from the same consumed challenge record.
 */
export type VerifiedSessionIdentity = {
  origin: string;
  rpID: string;
  tenant?: string;
  sessionKey?: string;
  challengeID: string;
  ceremonyID?: string;
  browserCeremonyID?: string;
  ceremonyGeneration?: number;
  /** Process generation of the consumed challenge. */
  generation?: number;
  /** Alias for `generation`, kept for authentication-session compatibility. */
  challengeGeneration?: number;
};
