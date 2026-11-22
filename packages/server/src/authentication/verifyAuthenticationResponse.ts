import type {
  AuthenticationResponseJSON,
  Base64URLString,
  CredentialDeviceType,
  UserVerificationRequirement,
  WebAuthnCredential,
} from '../types/index.ts';
import { decodeClientDataJSON } from '../helpers/decodeClientDataJSON.ts';
import { toHash } from '../helpers/toHash.ts';
import { verifySignature } from '../helpers/verifySignature.ts';
import { parseAuthenticatorData } from '../helpers/parseAuthenticatorData.ts';
import { parseBackupFlags } from '../helpers/parseBackupFlags.ts';
import type { AuthenticationExtensionsAuthenticatorOutputs } from '../helpers/decodeAuthenticatorExtensions.ts';
import { matchExpectedRPID } from '../helpers/matchExpectedRPID.ts';
import { isoBase64URL, isoUint8Array } from '../helpers/iso/index.ts';
import { decodeCredentialPublicKey } from '../helpers/decodeCredentialPublicKey.ts';
import { COSEKEYS, isPQCCOSEAlg } from '../helpers/cose.ts';
import { SettingsService } from '../services/settingsService.ts';
import {
  ChallengeContextError,
  PQCNotSupportedError,
} from '../errors/index.ts';
import { matchExpectedOrigin } from '../helpers/matchExpectedOrigin.ts';
import {
  ChallengeContextService,
  type ChallengeContextRecord,
  type ChallengeConsumption,
} from '../services/challengeContextService.ts';
import {
  assertChallengeResponseContext,
  challengeConsumptionError,
} from '../helpers/ceremonyVerification.ts';
import type {
  ChallengeAudit,
  VerifiedSessionIdentity,
  VerificationStage,
} from '../types/audit.ts';

/**
 * Configurable options when calling `verifyAuthenticationResponse()`
 */
export type VerifyAuthenticationResponseOpts = Parameters<typeof verifyAuthenticationResponse>[0];

/**
 * Verify that the user has legitimately completed the authentication process
 *
 * **Options:**
 *
 * @param response - Response returned by **@simplewebauthn/browser**'s `startAuthentication()`
 * @param expectedChallenge - The base64url-encoded `options.challenge` returned by `generateAuthenticationOptions()`
 * @param expectedOrigin - Website URL (or array of URLs) that the registration should have occurred on
 * @param expectedRPID - RP ID (or array of IDs) that was specified in the registration options
 * @param credential - An internal {@link WebAuthnCredential} corresponding to `id` in the authentication response
 * @param expectedCeremonyID **(Optional)** - Browser/tab ceremony identity that must match the
 * challenge record. Can be a predicate for RPs that store the identity externally.
 * @param expectedCeremonyGeneration **(Optional)** - Ceremony generation that must match the
 * challenge record.
 * @param sessionKey **(Optional)** - Login-session identity consuming this response. Required when
 * the challenge was generated with a session key.
 * @param expectedTenant **(Optional)** - Tenant/account identity consuming this response.
 * @param requireCeremony **(Optional)** - Reject a response whose challenge was not issued by this
 * process. Defaults to `false` for legacy stateless callers.
 * @param expectedType **(Optional)** - The response type expected ('webauthn.get')
 * @param requireUserVerification **(Optional)** - Enforce user verification by the authenticator (via PIN, fingerprint, etc...) Defaults to `true`
 * @param advancedFIDOConfig **(Optional)** - Options for satisfying more stringent FIDO RP feature requirements
 * @param advancedFIDOConfig.userVerification **(Optional)** - Enable alternative rules for evaluating the User Presence and User Verified flags in authenticator data: UV (and UP) flags are optional unless this value is `"required"`
 */
export async function verifyAuthenticationResponse(
  options: {
    response: AuthenticationResponseJSON;
    expectedChallenge: string | ((challenge: string) => boolean | Promise<boolean>);
    expectedOrigin: string | string[];
    expectedRPID: string | string[];
    credential: WebAuthnCredential;
    expectedCeremonyID?: string | ((ceremonyID: string | undefined) => boolean | Promise<boolean>);
    /** Aggregated ceremony expectation alias. */
    ceremony?: {
      id?: string;
      generation?: number;
      challengeID?: string;
      sessionKey?: string;
    };
    expectedCeremonyGeneration?: number;
    /** Alias for `expectedCeremonyGeneration`. */
    expectedGeneration?: number;
    sessionKey?: string;
    /** Alias for `sessionKey`. */
    sessionID?: string;
    /** Alias for `sessionKey`. */
    loginSessionID?: string;
    expectedSessionKey?: string;
    expectedTenant?: string;
    /** Alias for `expectedTenant`. */
    tenant?: string;
    /** Alias for `expectedTenant`. */
    tenantId?: string;
    requireCeremony?: boolean;
    /** Alias for `requireCeremony`. */
    requireChallengeContext?: boolean;
    expectedType?: string | string[];
    expectedTopOrigin?: string | string[];
    requireUserVerification?: boolean;
    advancedFIDOConfig?: {
      userVerification?: UserVerificationRequirement;
    };
  },
): Promise<VerifiedAuthenticationResponse> {
  const {
    response,
    expectedChallenge,
    expectedOrigin,
    expectedRPID,
    expectedType,
    expectedTopOrigin,
    credential,
    expectedCeremonyID,
    ceremony: expectedCeremony,
    expectedCeremonyGeneration,
    expectedGeneration,
    sessionKey,
    sessionID,
    loginSessionID,
    expectedSessionKey,
    expectedTenant,
    tenant,
    tenantId,
    requireCeremony,
    requireChallengeContext,
    requireUserVerification = true,
    advancedFIDOConfig,
  } = options;
  const expectedCeremonyGenerationValue = expectedCeremonyGeneration ??
    expectedGeneration ?? expectedCeremony?.generation;
  const expectedCeremonyIDValue = typeof expectedCeremonyID === 'string'
    ? expectedCeremonyID
    : (expectedCeremonyID === undefined ? expectedCeremony?.id : undefined);
  const sessionKeyValue = sessionKey ?? sessionID ?? loginSessionID ??
    expectedSessionKey ?? expectedCeremony?.sessionKey;
  const expectedChallengeIDValue = expectedCeremony?.challengeID;
  const sessionTenant = expectedTenant ?? tenant ?? tenantId;
  const ceremonyRequired = requireCeremony ?? requireChallengeContext ?? false;
  const callerExpectedOrigins = Array.isArray(options.expectedOrigin)
    ? [...options.expectedOrigin]
    : [options.expectedOrigin];
  const callerExpectedRPIDs = Array.isArray(options.expectedRPID)
    ? [...options.expectedRPID]
    : [options.expectedRPID];
  const ceremonyExpected = ceremonyRequired ||
    expectedCeremonyIDValue !== undefined ||
    expectedChallengeIDValue !== undefined ||
    typeof expectedCeremonyID === 'function' ||
    expectedCeremonyGenerationValue !== undefined;
  const { id, rawId, type: credentialType, response: assertionResponse } = response;

  // Ensure credential specified an ID
  if (!id) {
    throw new Error('Missing credential ID');
  }

  // Ensure ID is base64url-encoded
  if (id !== rawId) {
    throw new Error('Credential ID was not base64url-encoded');
  }

  // Make sure credential type is public-key
  if (credentialType !== 'public-key') {
    throw new Error(
      `Unexpected credential type ${credentialType}, expected "public-key"`,
    );
  }

  if (!response) {
    throw new Error('Credential missing response');
  }

  if (typeof assertionResponse?.clientDataJSON !== 'string') {
    throw new Error('Credential response clientDataJSON was not a string');
  }

  const clientDataJSON = decodeClientDataJSON(assertionResponse.clientDataJSON);

  const { type, origin, challenge, tokenBinding, crossOrigin, topOrigin } = clientDataJSON;

  const responseCeremonyID = response.ceremonyID ?? response.ceremony?.id;
  const responseCeremonyGeneration = response.ceremonyGeneration ??
    response.serverCeremonyGeneration ??
    response.ceremony?.generation;

  /**
   * Consume the challenge synchronously, before the caller's challenge verifier or any async
   * signature work. If this challenge was issued with a ceremony/session generation, the
   * pending -> used transition is the single-use fence that prevents a second tab, retry or
   * process from consuming it again.
   */
  const challengeConsumption: ChallengeConsumption = ChallengeContextService.consumeChallenge({
    challenge,
    ceremony: 'authentication',
    sessionKey: sessionKeyValue,
    ceremonyID: responseCeremonyID ??
      expectedCeremonyIDValue,
    ceremonyGeneration: responseCeremonyGeneration ?? expectedCeremonyGenerationValue,
  });
  const challengeRecord: ChallengeContextRecord | undefined = challengeConsumption.record;
  const exposeSession = challengeRecord !== undefined;
  const challengeAuditContext: Partial<ChallengeAudit> | undefined = challengeRecord
    ? {
      ceremony: 'authentication',
      stage: 'challenge',
      reason: 'challenge context check',
      actualOrigin: origin,
      expectedOrigins: challengeRecord.context.origins,
      callerExpectedOrigins,
      expectedRPID: challengeRecord.context.rpID || undefined,
      callerExpectedRPIDs,
      challengeID: challengeRecord.challengeID,
      ceremonyID: challengeRecord.ceremonyID,
      browserCeremonyID: response.browserCeremonyID,
      ceremonyGeneration: challengeRecord.ceremonyGeneration,
      generation: challengeRecord.generation,
      challengeGeneration: challengeRecord.generation,
      currentGeneration: ChallengeContextService.generation,
      tenant: sessionTenant,
      challengeTenant: challengeRecord.context.tenant,
      sessionKey: sessionKeyValue,
      challengeSessionKey: challengeRecord.sessionKey,
    }
    : undefined;

  if (!challengeConsumption.tracked && ceremonyExpected) {
    throw challengeConsumptionError({
      consumption: {
        ...challengeConsumption,
        tracked: true,
        status: 'missing' as const,
      },
      ceremony: 'authentication',
      actualOrigin: origin,
      tenant: sessionTenant,
      sessionKey: sessionKeyValue,
      browserCeremonyID: response.browserCeremonyID,
      callerExpectedOrigins,
      callerExpectedRPIDs,
    });
  }

  if (
    challengeConsumption.tracked &&
    challengeConsumption.status !== 'available'
  ) {
    throw challengeConsumptionError({
      consumption: challengeConsumption,
      ceremony: 'authentication',
      actualOrigin: origin,
      tenant: sessionTenant,
      sessionKey: sessionKeyValue,
      browserCeremonyID: response.browserCeremonyID,
      callerExpectedOrigins,
      callerExpectedRPIDs,
    });
  }

  if (
    challengeRecord !== undefined &&
    typeof expectedCeremonyID === 'function' &&
    !(await expectedCeremonyID(challengeRecord.ceremonyID))
  ) {
    const audit: ChallengeAudit = {
      ceremony: 'authentication',
      stage: 'ceremony',
      location:
        'packages/server/src/authentication/verifyAuthenticationResponse.ts:verifyAuthenticationResponse#ceremony',
      reason: 'Authentication response ceremony identity did not match the expected ceremony',
      actualOrigin: origin,
      expectedOrigins: challengeRecord.context.origins,
      callerExpectedOrigins,
      expectedRPID: challengeRecord.context.rpID || undefined,
      callerExpectedRPIDs,
      challengeID: challengeRecord.challengeID,
      ceremonyID: challengeRecord.ceremonyID,
      browserCeremonyID: response.browserCeremonyID,
      tabID: response.browserCeremonyID ?? challengeRecord.ceremonyID,
      ceremonyGeneration: challengeRecord.ceremonyGeneration,
      generation: challengeRecord.generation,
      currentGeneration: ChallengeContextService.generation,
      sessionKey: sessionKeyValue,
      timestamp: new Date().toISOString(),
    };
    throw new ChallengeContextError({
      message: audit.reason,
      code: 'CEREMONY_KIND_MISMATCH',
      audit,
    });
  }

  if (
    challengeRecord !== undefined &&
    expectedChallengeIDValue !== undefined &&
    challengeRecord.challengeID !== expectedChallengeIDValue
  ) {
    const reason =
      `Authentication challenge handle "${challengeRecord.challengeID}" did not match ` +
      `the expected handle "${expectedChallengeIDValue}"`;
    throw new ChallengeContextError({
      message: reason,
      code: 'CHALLENGE_STALE_GENERATION',
      audit: {
        ...(challengeAuditContext ?? {}),
        ceremony: 'authentication',
        stage: 'challenge_generation',
        location:
          'packages/server/src/authentication/verifyAuthenticationResponse.ts:verifyAuthenticationResponse#challengeGeneration',
        reason,
        actualOrigin: origin,
        expectedOrigins: challengeRecord.context.origins,
        callerExpectedOrigins,
        expectedRPID: challengeRecord.context.rpID || undefined,
        callerExpectedRPIDs,
        tenant: sessionTenant,
        challengeTenant: challengeRecord.context.tenant,
        challengeID: challengeRecord.challengeID,
        ceremonyID: challengeRecord.ceremonyID,
        browserCeremonyID: response.browserCeremonyID,
        tabID: response.browserCeremonyID ?? challengeRecord.ceremonyID,
        ceremonyGeneration: challengeRecord.ceremonyGeneration,
        generation: challengeRecord.generation,
        challengeGeneration: challengeRecord.generation,
        currentGeneration: ChallengeContextService.generation,
        sessionKey: sessionKeyValue,
        timestamp: new Date().toISOString(),
      },
    });
  }

  if (
    challengeRecord !== undefined &&
    expectedCeremonyGenerationValue !== undefined &&
    challengeRecord.ceremonyGeneration !== expectedCeremonyGenerationValue &&
    challengeRecord.generation !== expectedCeremonyGenerationValue
  ) {
    const audit: ChallengeAudit = {
      ceremony: 'authentication',
      stage: 'challenge_generation',
      location:
        'packages/server/src/authentication/verifyAuthenticationResponse.ts:verifyAuthenticationResponse#generation',
      reason:
        `Authentication challenge generation ${challengeRecord.ceremonyGeneration} ` +
        `did not match expected generation ${expectedCeremonyGenerationValue}`,
      actualOrigin: origin,
      expectedOrigins: challengeRecord.context.origins,
      callerExpectedOrigins,
      expectedRPID: challengeRecord.context.rpID || undefined,
      callerExpectedRPIDs,
      challengeID: challengeRecord.challengeID,
      ceremonyID: challengeRecord.ceremonyID,
      browserCeremonyID: response.browserCeremonyID,
      tabID: response.browserCeremonyID ?? challengeRecord.ceremonyID,
      ceremonyGeneration: challengeRecord.ceremonyGeneration,
      generation: challengeRecord.generation,
      currentGeneration: ChallengeContextService.generation,
      sessionKey: sessionKeyValue,
      timestamp: new Date().toISOString(),
    };
    throw new ChallengeContextError({
      message: audit.reason,
      code: 'CHALLENGE_STALE_GENERATION',
      audit,
    });
  }

  // Make sure we're handling an authentication
  if (Array.isArray(expectedType)) {
    if (!expectedType.includes(type)) {
      const joinedExpectedType = expectedType.join(', ');
      throw new Error(
        `Unexpected authentication response type "${type}", expected one of: ${joinedExpectedType}`,
      );
    }
  } else if (expectedType) {
    if (type !== expectedType) {
      throw new Error(
        `Unexpected authentication response type "${type}", expected "${expectedType}"`,
      );
    }
  } else if (type !== 'webauthn.get') {
    throw new Error(`Unexpected authentication response type: ${type}`);
  }

  // Ensure the device provided the challenge we gave it
  if (typeof expectedChallenge === 'function') {
    if (!(await expectedChallenge(challenge))) {
      throw new Error(
        `Custom challenge verifier returned false for registration response challenge "${challenge}"`,
      );
    }
  } else if (challenge !== expectedChallenge) {
    throw new Error(
      `Unexpected authentication response challenge "${challenge}", expected "${expectedChallenge}"`,
    );
  }

  // Check that the authentication response is within an expected iframe
  if (crossOrigin) {
    /**
     * TODO: Since Safari doesn't support `topOrigin` as of May 2026, only check this when
     * `topOrigin` is available for now.
     */
    if (topOrigin) {
      if (!expectedTopOrigin) {
        /**
         * If `expectedTopOrigin` is not set, this should be considered an unexpected cross-origin
         * request. Reject the response while helping the RP understand how they need to update this
         * method call if they want to support verification of such WebAuthn authentication requests.
         */
        throw new Error(
          `Detected cross-origin authentication response from top origin of "${topOrigin}", but a value for \`expectedTopOrigin\` was not specified when calling \`verifyAuthenticationResponse()\``,
        );
      }

      if (Array.isArray(expectedTopOrigin)) {
        if (!expectedTopOrigin.includes(topOrigin)) {
          const joinedExpectedTopOrigin = expectedTopOrigin.join(', ');
          throw new Error(
            `Unexpected cross-origin authentication response top origin of "${topOrigin}", expected one of: ${joinedExpectedTopOrigin}`,
          );
        }
      } else {
        if (topOrigin !== expectedTopOrigin) {
          throw new Error(
            `Unexpected cross-origin authentication response top origin of "${topOrigin}", expected: ${expectedTopOrigin}`,
          );
        }
      }
    }
  } else {
    if (topOrigin) {
      /**
       * If `topOrigin` is set despite `crossOrigin` being false, this is an unexpected request.
       *
       * See https://w3c.github.io/webauthn/#dom-collectedclientdata-toporigin.
       */
      throw new Error(
        `Unexpected top origin of "${topOrigin}" within a non-cross-origin authentication response. This error should be reported to the browser vendor as a WebAuthn specification violation with a link to https://w3c.github.io/webauthn/#dom-collectedclientdata-toporigin`,
      );
    }
  }

  // Check that the origin is our site
  matchExpectedOrigin(origin, expectedOrigin, challengeAuditContext);

  if (!isoBase64URL.isBase64URL(assertionResponse.authenticatorData)) {
    throw new Error(
      'Credential response authenticatorData was not a base64url string',
    );
  }

  if (!isoBase64URL.isBase64URL(assertionResponse.signature)) {
    throw new Error('Credential response signature was not a base64url string');
  }

  if (
    assertionResponse.userHandle &&
    typeof assertionResponse.userHandle !== 'string'
  ) {
    throw new Error('Credential response userHandle was not a string');
  }

  if (tokenBinding) {
    if (typeof tokenBinding !== 'object') {
      throw new Error('ClientDataJSON tokenBinding was not an object');
    }

    if (
      ['present', 'supported', 'notSupported'].indexOf(tokenBinding.status) < 0
    ) {
      throw new Error(`Unexpected tokenBinding status ${tokenBinding.status}`);
    }
  }

  const authDataBuffer = isoBase64URL.toBuffer(
    assertionResponse.authenticatorData,
  );
  const parsedAuthData = parseAuthenticatorData(authDataBuffer);
  const { rpIdHash, flags, counter, extensionsData } = parsedAuthData;

  // Make sure the response's RP ID is ours
  let expectedRPIDs: string[] = [];
  if (typeof expectedRPID === 'string') {
    expectedRPIDs = [expectedRPID];
  } else {
    expectedRPIDs = expectedRPID;
  }

  const matchedRPID = await matchExpectedRPID(
    rpIdHash,
    expectedRPIDs,
    challengeAuditContext,
  );

  if (challengeRecord) {
    assertChallengeResponseContext({
      record: challengeRecord,
      ceremony: 'authentication',
      actualOrigin: origin,
      actualRPID: matchedRPID,
      sessionTenant,
      sessionKey: sessionKeyValue,
      browserCeremonyID: response.browserCeremonyID,
      callerExpectedOrigins,
      callerExpectedRPIDs,
    });
    ChallengeContextService.recordConsumption(challenge, {
      origin,
      rpID: matchedRPID,
      tenant: sessionTenant,
      sessionKey: sessionKeyValue,
    });
  }

  if (advancedFIDOConfig !== undefined) {
    const { userVerification: fidoUserVerification } = advancedFIDOConfig;

    /**
     * Use FIDO Conformance-defined rules for verifying UP and UV flags
     */
    if (fidoUserVerification === 'required') {
      // Require `flags.uv` be true (implies `flags.up` is true)
      if (!flags.uv) {
        throw new Error(
          'User verification required, but user could not be verified',
        );
      }
    } else if (
      fidoUserVerification === 'preferred' ||
      fidoUserVerification === 'discouraged'
    ) {
      // Ignore `flags.uv`
    }
  } else {
    /**
     * Use WebAuthn spec-defined rules for verifying UP and UV flags
     */
    // WebAuthn only requires the user presence flag be true
    if (!flags.up) {
      throw new Error('User not present during authentication');
    }

    // Enforce user verification if required
    if (requireUserVerification && !flags.uv) {
      throw new Error(
        'User verification required, but user could not be verified',
      );
    }
  }

  const clientDataHash = await toHash(
    isoBase64URL.toBuffer(assertionResponse.clientDataJSON),
  );
  const signatureBase = isoUint8Array.concat([authDataBuffer, clientDataHash]);

  const signature = isoBase64URL.toBuffer(assertionResponse.signature);

  if (
    (counter > 0 || credential.counter > 0) &&
    counter <= credential.counter
  ) {
    // Error out when the counter in the DB is greater than or equal to the counter in the
    // dataStruct. It's related to how the authenticator maintains the number of times its been
    // used for this client. If this happens, then someone's somehow increased the counter
    // on the device without going through this site
    throw new Error(
      `Response counter value ${counter} was lower than expected ${credential.counter}`,
    );
  }

  const decodedPublicKey = decodeCredentialPublicKey(credential.publicKey);
  const pubKeyAlg = decodedPublicKey.get(COSEKEYS.alg);

  if (typeof pubKeyAlg !== 'number') {
    throw new Error('Credential public key was missing numeric alg');
  }

  if (isPQCCOSEAlg(pubKeyAlg) && !SettingsService.runtimeSupportsPQC()) {
    throw new PQCNotSupportedError(pubKeyAlg);
  }

  const { credentialDeviceType, credentialBackedUp } = parseBackupFlags(flags);

  const verified = await verifySignature({
    signature,
    data: signatureBase,
    credentialPublicKey: credential.publicKey,
  });

  /**
   * A reset/restart, cancellation or newer ceremony that happens while signature verification
   * is in flight must not publish a session from an older generation. This is the last check
   * before the success value is returned.
   */
  if (challengeRecord) {
    const currentRecord = ChallengeContextService.getChallenge(challenge);
    if (
      ChallengeContextService.generation !== challengeRecord.generation ||
      !currentRecord ||
      currentRecord !== challengeRecord ||
      currentRecord.status !== 'used'
    ) {
      const stage: VerificationStage = 'commit';
      const reason =
        'Authentication challenge generation changed before the login session could be committed';
      throw new ChallengeContextError({
        message: reason,
        code: 'CHALLENGE_STALE_GENERATION',
        audit: {
          ceremony: 'authentication',
          stage,
          location:
            'packages/server/src/authentication/verifyAuthenticationResponse.ts:verifyAuthenticationResponse#commit',
          reason,
          actualOrigin: origin,
          expectedOrigins: challengeRecord.context.origins,
          callerExpectedOrigins,
          actualRPID: matchedRPID,
          expectedRPID: challengeRecord.context.rpID || undefined,
          callerExpectedRPIDs,
          tenant: sessionTenant,
          challengeTenant: challengeRecord.context.tenant,
          challengeID: challengeRecord.challengeID,
          ceremonyID: challengeRecord.ceremonyID,
          browserCeremonyID: response.browserCeremonyID,
          tabID: response.browserCeremonyID ?? challengeRecord.ceremonyID,
          ceremonyGeneration: challengeRecord.ceremonyGeneration,
          generation: challengeRecord.generation,
          challengeGeneration: challengeRecord.generation,
          currentGeneration: ChallengeContextService.generation,
          sessionKey: sessionKeyValue,
          challengeSessionKey: challengeRecord.sessionKey,
          timestamp: new Date().toISOString(),
        },
      });
    }
  }

  let session: VerifiedSessionIdentity | undefined;
  if (verified && challengeRecord) {
    ChallengeContextService.recordConsumption(challenge, {
      credentialID: credential.id,
      userHandle: assertionResponse.userHandle,
    });
    challengeRecord.committedAt = Date.now();
    session = {
      origin: clientDataJSON.origin,
      rpID: matchedRPID,
      tenant: challengeRecord.context.tenant,
      sessionKey: challengeRecord.sessionKey,
      challengeID: challengeRecord.challengeID,
      ceremonyID: challengeRecord.ceremonyID,
      browserCeremonyID: response.browserCeremonyID,
      ceremonyGeneration: challengeRecord.ceremonyGeneration,
      generation: challengeRecord.generation,
      challengeGeneration: challengeRecord.generation,
    };
  }

  const toReturn: VerifiedAuthenticationResponse = {
    verified,
    authenticationInfo: {
      newCounter: counter,
      credentialID: credential.id,
      userVerified: flags.uv,
      credentialDeviceType,
      credentialBackedUp,
      authenticatorExtensionResults: extensionsData,
      origin: clientDataJSON.origin,
      rpID: matchedRPID,
      ...(challengeRecord && exposeSession
        ? {
          challengeID: challengeRecord.challengeID,
          ceremonyID: challengeRecord.ceremonyID,
          browserCeremonyID: response.browserCeremonyID,
          ceremonyGeneration: challengeRecord.ceremonyGeneration,
          generation: challengeRecord.generation,
          challengeGeneration: challengeRecord.generation,
          tenant: challengeRecord.context.tenant,
          sessionKey: challengeRecord.sessionKey,
          session,
          sessionIdentity: session,
          challengeContext: session,
          finalSession: session,
        }
        : {}),
    },
  };

  return toReturn;
}

/**
 * Result of authentication verification
 *
 * @param verified If the authentication response could be verified
 * @param authenticationInfo.credentialID The ID of the authenticator used during authentication.
 * Should be used to identify which DB authenticator entry needs its `counter` updated to the value
 * below
 * @param authenticationInfo.newCounter The number of times the authenticator identified above
 * reported it has been used. **Should be kept in a DB for later reference to help prevent replay
 * attacks!**
 * @param authenticationInfo.credentialDeviceType Whether this is a single-device or multi-device
 * credential. **Should be kept in a DB for later reference!**
 * @param authenticationInfo.credentialBackedUp Whether or not the multi-device credential has been
 * backed up. Always `false` for single-device credentials. **Should be kept in a DB for later
 * reference!**
 * @param authenticationInfo.origin The origin of the website that the authentication occurred on
 * @param authenticationInfo.rpID The RP ID that the authentication occurred on
 * @param authenticationInfo.session The ceremony/challenge/session identity to use when writing
 * the final login session. Only present when the challenge was tracked and the signature verified.
 * @param authenticationInfo?.authenticatorExtensionResults The authenticator extensions returned
 * by the browser
 */
export type VerifiedAuthenticationResponse = {
  verified: boolean;
  authenticationInfo: {
    credentialID: Base64URLString;
    newCounter: number;
    userVerified: boolean;
    credentialDeviceType: CredentialDeviceType;
    credentialBackedUp: boolean;
    origin: string;
    rpID: string;
    authenticatorExtensionResults?: AuthenticationExtensionsAuthenticatorOutputs;
    /** Tenant frozen into the challenge, when any. */
    tenant?: string;
    /** Login-session identity frozen into the challenge, when any. */
    sessionKey?: string;
    /** Digest/handle of the consumed challenge. */
    challengeID?: string;
    /** Browser/tab ceremony identity that issued the challenge. */
    ceremonyID?: string;
    /** Browser/tab identity reported by the client. */
    browserCeremonyID?: string;
    /** Ceremony generation that issued the challenge. */
    ceremonyGeneration?: number;
    /** Process generation of the consumed challenge. */
    generation?: number;
    /** Alias for `generation`. */
    challengeGeneration?: number;
    /** Verified identity an RP should use when creating the final login session. */
    session?: VerifiedSessionIdentity;
    /** Alias for `session`. */
    sessionIdentity?: VerifiedSessionIdentity;
    /** Alias for `session`. */
    challengeContext?: VerifiedSessionIdentity;
    /** Alias for `session`. */
    finalSession?: VerifiedSessionIdentity;
  };
};

/** Identity an RP should use when creating a login session after authentication. */
export type VerifiedAuthenticationSessionIdentity = VerifiedSessionIdentity;
/** Alias for {@link VerifiedAuthenticationSessionIdentity}. */
export type AuthenticationSessionIdentity = VerifiedAuthenticationSessionIdentity;
