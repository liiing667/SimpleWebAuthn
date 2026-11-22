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
import { PQCNotSupportedError } from '../errors/index.ts';
import { matchExpectedOrigin } from '../helpers/matchExpectedOrigin.ts';
import {
  ChallengeContextService,
  type ChallengeContextRecord,
  type ChallengeConsumption,
} from '../services/challengeContextService.ts';
import type {
  ChallengeAudit,
  VerificationStage,
  VerifiedSessionIdentity,
} from '../types/audit.ts';
import {
  asArray,
  AUTHENTICATION_SOURCE,
  assertChallengeGenerationCurrent,
  assertChallengeResponseContext,
  challengeConsumptionError,
  rethrowWithChallengeAudit,
} from '../helpers/challengeVerification.ts';

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
 * @param expectedType **(Optional)** - The response type expected ('webauthn.get')
 * @param requireUserVerification **(Optional)** - Enforce user verification by the authenticator (via PIN, fingerprint, etc...) Defaults to `true`
 * @param expectedTenant **(Optional)** - Tenant/account/session identity that is consuming this
 * response. Required when the challenge was generated with a `tenant` in its `challengeContext`.
 * @param requireChallengeContext **(Optional)** - When `true`, reject caller-managed challenges
 * that were not issued with a challenge context. Defaults to `false` for backwards compatibility.
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
    expectedType?: string | string[];
    expectedTopOrigin?: string | string[];
    requireUserVerification?: boolean;
    expectedTenant?: string;
    /** Alias for `expectedTenant` */
    tenant?: string;
    /** Alias for `expectedTenant` */
    tenantId?: string;
    /** Alias for `expectedTenant` */
    sessionTenant?: string;
    requireChallengeContext?: boolean;
    advancedFIDOConfig?: {
      userVerification?: UserVerificationRequirement;
    };
  },
): Promise<VerifiedAuthenticationResponse> {
  const {
    response: originalResponse,
    expectedChallenge,
    expectedOrigin: originalExpectedOrigin,
    expectedRPID: originalExpectedRPID,
    expectedType: originalExpectedType,
    expectedTopOrigin: originalExpectedTopOrigin,
    credential: originalCredential,
    requireUserVerification = true,
    expectedTenant,
    tenant,
    tenantId,
    sessionTenant,
    requireChallengeContext = false,
    advancedFIDOConfig,
  } = options;

  const sessionTenantID = expectedTenant ?? tenant ?? tenantId ?? sessionTenant;

  /**
   * Freeze the response and caller expectations before any async work. Verification can span
   * multiple awaits, and a caller that reuses or mutates the response object concurrently must not
   * be able to swap the challenge/origin/RP ID that is eventually committed to a session.
   */
  const response: AuthenticationResponseJSON = {
    ...originalResponse,
    response: {
      ...originalResponse.response,
      authenticatorData: originalResponse.response.authenticatorData,
      clientDataJSON: originalResponse.response.clientDataJSON,
      signature: originalResponse.response.signature,
      userHandle: originalResponse.response.userHandle,
    },
  };
  const expectedOrigin = Array.isArray(originalExpectedOrigin)
    ? [...originalExpectedOrigin]
    : originalExpectedOrigin;
  const expectedRPID = Array.isArray(originalExpectedRPID)
    ? [...originalExpectedRPID]
    : originalExpectedRPID;
  const expectedType = Array.isArray(originalExpectedType)
    ? [...originalExpectedType]
    : originalExpectedType;
  const expectedTopOrigin = Array.isArray(originalExpectedTopOrigin)
    ? [...originalExpectedTopOrigin]
    : originalExpectedTopOrigin;
  const credential: WebAuthnCredential = {
    ...originalCredential,
    publicKey: new Uint8Array(originalCredential.publicKey),
  };

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

  let currentStage: VerificationStage = 'challenge';
  let challengeAuditContext: Partial<ChallengeAudit> | undefined;
  let challengeConsumption: ChallengeConsumption | undefined;
  let challengeRecord: ChallengeContextRecord | undefined;
  let matchedRPID: string | undefined;

  try {
    currentStage = 'challenge';
    /**
     * Consume the challenge synchronously, before the caller's challenge verifier or any async
     * signature work. If this challenge was issued with a context, the pending -> used
     * transition is the single-use fence that prevents a second tenant from consuming it.
     */
    challengeConsumption = ChallengeContextService.consumeChallenge({
      challenge,
      ceremony: 'authentication',
      requireContext: requireChallengeContext,
    });
    challengeRecord = challengeConsumption.record;

    if (challengeConsumption.tracked) {
      challengeAuditContext = {
        ceremony: 'authentication',
        stage: currentStage,
        location: `${AUTHENTICATION_SOURCE}#challenge`,
        reason: 'challenge context check',
        actualOrigin: origin,
        expectedOrigins: challengeRecord?.context.origins ?? [],
        callerExpectedOrigins: asArray(expectedOrigin),
        expectedRPID: challengeRecord?.context.rpID,
        callerExpectedRPIDs: asArray(expectedRPID),
        tenant: sessionTenantID,
        challengeTenant: challengeRecord?.context.tenant,
        challengeID: challengeConsumption.challengeID,
        generation: challengeConsumption.generation,
        currentGeneration: ChallengeContextService.generation,
      };
    }

    if (challengeConsumption.tracked && challengeConsumption.status !== 'available') {
      throw challengeConsumptionError({
        consumption: challengeConsumption,
        ceremony: 'authentication',
        audit: challengeAuditContext,
      });
    }

    currentStage = 'ceremony';
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
      const originalChallenge = challengeRecord?.envelope?.c;
      const recordedChallenge = challengeRecord?.challenge;
      let challengeAccepted = await expectedChallenge(challenge);
      if (
        !challengeAccepted &&
        originalChallenge !== undefined &&
        originalChallenge !== challenge
      ) {
        // Preserve compatibility with callers that verify the pre-envelope custom challenge.
        challengeAccepted = await expectedChallenge(originalChallenge);
      }
      if (
        !challengeAccepted &&
        recordedChallenge !== undefined &&
        recordedChallenge !== challenge
      ) {
        challengeAccepted = await expectedChallenge(recordedChallenge);
      }
      if (!challengeAccepted) {
        throw new Error(
          `Custom challenge verifier returned false for registration response challenge "${challenge}"`,
        );
      }
    } else if (
      challenge !== expectedChallenge &&
      expectedChallenge !== challengeRecord?.challenge &&
      !(challengeRecord?.envelope?.c !== undefined &&
        expectedChallenge === challengeRecord?.envelope?.c)
    ) {
      throw new Error(
        `Unexpected authentication response challenge "${challenge}", expected "${expectedChallenge}"`,
      );
    }

    // Check that the authentication response is within an expected iframe
    currentStage = 'top_origin';
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

    // Check that the origin is our site. When a challenge context exists, the context also has to
    // allow this origin; a broad multi-origin `expectedOrigin` must not turn into a cross-tenant
    // wildcard.
    currentStage = 'origin';
    matchExpectedOrigin(origin, expectedOrigin, challengeAuditContext);

    currentStage = 'challenge';
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
    currentStage = 'rp_id';
    const expectedRPIDs = asArray(expectedRPID);
    matchedRPID = await matchExpectedRPID(rpIdHash, expectedRPIDs, challengeAuditContext);

    if (challengeRecord) {
      assertChallengeResponseContext({
        record: challengeRecord,
        ceremony: 'authentication',
        actualOrigin: origin,
        actualRPID: matchedRPID!,
        sessionTenant: sessionTenantID,
        auditContext: challengeAuditContext,
      });
    }

    currentStage = 'user_verification';
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

    currentStage = 'counter';
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

    currentStage = 'signature';
    const verified = await verifySignature({
      signature,
      data: signatureBase,
      credentialPublicKey: credential.publicKey,
    });

    currentStage = 'commit';
    if (challengeRecord) {
      assertChallengeGenerationCurrent({
        record: challengeRecord,
        ceremony: 'authentication',
        actualOrigin: origin,
        actualRPID: matchedRPID!,
        sessionTenant: sessionTenantID,
        auditContext: challengeAuditContext,
      });
    }

    const authenticationInfo: VerifiedAuthenticationResponse['authenticationInfo'] = {
      newCounter: counter,
      credentialID: credential.id,
      userVerified: flags.uv,
      credentialDeviceType,
      credentialBackedUp,
      authenticatorExtensionResults: extensionsData,
      origin: clientDataJSON.origin,
      rpID: matchedRPID!,
    };

    /**
     * Only publish the session identity when the signature actually verified. The identity is
     * assembled from the response's actual origin/RP ID and the frozen challenge tenant, not from
     * the caller's expectations, so a final session can be written against the same object that
     * was verified.
     */
    if (verified && challengeRecord && challengeConsumption) {
      const session = {
        origin: clientDataJSON.origin,
        rpID: matchedRPID!,
        tenant: challengeRecord.context.tenant,
        challengeID: challengeConsumption.challengeID,
        generation: challengeConsumption.generation,
      };
      authenticationInfo.session = session;
      authenticationInfo.challengeContext = session;
      authenticationInfo.finalSession = session;
      authenticationInfo.tenant = session.tenant;
      authenticationInfo.challengeID = session.challengeID;
      authenticationInfo.generation = session.generation;
    }

    return { verified, authenticationInfo };
  } catch (error) {
    /**
     * Legacy/stateless callers keep their historical error types and messages. Once a challenge
     * context is in play, every rejection carries a structured report naming the stage, actual
     * origin/RP ID/tenant and the exact check that rejected it.
     */
    rethrowWithChallengeAudit({
      error,
      ceremony: 'authentication',
      stage: currentStage,
      auditContext: challengeAuditContext,
      actualOrigin: origin,
      actualRPID: matchedRPID,
    });
  }
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
 * @param authenticationInfo?.authenticatorExtensionResults The authenticator extensions returned
 * by the browser
 * @param authenticationInfo?.session The verified challenge/session identity to use when writing
 * the final session. Only present when the challenge used a challenge context and the signature
 * verified.
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
    /** Tenant frozen into the challenge, copied from the verified session */
    tenant?: string;
    /** Handle of the consumed challenge */
    challengeID?: string;
    /** Generation of the consumed challenge */
    generation?: number;
    /** Verified origin/RP ID/tenant identity for the final session */
    session?: VerifiedSessionIdentity;
    /** Alias for `session` */
    challengeContext?: VerifiedSessionIdentity;
    /** Alias for `session` */
    finalSession?: VerifiedSessionIdentity;
  };
};
