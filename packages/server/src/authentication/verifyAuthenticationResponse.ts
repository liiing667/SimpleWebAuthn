import type {
  AuthenticationResponseJSON,
  Base64URLString,
  CredentialDeviceType,
  Uint8Array_,
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
  CredentialBindingError,
  type CredentialBindingStage,
  PQCNotSupportedError,
  type SimpleWebAuthnErrorCode,
} from '../errors/index.ts';
import { matchExpectedOrigin } from '../helpers/matchExpectedOrigin.ts';
import {
  AuthenticationChallengeService,
  type AuthenticationChallengeRecord,
} from '../services/authenticationChallengeService.ts';
import {
  normalizeUserIdentity,
  userHandleDigest,
  userHandleMatches,
} from '../helpers/userHandle.ts';

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
 * @param expectedUserID **(Optional)** - Owner/session user that this response must authenticate.
 * When supplied it must match the credential's owner and the response's `userHandle`.
 * @param expectedUserHandle **(Optional)** - Alias for `expectedUserID`.
 * @param credentialUserID **(Optional)** - Owner of `credential`, if not already stored on it.
 * @param credentialOwnerID **(Optional)** - Alias for `credentialUserID`.
 * @param requireUserBinding **(Optional)** - Reject discoverable responses whose user identity
 * cannot be proven against the credential owner or the challenge's allowed user identities.
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
    expectedUserID?: string | Uint8Array_;
    expectedUserHandle?: Base64URLString | Uint8Array_;
    credentialUserID?: Base64URLString | Uint8Array_;
    credentialOwnerID?: Base64URLString | Uint8Array_;
    userID?: Base64URLString | Uint8Array_;
    requireUserBinding?: boolean;
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
    expectedUserID,
    expectedUserHandle,
    credentialUserID,
    credentialOwnerID,
    userID,
    requireUserBinding,
    requireUserVerification = true,
    advancedFIDOConfig,
  } = options;
  const { id, rawId, type: credentialType, response: assertionResponse } = response;
  const {
    id: frozenCredentialID,
    publicKey: frozenCredentialPublicKey,
    counter: frozenCredentialCounter,
    userID: frozenCredentialUserID,
    userHandle: frozenCredentialUserHandle,
    ownerID: frozenCredentialOwnerID,
  } = credential;
  const assertionUserHandle = assertionResponse?.userHandle;
  const assertionUserHandleDigestPromise = userHandleDigest(assertionUserHandle);

  const failBinding = async (opts: {
    stage: CredentialBindingStage;
    message: string;
    code: SimpleWebAuthnErrorCode;
    expectedUserID?: string;
    challengeID?: string;
    generation?: number;
    currentGeneration?: number;
  }): Promise<never> => {
    const [userHandleDigestValue, expectedUserHandleDigestValue] = await Promise.all([
      assertionUserHandleDigestPromise,
      userHandleDigest(opts.expectedUserID),
    ]);

    throw new CredentialBindingError({
      message: opts.message,
      code: opts.code,
      audit: {
        stage: opts.stage,
        reason: opts.message,
        credentialID: id,
        credentialOwnerID: normalizeUserIdentity(
          frozenCredentialUserID ??
            frozenCredentialUserHandle ??
            frozenCredentialOwnerID,
        ),
        expectedUserID: opts.expectedUserID,
        userHandleDigest: userHandleDigestValue,
        expectedUserHandleDigest: expectedUserHandleDigestValue,
        challengeID: opts.challengeID,
        generation: opts.generation,
        currentGeneration: opts.currentGeneration ??
          AuthenticationChallengeService.generation,
        timestamp: new Date().toISOString(),
      },
    });
  };

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

  let clientDataJSON: ReturnType<typeof decodeClientDataJSON>;
  try {
    clientDataJSON = decodeClientDataJSON(assertionResponse.clientDataJSON);
  } catch {
    await failBinding({
      stage: 'client_data',
      code: 'INVALID_CLIENT_DATA_JSON',
      message: 'Credential response clientDataJSON could not be decoded',
    });
    throw new Error('Unreachable clientDataJSON failure');
  }

  const { type, origin, challenge, tokenBinding, crossOrigin, topOrigin } = clientDataJSON;

  if (
    assertionUserHandle !== undefined &&
    assertionUserHandle !== null &&
    typeof assertionUserHandle !== 'string'
  ) {
    await failBinding({
      stage: 'user_handle',
      code: 'UNEXPECTED_USER_HANDLE',
      message: 'Credential response userHandle was not a string',
      challengeID: isoBase64URL.fromUTF8String(challenge),
    });
  }

  const normalizedResponseID = isoBase64URL.trimPadding(id);
  const normalizedCredentialID = isoBase64URL.trimPadding(frozenCredentialID);

  /**
   * Consume the challenge before any async verification work. If this challenge was issued by
   * this process, only one submission can ever pass this point, even when the first submission
   * later fails origin, RP ID, signature or user-identity checks.
   */
  const challengeConsumption = AuthenticationChallengeService.consumeChallenge(challenge);
  const challengeRecord: AuthenticationChallengeRecord | undefined =
    challengeConsumption.record;
  const challengeID = challengeRecord?.challengeID ??
    isoBase64URL.fromBuffer(await toHash(challenge));

  if (challengeConsumption.tracked && challengeConsumption.status !== 'available') {
    switch (challengeConsumption.status) {
      case 'used':
        await failBinding({
          stage: 'challenge_replay',
          code: 'AUTHENTICATION_CHALLENGE_ALREADY_USED',
          message: 'Authentication challenge has already been used',
          challengeID,
          generation: challengeConsumption.generation,
        });
        break;
      case 'expired':
        await failBinding({
          stage: 'challenge_expiry',
          code: 'AUTHENTICATION_CHALLENGE_EXPIRED',
          message: 'Authentication challenge has expired',
          challengeID,
          generation: challengeConsumption.generation,
        });
        break;
      case 'cancelled':
        await failBinding({
          stage: 'challenge_cancellation',
          code: 'AUTHENTICATION_CHALLENGE_CANCELLED',
          message: 'Authentication challenge was cancelled',
          challengeID,
          generation: challengeConsumption.generation,
        });
        break;
      case 'missing':
      case 'stale_generation':
        await failBinding({
          stage: 'challenge_lookup',
          code: 'AUTHENTICATION_CHALLENGE_STALE',
          message:
            'Authentication challenge is no longer available; regenerate authentication options',
          challengeID,
          generation: challengeConsumption.generation,
        });
        break;
      case 'available':
        break;
    }
  }

  const allowedCredentialIDs = challengeRecord?.binding.credentialIDs;
  if (
    allowedCredentialIDs &&
    !allowedCredentialIDs.some((credentialID) =>
      isoBase64URL.trimPadding(credentialID) === normalizedResponseID
    )
  ) {
    await failBinding({
      stage: 'credential_id',
      code: 'UNEXPECTED_CREDENTIAL_ID',
      message:
        `Authentication response credential ID "${id}" was not offered by the ` +
        'authentication challenge',
      challengeID,
      generation: challengeConsumption.generation,
    });
  }

  /**
   * Resolve the credential owner from every trusted source available. A challenge issued for a
   * specific user/credential freezes the owner so a later retry cannot swap identities.
   */
  const ownerClaims: string[] = [];
  const addOwnerClaim = (value: unknown) => {
    const normalized = normalizeUserIdentity(value as string | Uint8Array_ | null | undefined);
    if (normalized) {
      ownerClaims.push(normalized);
    }
  };
  addOwnerClaim(challengeRecord?.binding.credentialOwners?.[normalizedResponseID]);
  addOwnerClaim(frozenCredentialUserID);
  addOwnerClaim(frozenCredentialUserHandle);
  addOwnerClaim(frozenCredentialOwnerID);
  addOwnerClaim(credentialUserID);
  addOwnerClaim(credentialOwnerID);
  addOwnerClaim(
    typeof expectedUserID === 'string'
      ? expectedUserID
      : expectedUserID
      ? isoBase64URL.fromBuffer(expectedUserID)
      : undefined,
  );
  addOwnerClaim(expectedUserHandle);
  addOwnerClaim(userID);

  let boundOwnerID: string | undefined;
  for (const claim of ownerClaims) {
    if (!boundOwnerID) {
      boundOwnerID = claim;
    } else if (!userHandleMatches(boundOwnerID, claim)) {
      await failBinding({
        stage: 'user_handle',
        code: 'UNEXPECTED_USER_HANDLE',
        message:
          `Credential owner "${boundOwnerID}" does not match the expected user "${claim}"`,
        expectedUserID: claim,
        challengeID,
        generation: challengeConsumption.generation,
      });
    }
  }

  const challengeUserIDs = challengeRecord?.binding.userIDs;
  const hasAssertionUserHandle = typeof assertionUserHandle === 'string' &&
    assertionUserHandle.length > 0;

  if (boundOwnerID) {
    if (hasAssertionUserHandle && !userHandleMatches(assertionUserHandle, boundOwnerID)) {
      await failBinding({
        stage: 'user_handle',
        code: 'UNEXPECTED_USER_HANDLE',
        message:
          `Authentication response userHandle does not match the owner of credential "${id}"`,
        expectedUserID: boundOwnerID,
        challengeID,
        generation: challengeConsumption.generation,
      });
    }
  } else if (challengeUserIDs?.length) {
    if (hasAssertionUserHandle) {
      if (requireUserBinding || challengeRecord?.binding.requireUserBinding) {
        await failBinding({
          stage: 'user_handle',
          code: 'UNVERIFIED_USER_HANDLE',
          message:
            'Authentication response userHandle could not be verified against a credential owner',
          expectedUserID: challengeUserIDs[0],
          challengeID,
          generation: challengeConsumption.generation,
        });
      }

      const matchedUserID = challengeUserIDs.find((challengeUserID) =>
        userHandleMatches(assertionUserHandle, challengeUserID)
      );
      if (!matchedUserID) {
        await failBinding({
          stage: 'user_handle',
          code: 'UNEXPECTED_USER_HANDLE',
          message:
            'Authentication response userHandle is not one of the users accepted by the challenge',
          expectedUserID: challengeUserIDs[0],
          challengeID,
          generation: challengeConsumption.generation,
        });
      }
      boundOwnerID = matchedUserID;
    } else if (challengeUserIDs.length === 1) {
      // Non-discoverable credentials do not return a userHandle, but a challenge bound to exactly
      // one user still identifies the owner unambiguously.
      boundOwnerID = challengeUserIDs[0];
    }
  } else if (
    hasAssertionUserHandle &&
    (requireUserBinding || challengeRecord?.binding.requireUserBinding)
  ) {
    await failBinding({
      stage: 'user_handle',
      code: 'UNVERIFIED_USER_HANDLE',
      message:
        'Authentication response userHandle could not be verified against the credential owner',
      challengeID,
      generation: challengeConsumption.generation,
    });
  }

  AuthenticationChallengeService.recordConsumption(challenge, {
    credentialID: normalizedResponseID,
    userID: boundOwnerID,
    userHandle: hasAssertionUserHandle ? assertionUserHandle ?? undefined : undefined,
  });

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
  matchExpectedOrigin(origin, expectedOrigin);

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

  const matchedRPID = await matchExpectedRPID(rpIdHash, expectedRPIDs);

  if (challengeRecord && matchedRPID !== challengeRecord.rpID) {
    await failBinding({
      stage: 'rp_id',
      code: 'UNEXPECTED_RP_ID',
      message:
        `Authentication response RP ID "${matchedRPID}" does not match the RP ID ` +
        `"${challengeRecord.rpID}" frozen into the challenge`,
      challengeID,
      generation: challengeConsumption.generation,
    });
  }

  if (frozenCredentialID && normalizedResponseID !== normalizedCredentialID) {
    await failBinding({
      stage: 'credential_id',
      code: 'UNEXPECTED_CREDENTIAL_ID',
      message:
        `Authentication response credential ID "${id}" does not match the credential ` +
        `being verified ("${frozenCredentialID}")`,
      challengeID,
      generation: challengeConsumption.generation,
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
    (counter > 0 || frozenCredentialCounter > 0) &&
    counter <= frozenCredentialCounter
  ) {
    // Error out when the counter in the DB is greater than or equal to the counter in the
    // dataStruct. It's related to how the authenticator maintains the number of times its been
    // used for this client. If this happens, then someone's somehow increased the counter
    // on the device without going through this site
    throw new Error(
      `Response counter value ${counter} was lower than expected ${frozenCredentialCounter}`,
    );
  }

  const decodedPublicKey = decodeCredentialPublicKey(frozenCredentialPublicKey);
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
    credentialPublicKey: frozenCredentialPublicKey,
  });

  /**
   * A process restart (or an explicit reset/reissue) during signature verification must not
   * publish a session from a challenge generation that no longer exists. This is the last check
   * before the success value is returned; there are no more awaits, so it is atomic with the
   * session identity below.
   */
  if (challengeConsumption.tracked) {
    const trackedRecord = AuthenticationChallengeService.getChallenge(challenge);
    if (
      AuthenticationChallengeService.generation !== challengeConsumption.generation ||
      trackedRecord !== challengeRecord ||
      trackedRecord?.status !== 'used'
    ) {
      await failBinding({
        stage: 'commit',
        code: 'AUTHENTICATION_CHALLENGE_STALE',
        message:
          'Authentication challenge generation changed before the session could be committed',
        challengeID,
        generation: challengeConsumption.generation,
      });
    }
  }

  const assertionUserHandleDigest = await assertionUserHandleDigestPromise;
  const sessionIdentity: VerifiedAuthenticationSessionIdentity = {
    credentialID: frozenCredentialID,
    userID: boundOwnerID,
    credentialOwnerID: boundOwnerID,
    userHandle: hasAssertionUserHandle ? assertionUserHandle ?? undefined : undefined,
    userHandleDigest: assertionUserHandleDigest,
    challengeID,
    challengeGeneration: challengeConsumption.generation,
    generation: challengeConsumption.generation,
  };

  const toReturn: VerifiedAuthenticationResponse = {
    verified,
    authenticationInfo: {
      newCounter: counter,
      credentialID: frozenCredentialID,
      userVerified: flags.uv,
      credentialDeviceType,
      credentialBackedUp,
      authenticatorExtensionResults: extensionsData,
      origin: clientDataJSON.origin,
      rpID: matchedRPID,
      userHandle: sessionIdentity.userHandle,
      userID: sessionIdentity.userID,
      credentialOwnerID: sessionIdentity.credentialOwnerID,
      userHandleDigest: sessionIdentity.userHandleDigest,
      challengeID: sessionIdentity.challengeID,
      challengeGeneration: sessionIdentity.challengeGeneration,
      generation: sessionIdentity.generation,
      sessionIdentity,
    },
  };

  return toReturn;
}

/**
 * The identity an RP should use when creating a session after authentication.
 *
 * Every field comes from the same verified challenge generation. In particular, `credentialID`
 * is the credential that actually signed the assertion and `userID` is the owner that the
 * response's `userHandle` was checked against.
 */
export type VerifiedAuthenticationSessionIdentity = {
  credentialID: Base64URLString;
  /** Verified credential owner / user identity, when binding information was available. */
  userID?: string;
  /** Alias for `userID`; the value that should be stored as the credential owner. */
  credentialOwnerID?: string;
  /** The raw userHandle returned by the authenticator, if any. */
  userHandle?: Base64URLString;
  /** SHA-256 digest of the userHandle, safe to write to an audit log. */
  userHandleDigest?: string;
  /** Digest of the challenge that was consumed. */
  challengeID: string;
  /** Process generation that issued the challenge, when it was tracked. */
  challengeGeneration?: number;
  /** Alias for `challengeGeneration`. */
  generation?: number;
};

/** Alias for {@link VerifiedAuthenticationSessionIdentity}. */
export type AuthenticationSessionIdentity = VerifiedAuthenticationSessionIdentity;

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
 * @param authenticationInfo.userID The verified credential owner, when binding information was
 * available
 * @param authenticationInfo.userHandleDigest Digest of the authenticator's returned user handle
 * @param authenticationInfo.challengeID Digest of the consumed challenge
 * @param authenticationInfo.sessionIdentity The credential/user/challenge identity that the RP
 * should use when creating its final session
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
    /** Verified session identity. */
    userID?: string;
    /** Alias for `userID`. */
    credentialOwnerID?: string;
    /** Raw userHandle returned by the authenticator, if any. */
    userHandle?: Base64URLString;
    /** SHA-256 digest of `userHandle`, safe to write to an audit log. */
    userHandleDigest?: string;
    /** Digest of the challenge consumed by this verification. */
    challengeID: string;
    /** Process generation that issued the challenge, when tracked. */
    challengeGeneration?: number;
    /** Alias for `challengeGeneration`. */
    generation?: number;
    /**
     * The identity an RP should use when creating the final session. This object is built from
     * the same consumed challenge as the assertion verification above.
     */
    sessionIdentity: VerifiedAuthenticationSessionIdentity;
    authenticatorExtensionResults?: AuthenticationExtensionsAuthenticatorOutputs;
  };
};
