import type {
  CredentialDeviceType,
  RegistrationResponseJSON,
  Uint8Array_,
  WebAuthnCredential,
} from '../types/index.ts';
import { PQCNotSupportedError } from '../errors/index.ts';
import {
  type AttestationFormat,
  type AttestationStatement,
  decodeAttestationObject,
} from '../helpers/decodeAttestationObject.ts';
import type { AuthenticationExtensionsAuthenticatorOutputs } from '../helpers/decodeAuthenticatorExtensions.ts';
import { decodeClientDataJSON } from '../helpers/decodeClientDataJSON.ts';
import { parseAuthenticatorData } from '../helpers/parseAuthenticatorData.ts';
import { toHash } from '../helpers/toHash.ts';
import { decodeCredentialPublicKey } from '../helpers/decodeCredentialPublicKey.ts';
import { COSEKEYS, isPQCCOSEAlg } from '../helpers/cose.ts';
import { convertAAGUIDToString } from '../helpers/convertAAGUIDToString.ts';
import { parseBackupFlags } from '../helpers/parseBackupFlags.ts';
import { matchExpectedRPID } from '../helpers/matchExpectedRPID.ts';
import { isoBase64URL } from '../helpers/iso/index.ts';
import { SettingsService } from '../services/settingsService.ts';
import { MetadataService } from '../services/metadataService.ts';
import { ConvenienceMetadataService } from '../services/convenienceMetadataService.ts';
import type { ProviderMetadata } from '../metadata/convenienceMDSTypes.ts';

import { getDefaultSupportedAlgorithmIDs } from './generateRegistrationOptions.ts';
import { verifyAttestationFIDOU2F } from './verifications/verifyAttestationFIDOU2F.ts';
import { verifyAttestationPacked } from './verifications/verifyAttestationPacked.ts';
import { verifyAttestationAndroidSafetyNet } from './verifications/verifyAttestationAndroidSafetyNet.ts';
import { verifyAttestationTPM } from './verifications/tpm/verifyAttestationTPM.ts';
import { verifyAttestationAndroidKey } from './verifications/verifyAttestationAndroidKey.ts';
import { verifyAttestationApple } from './verifications/verifyAttestationApple.ts';
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
  assertChallengeGenerationCurrent,
  assertChallengeResponseContext,
  challengeConsumptionError,
  REGISTRATION_SOURCE,
  rethrowWithChallengeAudit,
} from '../helpers/challengeVerification.ts';

/**
 * Configurable options when calling `verifyRegistrationResponse()`
 */
export type VerifyRegistrationResponseOpts = Parameters<typeof verifyRegistrationResponse>[0];

/**
 * Verify that the user has legitimately completed the registration process
 *
 * **Options:**
 *
 * @param response - Response returned by **@simplewebauthn/browser**'s `startAuthentication()`
 * @param expectedChallenge - The base64url-encoded `options.challenge` returned by `generateRegistrationOptions()`
 * @param expectedOrigin - Website URL (or array of URLs) that the registration should have occurred on
 * @param expectedRPID - RP ID (or array of IDs) that was specified in the registration options
 * @param expectedType **(Optional)** - The response type expected ('webauthn.create')
 * @param requireUserPresence **(Optional)** - Enforce user presence by the authenticator (or skip it during auto registration) Defaults to `true`
 * @param requireUserVerification **(Optional)** - Enforce user verification by the authenticator (via PIN, fingerprint, etc...) Defaults to `true`
 * @param supportedAlgorithmIDs **(Optional)** - Array of numeric COSE algorithm identifiers indicating supported public key algorithms. Import `COSEALG` from \@simplewebauthn/server/helpers for suitable values. Should be the same value that was specified for this same argument when calling `generateRegistrationOptions()`. Defaults to `[COSEALG.EdDSA, COSEALG.ES256, COSEALG.RS256]`
 * @param attestationSafetyNetEnforceCTSCheck **(Optional)** - Require that an Android device's system integrity has not been tampered with if it uses SafetyNet attestation. Defaults to `true`
 * @param expectedTenant **(Optional)** - Tenant/account/session identity that is consuming this
 * registration. Required when the challenge was generated with a `tenant` in its
 * `challengeContext`.
 * @param requireChallengeContext **(Optional)** - When `true`, reject caller-managed challenges
 * that were not issued with a challenge context. Defaults to `false` for backwards compatibility.
 */
export async function verifyRegistrationResponse(
  options: {
    response: RegistrationResponseJSON;
    expectedChallenge: string | ((challenge: string) => boolean | Promise<boolean>);
    expectedOrigin: string | string[];
    expectedRPID?: string | string[];
    expectedType?: string | string[];
    requireUserPresence?: boolean;
    requireUserVerification?: boolean;
    supportedAlgorithmIDs?: number[];
    attestationSafetyNetEnforceCTSCheck?: boolean;
    expectedTenant?: string;
    /** Alias for `expectedTenant` */
    tenant?: string;
    /** Alias for `expectedTenant` */
    tenantId?: string;
    /** Alias for `expectedTenant` */
    sessionTenant?: string;
    requireChallengeContext?: boolean;
  },
): Promise<VerifiedRegistrationResponse> {
  const {
    response: originalResponse,
    expectedChallenge,
    expectedOrigin: originalExpectedOrigin,
    expectedRPID: originalExpectedRPID,
    expectedType: originalExpectedType,
    requireUserPresence = true,
    requireUserVerification = true,
    supportedAlgorithmIDs: originalSupportedAlgorithmIDs = getDefaultSupportedAlgorithmIDs(),
    attestationSafetyNetEnforceCTSCheck = true,
    expectedTenant,
    tenant,
    tenantId,
    sessionTenant,
    requireChallengeContext = false,
  } = options;

  const sessionTenantID = expectedTenant ?? tenant ?? tenantId ?? sessionTenant;

  /**
   * Freeze the response and caller expectations before any async work. The attestation object,
   * challenge, origin and supported algorithms all need to describe the same submission when the
   * registration is finally committed.
   */
  const response: RegistrationResponseJSON = {
    ...originalResponse,
    response: {
      ...originalResponse.response,
      attestationObject: originalResponse.response.attestationObject,
      clientDataJSON: originalResponse.response.clientDataJSON,
      transports: originalResponse.response.transports
        ? [...originalResponse.response.transports]
        : undefined,
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
  const supportedAlgorithmIDs = [...originalSupportedAlgorithmIDs];

  const { id, rawId, type: credentialType, response: attestationResponse } = response;

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

  const clientDataJSON = decodeClientDataJSON(
    attestationResponse.clientDataJSON,
  );

  const { type, origin, challenge, tokenBinding } = clientDataJSON;

  let currentStage: VerificationStage = 'challenge';
  let challengeAuditContext: Partial<ChallengeAudit> | undefined;
  let challengeConsumption: ChallengeConsumption | undefined;
  let challengeRecord: ChallengeContextRecord | undefined;
  let matchedRPID: string | undefined;

  try {
    currentStage = 'challenge';
    /**
     * Consume the challenge synchronously before any async attestation work. Both registration
     * and authentication share the same ledger/generation, so a challenge issued for one
     * ceremony can't be committed by the other.
     */
    challengeConsumption = ChallengeContextService.consumeChallenge({
      challenge,
      ceremony: 'registration',
      requireContext: requireChallengeContext,
    });
    challengeRecord = challengeConsumption.record;

    if (challengeConsumption.tracked) {
      challengeAuditContext = {
        ceremony: 'registration',
        stage: currentStage,
        location: `${REGISTRATION_SOURCE}#challenge`,
        reason: 'challenge context check',
        actualOrigin: origin,
        expectedOrigins: challengeRecord?.context.origins ?? [],
        callerExpectedOrigins: asArray(expectedOrigin),
        expectedRPID: challengeRecord?.context.rpID,
        callerExpectedRPIDs: expectedRPID ? asArray(expectedRPID) : undefined,
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
        ceremony: 'registration',
        audit: challengeAuditContext,
      });
    }

    currentStage = 'ceremony';
    // Make sure we're handling an registration
    if (Array.isArray(expectedType)) {
      if (!expectedType.includes(type)) {
        const joinedExpectedType = expectedType.join(', ');
        throw new Error(
          `Unexpected registration response type "${type}", expected one of: ${joinedExpectedType}`,
        );
      }
    } else if (expectedType) {
      if (type !== expectedType) {
        throw new Error(
          `Unexpected registration response type "${type}", expected "${expectedType}"`,
        );
      }
    } else if (type !== 'webauthn.create') {
      throw new Error(`Unexpected registration response type: ${type}`);
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
        `Unexpected registration response challenge "${challenge}", expected "${expectedChallenge}"`,
      );
    }

    // Check that the origin is our site. A challenge context additionally pins the origin(s) that
    // were allowed when the options were generated.
    currentStage = 'origin';
    matchExpectedOrigin(origin, expectedOrigin, challengeAuditContext);

    if (tokenBinding) {
      if (typeof tokenBinding !== 'object') {
        throw new Error(`Unexpected value for TokenBinding "${tokenBinding}"`);
      }

      if (
        ['present', 'supported', 'not-supported'].indexOf(tokenBinding.status) < 0
      ) {
        throw new Error(
          `Unexpected tokenBinding.status value of "${tokenBinding.status}"`,
        );
      }
    }

    const attestationObject = isoBase64URL.toBuffer(
      attestationResponse.attestationObject,
    );
    const decodedAttestationObject = decodeAttestationObject(attestationObject);
    const fmt = decodedAttestationObject.get('fmt');
    const authData = decodedAttestationObject.get('authData');
    const attStmt = decodedAttestationObject.get('attStmt');

    const parsedAuthData = parseAuthenticatorData(authData);
    const {
      aaguid,
      rpIdHash,
      flags,
      credentialID,
      counter,
      credentialPublicKey,
      extensionsData,
    } = parsedAuthData;

    // Make sure the response's RP ID is ours. When a challenge context is present its RP ID is
    // authoritative even if the caller didn't repeat `expectedRPID`.
    currentStage = 'rp_id';
    const expectedRPIDs = expectedRPID
      ? asArray(expectedRPID)
      : challengeRecord
      ? [challengeRecord.context.rpID]
      : undefined;

    if (expectedRPIDs) {
      matchedRPID = await matchExpectedRPID(
        rpIdHash,
        expectedRPIDs,
        challengeAuditContext,
      );
    }

    if (challengeRecord && matchedRPID) {
      assertChallengeResponseContext({
        record: challengeRecord,
        ceremony: 'registration',
        actualOrigin: origin,
        actualRPID: matchedRPID,
        sessionTenant: sessionTenantID,
        auditContext: challengeAuditContext,
      });
    }

    currentStage = 'user_verification';
    // Make sure someone was physically present
    if (requireUserPresence && !flags.up) {
      throw new Error('User presence was required, but user was not present');
    }

    // Enforce user verification if specified
    if (requireUserVerification && !flags.uv) {
      throw new Error(
        'User verification was required, but user could not be verified',
      );
    }

    currentStage = 'challenge';
    if (!credentialID) {
      throw new Error('No credential ID was provided by authenticator');
    }

    if (!credentialPublicKey) {
      throw new Error('No public key was provided by authenticator');
    }

    if (!aaguid) {
      throw new Error('No AAGUID was present during registration');
    }

    const decodedPublicKey = decodeCredentialPublicKey(credentialPublicKey);
    const pubKeyAlg = decodedPublicKey.get(COSEKEYS.alg);

    if (typeof pubKeyAlg !== 'number') {
      throw new Error('Credential public key was missing numeric alg');
    }

    // Make sure the key algorithm is one we specified within the registration options
    if (!supportedAlgorithmIDs.includes(pubKeyAlg as number)) {
      const supported = supportedAlgorithmIDs.join(', ');
      throw new Error(
        `Unexpected public key alg "${pubKeyAlg}", expected one of "${supported}"`,
      );
    }

    /**
     * If the runtime doesn't support PQC passkeys then terminate here at the first sign of a PQC
     * algorithm so that downstream issues that arise due to lack of PQC support won't get masked as
     * unexpected behavior.
     *
     * I'm choosing to raise here even if attestation is "none" because it feels weird to allow an RP
     * to parse a registration response w/o attestation only to encounter failure when trying to auth
     * with the PQC passkey and the runtime doesn't support PQC.
     */
    if (isPQCCOSEAlg(pubKeyAlg) && !SettingsService.runtimeSupportsPQC()) {
      throw new PQCNotSupportedError(pubKeyAlg);
    }

    const clientDataHash = await toHash(
      isoBase64URL.toBuffer(attestationResponse.clientDataJSON),
    );
    const rootCertificates = SettingsService.getRootCertificates({ identifier: fmt });

    // Prepare arguments to pass to the relevant verification method
    const verifierOpts: AttestationFormatVerifierOpts = {
      aaguid,
      attStmt,
      authData,
      clientDataHash,
      credentialID,
      credentialPublicKey,
      rootCertificates,
      rpIdHash,
      attestationSafetyNetEnforceCTSCheck,
    };

    /**
     * Verification can only be performed when attestation = 'direct'
     */
    currentStage = 'signature';
    let verified = false;
    if (fmt === 'fido-u2f') {
      verified = await verifyAttestationFIDOU2F(verifierOpts);
    } else if (fmt === 'packed') {
      verified = await verifyAttestationPacked(verifierOpts);
    } else if (fmt === 'android-safetynet') {
      verified = await verifyAttestationAndroidSafetyNet(verifierOpts);
    } else if (fmt === 'android-key') {
      verified = await verifyAttestationAndroidKey(verifierOpts);
    } else if (fmt === 'tpm') {
      verified = await verifyAttestationTPM(verifierOpts);
    } else if (fmt === 'apple') {
      verified = await verifyAttestationApple(verifierOpts);
    } else if (fmt === 'none') {
      if (attStmt.size > 0) {
        throw new Error('None attestation had unexpected attestation statement');
      }
      // This is the weaker of the attestations, so there's nothing else to really check
      verified = true;
    } else {
      throw new Error(`Unsupported Attestation Format: ${fmt}`);
    }

    if (!verified) {
      return { verified: false };
    }

    currentStage = 'commit';
    const { credentialDeviceType, credentialBackedUp } = parseBackupFlags(flags);
    const formattedAAGUID = convertAAGUIDToString(aaguid);
    // Try to pull provider metadata from either MDS service,
    const providerMetadata = await MetadataService.getProviderMetadata(formattedAAGUID) ??
      await ConvenienceMetadataService.getProviderMetadata(formattedAAGUID);

    if (challengeRecord) {
      assertChallengeGenerationCurrent({
        record: challengeRecord,
        ceremony: 'registration',
        actualOrigin: origin,
        actualRPID: matchedRPID ?? challengeRecord.context.rpID,
        sessionTenant: sessionTenantID,
        auditContext: challengeAuditContext,
      });
    }

    const registrationInfo: Extract<
      VerifiedRegistrationResponse,
      { verified: true }
    >['registrationInfo'] = {
      fmt,
      aaguid: formattedAAGUID,
      passkeyProviderMetadata: providerMetadata,
      credentialType,
      credential: {
        id: isoBase64URL.fromBuffer(credentialID),
        publicKey: credentialPublicKey,
        counter,
        transports: response.response.transports,
      },
      attestationObject,
      userVerified: flags.uv,
      credentialDeviceType,
      credentialBackedUp,
      origin: clientDataJSON.origin,
      rpID: matchedRPID,
      authenticatorExtensionResults: extensionsData,
    };

    if (challengeRecord && challengeConsumption) {
      const session: VerifiedSessionIdentity = {
        origin: clientDataJSON.origin,
        rpID: matchedRPID ?? challengeRecord.context.rpID,
        tenant: challengeRecord.context.tenant,
        challengeID: challengeConsumption.challengeID,
        generation: challengeConsumption.generation,
      };
      registrationInfo.session = session;
      registrationInfo.challengeContext = session;
      registrationInfo.finalSession = session;
      registrationInfo.tenant = session.tenant;
      registrationInfo.challengeID = session.challengeID;
      registrationInfo.generation = session.generation;
    }

    return {
      verified: true,
      registrationInfo,
    };
  } catch (error) {
    rethrowWithChallengeAudit({
      error,
      ceremony: 'registration',
      stage: currentStage,
      auditContext: challengeAuditContext,
      actualOrigin: origin,
      actualRPID: matchedRPID,
    });
  }
}

/**
 * Result of registration verification
 *
 * @param verified If the assertion response could be verified
 * @param registrationInfo.fmt Type of attestation
 * @param registrationInfo.counter The number of times the authenticator reported it has been used.
 * **Should be kept in a DB for later reference to help prevent replay attacks!**
 * @param registrationInfo.aaguid Authenticator's Attestation GUID indicating the type of the
 * authenticator
 * @param registrationInfo.passkeyProviderMetadata Localized names, and light and dark mode icons,
 * for the passkey provider that manages this credential. Requires `MetadataService.initialize()`
 * to have been called prior to calling `verifyRegistrationResponse()`, and for metadata to exist
 * for `registrationInfo.aaguid`
 * @param registrationInfo.credentialPublicKey The credential's public key
 * @param registrationInfo.credentialID The credential's credential ID for the public key above
 * @param registrationInfo.credentialType The type of the credential returned by the browser
 * @param registrationInfo.userVerified Whether the user was uniquely identified during attestation
 * @param registrationInfo.attestationObject The raw `response.attestationObject` Buffer returned by
 * the authenticator
 * @param registrationInfo.credentialDeviceType Whether this is a single-device or multi-device
 * credential. **Should be kept in a DB for later reference!**
 * @param registrationInfo.credentialBackedUp Whether or not the multi-device credential has been
 * backed up. Always `false` for single-device credentials. **Should be kept in a DB for later
 * reference!**
 * @param registrationInfo.origin The origin of the website that the registration occurred on
 * @param registrationInfo?.rpID The RP ID that the registration occurred on, if one or more were
 * specified in the registration options
 * @param registrationInfo?.authenticatorExtensionResults The authenticator extensions returned
 * by the browser
 * @param registrationInfo?.session The verified challenge/session identity to use when committing
 * the new credential. Only present when the challenge used a challenge context.
 */
export type VerifiedRegistrationResponse = {
  verified: false;
  registrationInfo?: never;
} | {
  verified: true;
  registrationInfo: {
    fmt: AttestationFormat;
    aaguid: string;
    passkeyProviderMetadata?: ProviderMetadata;
    credential: WebAuthnCredential;
    credentialType: 'public-key';
    attestationObject: Uint8Array_;
    userVerified: boolean;
    credentialDeviceType: CredentialDeviceType;
    credentialBackedUp: boolean;
    origin: string;
    rpID?: string;
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

/**
 * Values passed to all attestation format verifiers, from which they are free to use as they please
 */
export type AttestationFormatVerifierOpts = {
  aaguid: Uint8Array_;
  attStmt: AttestationStatement;
  authData: Uint8Array_;
  clientDataHash: Uint8Array_;
  credentialID: Uint8Array_;
  credentialPublicKey: Uint8Array_;
  rootCertificates: string[];
  rpIdHash: Uint8Array_;
  verifyTimestampMS?: boolean;
  attestationSafetyNetEnforceCTSCheck?: boolean;
};
