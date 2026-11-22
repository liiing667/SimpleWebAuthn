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
import {
  reconcileCredentialBackupState,
  withReconciledBackupState,
} from '../helpers/credentialBackupState.ts';
import type { AuthenticationExtensionsAuthenticatorOutputs } from '../helpers/decodeAuthenticatorExtensions.ts';
import { matchExpectedRPID } from '../helpers/matchExpectedRPID.ts';
import { isoBase64URL, isoUint8Array } from '../helpers/iso/index.ts';
import { decodeCredentialPublicKey } from '../helpers/decodeCredentialPublicKey.ts';
import { COSEKEYS, isPQCCOSEAlg } from '../helpers/cose.ts';
import { SettingsService } from '../services/settingsService.ts';
import { PQCNotSupportedError } from '../errors/index.ts';
import { matchExpectedOrigin } from '../helpers/matchExpectedOrigin.ts';

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
    requireUserVerification = true,
    advancedFIDOConfig,
  } = options;
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

  /**
   * Reconcile the observed flags against the backup state persisted for this credential. This is
   * what keeps the login conclusion consistent with the stored record:
   *
   * - Legacy credentials without a policy version are recoverably migrated
   * - A credential's device type can never regress (multi-device stays multi-device)
   * - Backup state is monotonic and can never flip back from backed-up to not-backed-up
   * - Concurrent verification flows converge on the same persistable values
   *
   * The reconciliation also enforces the library's historical interpretation of the flags,
   * including raising `InvalidBackupFlags` for the spec-impossible BE=0, BS=1 combination.
   */
  const reconciled = reconcileCredentialBackupState({
    credential,
    observed: { be: !!flags.be, bs: !!flags.bs },
  });

  /**
   * The backup flags as derived purely from this response's authenticator data. Exposed for
   * inspection via `observedCredentialDeviceType`/`observedCredentialBackedUp`.
   */
  const parsed = parseBackupFlags(flags);

  /**
   * A copy of the credential carrying the reconciled, persistable backup state. Relying Parties
   * should store this object so that the next login starts from the migrated/upgraded record.
   */
  const persistedCredential = withReconciledBackupState(credential, reconciled);

  const toReturn: VerifiedAuthenticationResponse = {
    verified: await verifySignature({
      signature,
      data: signatureBase,
      credentialPublicKey: credential.publicKey,
    }),
    authenticationInfo: {
      newCounter: counter,
      credentialID: credential.id,
      userVerified: flags.uv,
      /**
       * The values below describe the credential's reconciled state so that the login conclusion
       * always matches what should be persisted, rather than the raw flags of this one response.
       */
      credentialDeviceType: reconciled.credentialDeviceType,
      credentialBackedUp: reconciled.credentialBackedUp,
      /**
       * The backup flags exactly as observed in this response, for Relying Parties that want to
       * inspect what the authenticator claimed independently of the reconciled state.
       */
      observedCredentialDeviceType: parsed.credentialDeviceType,
      observedCredentialBackedUp: parsed.credentialBackedUp,
      /**
       * The credential enriched with the reconciled backup state, ready to be persisted.
       */
      credential: persistedCredential,
      /**
       * `true` when the supplied credential was a legacy record (no policy version) that was just
       * migrated to the current backup-state policy.
       */
      backupStateMigrated: reconciled.migrated,
      backupPolicyVersion: reconciled.backupPolicyVersion,
      authenticatorExtensionResults: extensionsData,
      origin: clientDataJSON.origin,
      rpID: matchedRPID,
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
 * @param authenticationInfo.observedCredentialDeviceType The device type derived only from the BE
 * flag of this response, before reconciliation against the persisted credential state.
 * @param authenticationInfo.observedCredentialBackedUp The backup state derived only from the BS
 * flag of this response, before reconciliation against the persisted credential state.
 * @param authenticationInfo.credential The credential enriched with the reconciled
 * `credentialDeviceType`, `credentialBackedUp`, and `backupPolicyVersion`. Persist this object so
 * that the credential's backup policy never regresses and legacy records stay migrated.
 * @param authenticationInfo.backupStateMigrated Whether the supplied credential was a legacy
 * record (without a backup policy version) that was just migrated to the current policy.
 * @param authenticationInfo.backupPolicyVersion The backup-state policy version applied to the
 * returned credential state.
 * @param authenticationInfo.origin The origin of the website that the authentication occurred on
 * @param authenticationInfo.rpID The RP ID that the authentication occurred on
 * @param authenticationInfo?.authenticatorExtensionResults The authenticator extensions returned
 * by the browser
 */
export type VerifiedAuthenticationResponse = {
  verified: boolean;
  authenticationInfo: {
    credentialID: Base64URLString;
    newCounter: number;
    userVerified: boolean;
    /**
     * The credential's reconciled device type. This matches the value persisted for the
     * credential and can never regress from `multiDevice` back to `singleDevice`.
     */
    credentialDeviceType: CredentialDeviceType;
    /**
     * The credential's reconciled backup state. Monotonic: once `true` it stays `true`, and it
     * is always `false` for single-device credentials.
     */
    credentialBackedUp: boolean;
    /**
     * The device type derived solely from the BE flag of this response's authenticator data.
     * Exposed for inspection; prefer `credentialDeviceType` for any policy decision.
     */
    observedCredentialDeviceType: CredentialDeviceType;
    /**
     * The backup state derived solely from the BS flag of this response's authenticator data.
     * Exposed for inspection; prefer `credentialBackedUp` for any policy decision.
     */
    observedCredentialBackedUp: boolean;
    /**
     * A copy of the credential passed into verification, enriched with the reconciled
     * `credentialDeviceType`, `credentialBackedUp`, and `backupPolicyVersion` values. Persist
     * this object after a successful verification.
     */
    credential: WebAuthnCredential;
    /**
     * Whether the supplied credential was a legacy record without a backup policy version that
     * was just migrated to the current policy.
     */
    backupStateMigrated: boolean;
    /**
     * The backup-state policy version in effect for the returned (reconciled) credential state.
     */
    backupPolicyVersion: number;
    origin: string;
    rpID: string;
    authenticatorExtensionResults?: AuthenticationExtensionsAuthenticatorOutputs;
  };
};
