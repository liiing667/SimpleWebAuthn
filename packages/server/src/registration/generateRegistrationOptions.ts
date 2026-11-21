import type {
  AuthenticationExtensionsClientInputs,
  AuthenticatorSelectionCriteria,
  Base64URLString,
  PublicKeyCredentialCreationOptionsJSON,
  PublicKeyCredentialDescriptorJSON,
  PublicKeyCredentialHint,
  PublicKeyCredentialParameters,
  Uint8Array_,
} from '../types/index.ts';
import { SettingsService } from '../services/settingsService.ts';
import { generateChallenge } from '../helpers/generateChallenge.ts';
import { generateUserID } from '../helpers/generateUserID.ts';
import { isoBase64URL, isoUint8Array } from '../helpers/iso/index.ts';
import { COSEALG } from '../helpers/cose.ts';
import { RegistrationChallengeService } from '../services/registrationChallengeService.ts';

export type GenerateRegistrationOptionsOpts = Parameters<typeof generateRegistrationOptions>[0];

/**
 * Set up some default authenticator selection options as per the latest spec:
 * https://www.w3.org/TR/webauthn-2/#dictdef-authenticatorselectioncriteria
 *
 * Helps with some older platforms (e.g. Android 7.0 Nougat) that may not be aware of these
 * defaults.
 */
const defaultAuthenticatorSelection: AuthenticatorSelectionCriteria = {
  residentKey: 'preferred',
  userVerification: 'preferred',
};

/**
 * Generate the default array of public key algorithms to offer during registration. Defaults to
 * the most commonly-supported algorithms of EdDSA, ES256, and RS256. When the runtime supports
 * PQC algorithms, ML-DSA-44 is included as the most preferred algorithm.
 */
export function getDefaultSupportedAlgorithmIDs(): COSEALG[] {
  if (SettingsService.runtimeSupportsPQC()) {
    return [COSEALG.ML_DSA_44, COSEALG.EdDSA, COSEALG.ES256, COSEALG.RS256];
  }

  return [COSEALG.EdDSA, COSEALG.ES256, COSEALG.RS256];
}

/**
 * Prepare a value to pass into navigator.credentials.create(...) for authenticator registration
 *
 * **Options:**
 *
 * @param rpName - User-visible, "friendly" website/service name
 * @param rpID - Valid domain name (after `https://`)
 * @param userName - User's website-specific username (email, etc...)
 * @param userID **(Optional)** - User's website-specific unique ID. Defaults to generating a random identifier
 * @param challenge **(Optional)** - Random value the authenticator needs to sign and pass back. Defaults to generating a random value
 * @param userDisplayName **(Optional)** - User's actual name. Defaults to `""`
 * @param timeout **(Optional)** - How long (in ms) the user can take to complete attestation. Defaults to `60000`
 * @param attestationType **(Optional)** - Specific attestation statement. Defaults to `"none"`
 * @param excludeCredentials **(Optional)** - Authenticators registered by the user so the user can't register the same credential multiple times. Defaults to `[]`
 * @param authenticatorSelection **(Optional)** - Advanced criteria for restricting the types of authenticators that may be used. Defaults to `{ residentKey: 'preferred', userVerification: 'preferred' }`
 * @param extensions **(Optional)** - Additional plugins the authenticator or browser should use during attestation
 * @param supportedAlgorithmIDs **(Optional)** - Array of numeric COSE algorithm identifiers indicating supported public key algorithms. Import `COSEALG` from \@simplewebauthn/server/helpers for suitable values. Defaults to `[COSEALG.EdDSA, COSEALG.ES256, COSEALG.RS256]`
 * @param preferredAuthenticatorType **(Optional)** - Encourage the browser to prompt the user to register a specific type of authenticator
 */
export async function generateRegistrationOptions(
  options: {
    rpName: string;
    rpID: string;
    userName: string;
    userID?: Uint8Array_;
    challenge?: string | Uint8Array_;
    userDisplayName?: string;
    timeout?: number;
    attestationType?: 'direct' | 'enterprise' | 'none';
    excludeCredentials?: {
      id: Base64URLString;
      transports?: string[];
    }[];
    authenticatorSelection?: AuthenticatorSelectionCriteria;
    extensions?: AuthenticationExtensionsClientInputs;
    supportedAlgorithmIDs?: number[];
    preferredAuthenticatorType?: 'securityKey' | 'localDevice' | 'remoteDevice';
  },
): Promise<PublicKeyCredentialCreationOptionsJSON> {
  const {
    rpName,
    rpID,
    userName,
    userID,
    challenge = await generateChallenge(),
    userDisplayName = '',
    timeout = 60000,
    attestationType = 'none',
    excludeCredentials = [],
    authenticatorSelection = defaultAuthenticatorSelection,
    extensions,
    supportedAlgorithmIDs = getDefaultSupportedAlgorithmIDs(),
    preferredAuthenticatorType,
  } = options;

  /**
   * Prepare pubKeyCredParams from the array of algorithm ID's
   */
  const pubKeyCredParams: PublicKeyCredentialParameters[] = supportedAlgorithmIDs.map((id) => ({
    alg: id,
    type: 'public-key',
  }));

  /**
   * Capture some of the nuances of how `residentKey` and `requireResidentKey` how either is set
   * depending on when either is defined in the options
   */
  if (authenticatorSelection.residentKey === undefined) {
    /**
     * `residentKey`: "If no value is given then the effective value is `required` if
     * requireResidentKey is true or `discouraged` if it is false or absent."
     *
     * See https://www.w3.org/TR/webauthn-2/#dom-authenticatorselectioncriteria-residentkey
     */
    if (authenticatorSelection.requireResidentKey) {
      authenticatorSelection.residentKey = 'required';
    } else {
      /**
       * FIDO Conformance v1.7.2 fails the first test if we do this, even though this is
       * technically compatible with the WebAuthn L2 spec...
       */
      // authenticatorSelection.residentKey = 'discouraged';
    }
  } else {
    /**
     * `requireResidentKey`: "Relying Parties SHOULD set it to true if, and only if, residentKey is
     * set to "required""
     *
     * Spec says this property defaults to `false` so we should still be okay to assign `false` too
     *
     * See https://www.w3.org/TR/webauthn-2/#dom-authenticatorselectioncriteria-requireresidentkey
     */
    authenticatorSelection.requireResidentKey = authenticatorSelection.residentKey === 'required';
  }

  /**
   * Preserve ability to specify `string` values for challenges
   */
  let _challenge = challenge;
  if (typeof _challenge === 'string') {
    _challenge = isoUint8Array.fromUTF8String(_challenge);
  }

  /**
   * Explicitly disallow use of strings for userID anymore because `isoBase64URL.fromBuffer()` below
   * will return an empty string if one gets through!
   */
  if (typeof userID === 'string') {
    throw new Error(
      `String values for \`userID\` are no longer supported. See https://simplewebauthn.dev/docs/advanced/server/custom-user-ids`,
    );
  }

  /**
   * Generate a user ID if one is not provided
   */
  let _userID = userID;
  if (!_userID) {
    _userID = await generateUserID();
  }

  const challengeString = isoBase64URL.fromBuffer(_challenge);
  const _userIDString = isoBase64URL.fromBuffer(_userID);
  /**
   * Group credentials by the RP's stable user ID when one is supplied. When options only get a
   * library-generated random user ID, fall back to the RP ID + username so a retry for the same
   * account can still inherit `excludeCredentials` from a registration that hasn't been saved.
   */
  const trackingKey = userID !== undefined
    ? `user:${_userIDString}`
    : `name:${rpID}\u0000${userName}`;

  /**
   * Map authenticator preference to hints. Map to authenticatorAttachment as well for
   * backwards-compatibility.
   */
  const hints: PublicKeyCredentialHint[] = [];
  if (preferredAuthenticatorType) {
    if (preferredAuthenticatorType === 'securityKey') {
      hints.push('security-key');
      authenticatorSelection.authenticatorAttachment = 'cross-platform';
    } else if (preferredAuthenticatorType === 'localDevice') {
      hints.push('client-device');
      authenticatorSelection.authenticatorAttachment = 'platform';
    } else if (preferredAuthenticatorType === 'remoteDevice') {
      hints.push('hybrid');
      authenticatorSelection.authenticatorAttachment = 'cross-platform';
    }
  }

  const excludeCredentialDescriptors: PublicKeyCredentialDescriptorJSON[] = excludeCredentials.map(
    (cred) => {
      if (!isoBase64URL.isBase64URL(cred.id)) {
        throw new Error(`excludeCredential id "${cred.id}" is not a valid base64url string`);
      }

      return {
        ...cred,
        id: isoBase64URL.trimPadding(cred.id),
        type: 'public-key',
      };
    },
  );

  /**
   * If this user already completed a registration that hasn't made it into the RP's database yet
   * (for example because saving timed out), keep that credential in `excludeCredentials` so a
   * retry can't convince the authenticator to mint a second credential.
   */
  for (const credential of RegistrationChallengeService.getCredentialsForUser(trackingKey)) {
    if (!excludeCredentialDescriptors.some((cred) => cred.id === credential.credentialID)) {
      const descriptor: PublicKeyCredentialDescriptorJSON = {
        id: credential.credentialID,
        type: 'public-key',
      };
      if (credential.transports) {
        descriptor.transports = credential.transports;
      }
      excludeCredentialDescriptors.push(descriptor);
    }
  }

  /**
   * Remember this challenge so `verifyRegistrationResponse()` can consume it exactly once. This
   * closes the gap where a client retries a timed-out registration (or replays a captured `none`
   * attestation) with the same challenge.
   */
  RegistrationChallengeService.rememberChallenge({
    challenge: challengeString,
    userID: _userIDString,
    trackingKey,
    userIDWasProvided: userID !== undefined,
    timeoutMS: timeout,
  });

  return {
    challenge: challengeString,
    rp: {
      name: rpName,
      id: rpID,
    },
    user: {
      id: _userIDString,
      name: userName,
      displayName: userDisplayName,
    },
    pubKeyCredParams,
    timeout,
    attestation: attestationType,
    excludeCredentials: excludeCredentialDescriptors,
    authenticatorSelection,
    extensions: {
      ...extensions,
      credProps: true,
    },
    hints,
  };
}
