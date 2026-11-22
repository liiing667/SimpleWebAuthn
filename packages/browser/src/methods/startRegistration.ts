import type {
  CredentialCreationOptions,
  PublicKeyCredentialCreationOptions,
  PublicKeyCredentialCreationOptionsJSON,
  RegistrationCredential,
  RegistrationResponseJSON,
} from '../types/index.ts';
import { bufferToBase64URLString } from '../helpers/bufferToBase64URLString.ts';
import { base64URLStringToBuffer } from '../helpers/base64URLStringToBuffer.ts';
import { browserSupportsWebAuthn } from '../helpers/browserSupportsWebAuthn.ts';
import { toPublicKeyCredentialDescriptor } from '../helpers/toPublicKeyCredentialDescriptor.ts';
import { identifyRegistrationError } from '../helpers/identifyRegistrationError.ts';
import { WebAuthnAbortService } from '../helpers/webAuthnAbortService.ts';
import { toAuthenticatorAttachment } from '../helpers/toAuthenticatorAttachment.ts';
import { WebAuthnError } from '../helpers/webAuthnError.ts';

export type StartRegistrationOpts = Parameters<typeof startRegistration>[0];

/**
 * Begin authenticator "registration" via WebAuthn attestation
 *
 * @param optionsJSON Output from **@simplewebauthn/server**'s `generateRegistrationOptions()`
 * @param useAutoRegister (Optional) Try to silently create a passkey with the password manager that the user just signed in with. Defaults to `false`.
 */
export async function startRegistration(
  options: {
    optionsJSON: PublicKeyCredentialCreationOptionsJSON;
    useAutoRegister?: boolean;
  },
): Promise<RegistrationResponseJSON> {
  // @ts-ignore: Intentionally check for old call structure to warn about improper API call
  if (!options.optionsJSON && options.challenge) {
    console.warn(
      'startRegistration() was not called correctly. It will try to continue with the provided options, but this call should be refactored to use the expected call structure instead. See https://simplewebauthn.dev/docs/packages/browser#typeerror-cannot-read-properties-of-undefined-reading-challenge for more information.',
    );

    // @ts-ignore: Reassign the options, passed in as a positional argument, to the expected variable
    options = { optionsJSON: options };
  }

  const { optionsJSON, useAutoRegister = false } = options;

  const {
    ceremonyID: optionCeremonyID,
    ceremonyGeneration: optionCeremonyGeneration,
    challengeID: optionChallengeID,
    ceremony: optionCeremony,
    ...browserOptionsJSON
  } = optionsJSON;
  const hasCeremonyMetadata = optionCeremonyID !== undefined ||
    optionCeremonyGeneration !== undefined ||
    optionChallengeID !== undefined ||
    optionCeremony !== undefined;

  if (!browserSupportsWebAuthn()) {
    throw new Error('WebAuthn is not supported in this browser');
  }

  // We need to convert some values to Uint8Arrays before passing the credentials to the navigator
  const publicKey: PublicKeyCredentialCreationOptions = {
    ...browserOptionsJSON,
    challenge: base64URLStringToBuffer(browserOptionsJSON.challenge),
    user: {
      ...browserOptionsJSON.user,
      id: base64URLStringToBuffer(browserOptionsJSON.user.id),
    },
    excludeCredentials: browserOptionsJSON.excludeCredentials?.map(
      toPublicKeyCredentialDescriptor,
    ),
  };

  // Prepare options for `.create()`
  const createOptions: CredentialCreationOptions = {};

  /**
   * Try to use conditional create to register a passkey for the user with the password manager
   * the user just used to authenticate with. The user won't be shown any prominent UI by the
   * browser.
   */
  if (useAutoRegister) {
    // @ts-ignore: `mediation` doesn't yet exist on CredentialCreationOptions but it's possible as of Sept 2024
    createOptions.mediation = 'conditional' as CredentialMediationRequirement;
  }

  // Finalize options
  createOptions.publicKey = publicKey;
  // Set up the ability to cancel this request if the user attempts another
  const abortSignal = WebAuthnAbortService.createNewAbortSignal();
  const ceremony = WebAuthnAbortService.getCeremonyState(abortSignal) ?? {
    signal: abortSignal,
    generation: WebAuthnAbortService.generation,
    ceremonyID: WebAuthnAbortService.ceremonyID,
  };
  createOptions.signal = abortSignal;

  // Wait for the user to complete attestation
  let credential;
  try {
    credential = (await navigator.credentials.create(
      // TODO: Newer versions of Deno require this casting, revisit once we're using Deno 2.6+
      createOptions as globalThis.CredentialCreationOptions,
    )) as RegistrationCredential;
  } catch (err) {
    throw identifyRegistrationError({ error: err as Error, options: createOptions });
  }

  /**
   * As with authentication, a stale registration result must not be delivered to a newer
   * ceremony after the original one was superseded or cancelled.
   */
  if (!WebAuthnAbortService.isCurrentCeremony(ceremony.signal, ceremony.generation)) {
    const abortError = new Error(
      'Registration ceremony was superseded or cancelled before its result could be used',
    );
    abortError.name = 'AbortError';
    const identified = identifyRegistrationError({
      error: abortError,
      options: createOptions,
    });
    if (identified instanceof WebAuthnError) {
      throw identified;
    }
    throw new WebAuthnError({
      message: 'Registration ceremony was sent an abort signal',
      code: 'ERROR_CEREMONY_ABORTED',
      cause: abortError,
    });
  }

  if (!credential) {
    throw new Error('Registration was not completed');
  }

  const { id, rawId, response, type } = credential;

  // Continue to play it safe with `getTransports()` for now, even when L3 types say it's required
  let transports: string[] | undefined = undefined;
  if (typeof response.getTransports === 'function') {
    transports = response.getTransports();
  }

  // L3 says this is required, but browser and webview support are still not guaranteed.
  let responsePublicKeyAlgorithm: number | undefined = undefined;
  if (typeof response.getPublicKeyAlgorithm === 'function') {
    try {
      responsePublicKeyAlgorithm = response.getPublicKeyAlgorithm();
    } catch (error) {
      warnOnBrokenImplementation('getPublicKeyAlgorithm()', error as Error);
    }
  }

  let responsePublicKey: string | undefined = undefined;
  if (typeof response.getPublicKey === 'function') {
    try {
      const _publicKey = response.getPublicKey();
      if (_publicKey !== null) {
        responsePublicKey = bufferToBase64URLString(_publicKey);
      }
    } catch (error) {
      warnOnBrokenImplementation('getPublicKey()', error as Error);
    }
  }

  // L3 says this is required, but browser and webview support are still not guaranteed.
  let responseAuthenticatorData: string | undefined;
  if (typeof response.getAuthenticatorData === 'function') {
    try {
      responseAuthenticatorData = bufferToBase64URLString(
        response.getAuthenticatorData(),
      );
    } catch (error) {
      warnOnBrokenImplementation('getAuthenticatorData()', error as Error);
    }
  }

  return {
    id,
    rawId: bufferToBase64URLString(rawId),
    response: {
      attestationObject: bufferToBase64URLString(response.attestationObject),
      clientDataJSON: bufferToBase64URLString(response.clientDataJSON),
      transports,
      publicKeyAlgorithm: responsePublicKeyAlgorithm,
      publicKey: responsePublicKey,
      authenticatorData: responseAuthenticatorData,
    },
    type,
    clientExtensionResults: credential.getClientExtensionResults(),
    authenticatorAttachment: toAuthenticatorAttachment(
      credential.authenticatorAttachment,
    ),
    ...(hasCeremonyMetadata
      ? {
        ceremonyID: optionCeremonyID ?? optionCeremony?.id ?? ceremony.ceremonyID,
        ceremonyGeneration: optionCeremonyGeneration ??
          optionCeremony?.generation ?? ceremony.generation,
        browserCeremonyID: ceremony.ceremonyID,
        browserCeremonyGeneration: ceremony.generation,
        ...(optionCeremonyGeneration !== undefined ||
            optionCeremony?.generation !== undefined
          ? {
            serverCeremonyGeneration: optionCeremonyGeneration ??
              optionCeremony?.generation,
          }
          : {}),
        ...(optionChallengeID || optionCeremony?.challengeID
          ? { challengeID: optionChallengeID ?? optionCeremony?.challengeID }
          : {}),
        ceremony: {
          id: optionCeremonyID ?? optionCeremony?.id ?? ceremony.ceremonyID,
          generation: optionCeremonyGeneration ?? optionCeremony?.generation ??
            ceremony.generation,
          challengeID: optionChallengeID ?? optionCeremony?.challengeID,
          sessionKey: optionCeremony?.sessionKey,
        },
      }
      : {}),
  };
}

/**
 * Visibly warn when we detect an issue related to a passkey provider intercepting WebAuthn API
 * calls
 */
function warnOnBrokenImplementation(methodName: string, cause: Error): void {
  console.warn(
    `The browser extension that intercepted this WebAuthn API call incorrectly implemented ${methodName}. You should report this error to them.\n`,
    cause,
  );
}
