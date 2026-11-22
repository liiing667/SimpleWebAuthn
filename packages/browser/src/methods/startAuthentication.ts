import type {
  AuthenticationCredential,
  AuthenticationResponseJSON,
  CredentialRequestOptions,
  PublicKeyCredentialRequestOptions,
  PublicKeyCredentialRequestOptionsJSON,
} from '../types/index.ts';
import { bufferToBase64URLString } from '../helpers/bufferToBase64URLString.ts';
import { base64URLStringToBuffer } from '../helpers/base64URLStringToBuffer.ts';
import { browserSupportsWebAuthn } from '../helpers/browserSupportsWebAuthn.ts';
import { browserSupportsWebAuthnAutofill } from '../helpers/browserSupportsWebAuthnAutofill.ts';
import { toPublicKeyCredentialDescriptor } from '../helpers/toPublicKeyCredentialDescriptor.ts';
import { identifyAuthenticationError } from '../helpers/identifyAuthenticationError.ts';
import { WebAuthnAbortService } from '../helpers/webAuthnAbortService.ts';
import { toAuthenticatorAttachment } from '../helpers/toAuthenticatorAttachment.ts';
import { WebAuthnError } from '../helpers/webAuthnError.ts';

export type StartAuthenticationOpts = Parameters<typeof startAuthentication>[0];

/**
 * Begin authenticator "login" via WebAuthn assertion
 *
 * @param optionsJSON Output from **@simplewebauthn/server**'s `generateAuthenticationOptions()`
 * @param useBrowserAutofill (Optional) Initialize conditional UI to enable logging in via browser autofill prompts. Defaults to `false`.
 * @param verifyBrowserAutofillInput (Optional) Ensure a suitable `<input>` element is present when `useBrowserAutofill` is `true`. Defaults to `true`.
 */
export async function startAuthentication(
  options: {
    optionsJSON: PublicKeyCredentialRequestOptionsJSON;
    useBrowserAutofill?: boolean;
    verifyBrowserAutofillInput?: boolean;
  },
): Promise<AuthenticationResponseJSON> {
  // @ts-ignore: Intentionally check for old call structure to warn about improper API call
  if (!options.optionsJSON && options.challenge) {
    console.warn(
      'startAuthentication() was not called correctly. It will try to continue with the provided options, but this call should be refactored to use the expected call structure instead. See https://simplewebauthn.dev/docs/packages/browser#typeerror-cannot-read-properties-of-undefined-reading-challenge for more information.',
    );

    // @ts-ignore: Reassign the options, passed in as a positional argument, to the expected variable
    options = { optionsJSON: options };
  }

  const {
    optionsJSON,
    useBrowserAutofill = false,
    verifyBrowserAutofillInput = true,
  } = options;

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

  // We need to avoid passing empty array to avoid blocking retrieval
  // of public key
  let allowCredentials;
  if (optionsJSON.allowCredentials?.length !== 0) {
    allowCredentials = optionsJSON.allowCredentials?.map(
      toPublicKeyCredentialDescriptor,
    );
  }

  // We need to convert some values to Uint8Arrays before passing the credentials to the navigator
  const publicKey: PublicKeyCredentialRequestOptions = {
    ...browserOptionsJSON,
    challenge: base64URLStringToBuffer(browserOptionsJSON.challenge),
    allowCredentials,
  };

  // Prepare options for `.get()`
  const getOptions: CredentialRequestOptions = {};

  /**
   * Set up the page to prompt the user to select a credential for authentication via the browser's
   * input autofill mechanism.
   */
  if (useBrowserAutofill) {
    if (!(await browserSupportsWebAuthnAutofill())) {
      throw Error('Browser does not support WebAuthn autofill');
    }

    // Check for an <input> with "webauthn" in its `autocomplete` attribute
    const eligibleInputs = document.querySelectorAll(
      "input[autocomplete$='webauthn']",
    );

    // WebAuthn autofill requires at least one valid input
    if (eligibleInputs.length < 1 && verifyBrowserAutofillInput) {
      throw Error(
        'No <input> with "webauthn" as the only or last value in its `autocomplete` attribute was detected',
      );
    }

    // `CredentialMediationRequirement` doesn't know about "conditional" yet as of
    // typescript@4.6.3
    getOptions.mediation = 'conditional' as CredentialMediationRequirement;
    // Conditional UI requires an empty allow list
    publicKey.allowCredentials = [];
  }

  // Finalize options
  getOptions.publicKey = publicKey;
  // Set up the ability to cancel this request if the user attempts another
  const abortSignal = WebAuthnAbortService.createNewAbortSignal();
  const ceremony = WebAuthnAbortService.getCeremonyState(abortSignal) ?? {
    signal: abortSignal,
    generation: WebAuthnAbortService.generation,
    ceremonyID: WebAuthnAbortService.ceremonyID,
  };
  getOptions.signal = abortSignal;

  // Wait for the user to complete assertion
  let credential;
  try {
    credential = (await navigator.credentials.get(
      // TODO: Newer versions of Deno require this casting, revisit once we're using Deno 2.6+
      getOptions as globalThis.CredentialRequestOptions,
    )) as AuthenticationCredential;
  } catch (err) {
    throw identifyAuthenticationError({ error: err as Error, options: getOptions });
  }

  /**
   * A browser can resolve an assertion at the same moment another ceremony starts or the current
   * one is cancelled. The result belongs to the old ceremony and must never be returned to the
   * caller's newer session.
   */
  if (!WebAuthnAbortService.isCurrentCeremony(ceremony.signal, ceremony.generation)) {
    const abortError = new Error(
      'Authentication ceremony was superseded or cancelled before its result could be used',
    );
    abortError.name = 'AbortError';
    const identified = identifyAuthenticationError({
      error: abortError,
      options: getOptions,
    });
    if (identified instanceof WebAuthnError) {
      throw identified;
    }
    throw new WebAuthnError({
      message: 'Authentication ceremony was sent an abort signal',
      code: 'ERROR_CEREMONY_ABORTED',
      cause: abortError,
    });
  }

  if (!credential) {
    throw new Error('Authentication was not completed');
  }

  const { id, rawId, response, type } = credential;

  let userHandle = undefined;
  if (response.userHandle) {
    userHandle = bufferToBase64URLString(response.userHandle);
  }

  // Convert values to base64 to make it easier to send back to the server
  return {
    id,
    rawId: bufferToBase64URLString(rawId),
    response: {
      authenticatorData: bufferToBase64URLString(response.authenticatorData),
      clientDataJSON: bufferToBase64URLString(response.clientDataJSON),
      signature: bufferToBase64URLString(response.signature),
      userHandle,
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
