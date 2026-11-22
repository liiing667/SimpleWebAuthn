import type {
  AuthenticationExtensionsClientInputs,
  Base64URLString,
  PublicKeyCredentialDescriptorJSON,
  PublicKeyCredentialRequestOptionsJSON,
  Uint8Array_,
} from '../types/index.ts';
import { isoBase64URL, isoUint8Array } from '../helpers/iso/index.ts';
import { generateChallenge } from '../helpers/generateChallenge.ts';
import { normalizeUserIdentity } from '../helpers/userHandle.ts';
import {
  type AuthenticationChallengeBinding,
  AuthenticationChallengeService,
} from '../services/authenticationChallengeService.ts';

export type GenerateAuthenticationOptionsOpts = Parameters<typeof generateAuthenticationOptions>[0];

/**
 * Identity information frozen into an authentication challenge.
 */
export type AuthenticationChallengeContext = {
  /** User/account identity this challenge belongs to. */
  userID?: Base64URLString | Uint8Array_;
  /** Alias for `userID`. */
  userHandle?: Base64URLString | Uint8Array_;
  /** Alias for `userID`. */
  expectedUserID?: Base64URLString | Uint8Array_;
  /**
   * Users that may complete this challenge. Useful for explicit username flows; discoverable
   * credentials in a truly usernameless flow should instead persist the owner on each credential
   * and pass that owner to `verifyAuthenticationResponse()`.
   */
  allowedUserIDs?: (Base64URLString | Uint8Array_)[];
  /** Owners of the credentials offered via `allowCredentials`, keyed by credential ID. */
  credentialOwners?: Record<string, Base64URLString | Uint8Array_>;
  /** Require verification to prove a user identity was bound to the challenge. */
  requireUserBinding?: boolean;
  /** RP ID to freeze. Defaults to the `rpID` argument. */
  rpID?: string;
};

function collectCredentialOwners(
  options: GenerateAuthenticationOptionsOpts,
): Record<string, Base64URLString> {
  const owners: Record<string, Base64URLString> = {};

  for (const [credentialID, owner] of Object.entries(options.credentialOwners ?? {})) {
    const normalizedOwner = normalizeUserIdentity(
      owner as string | Uint8Array_ | undefined,
    );
    if (normalizedOwner) {
      owners[isoBase64URL.trimPadding(credentialID)] = normalizedOwner;
    }
  }

  for (const [credentialID, owner] of Object.entries(
    options.challengeContext?.credentialOwners ?? {},
  )) {
    const normalizedOwner = normalizeUserIdentity(
      owner as string | Uint8Array_ | undefined,
    );
    if (normalizedOwner) {
      owners[isoBase64URL.trimPadding(credentialID)] = normalizedOwner;
    }
  }

  for (const credential of options.allowCredentials ?? []) {
    const owner = normalizeUserIdentity(
      credential.userID ?? credential.userHandle ?? credential.ownerID,
    );
    if (owner) {
      owners[isoBase64URL.trimPadding(credential.id)] = owner;
    }
  }

  const explicitUserID = normalizeUserIdentity(
    options.userID ??
      options.userHandle ??
      options.expectedUserID ??
      options.challengeContext?.userID ??
      options.challengeContext?.userHandle ??
      options.challengeContext?.expectedUserID,
  );

  /**
   * A single offered credential combined with an explicit user ID is unambiguous, so remember
   * that owner without requiring callers to duplicate the user ID onto the descriptor.
   */
  const onlyAllowCredential = options.allowCredentials?.length === 1
    ? options.allowCredentials[0]
    : undefined;
  if (explicitUserID && onlyAllowCredential) {
    const credentialID = isoBase64URL.trimPadding(onlyAllowCredential.id);
    owners[credentialID] = owners[credentialID] ?? explicitUserID;
  }

  return owners;
}

function collectAllowedUserIDs(
  options: GenerateAuthenticationOptionsOpts,
): Base64URLString[] {
  const explicitUserID = normalizeUserIdentity(
    options.userID ??
      options.userHandle ??
      options.expectedUserID ??
      options.challengeContext?.userID ??
      options.challengeContext?.userHandle ??
      options.challengeContext?.expectedUserID,
  );
  if (explicitUserID) {
    return [explicitUserID];
  }

  const userIDs = new Set<Base64URLString>();
  const candidates = [
    ...(options.allowedUserIDs ?? []),
    ...(options.challengeContext?.allowedUserIDs ?? []),
  ];

  for (const candidate of candidates) {
    const normalized = normalizeUserIdentity(candidate);
    if (normalized) {
      userIDs.add(normalized);
    }
  }

  return [...userIDs];
}

/**
 * Prepare a value to pass into navigator.credentials.get(...) for authenticator authentication
 *
 * **Options:**
 *
 * @param rpID - Valid domain name (after `https://`)
 * @param allowCredentials **(Optional)** - Authenticators previously registered by the user, if any. If undefined the client will ask the user which credential they want to use
 * @param challenge **(Optional)** - Random value the authenticator needs to sign and pass back user for authentication. Defaults to generating a random value
 * @param timeout **(Optional)** - How long (in ms) the user can take to complete authentication. Defaults to `60000`
 * @param userVerification **(Optional)** - Set to `'discouraged'` when asserting as part of a 2FA flow, otherwise set to `'preferred'` or `'required'` as desired. Defaults to `"preferred"`
 * @param extensions **(Optional)** - Additional plugins the authenticator or browser should use during authentication
 * @param challengeContext **(Optional)** - Freeze the RP ID, user identity and credential owners into the challenge. This makes the challenge single-use across retries, concurrent submissions and restarts.
 * @param userID **(Optional)** - Alias for `challengeContext.userID`
 * @param userHandle **(Optional)** - Alias for `challengeContext.userID`
 * @param allowedUserIDs **(Optional)** - Alias for `challengeContext.allowedUserIDs`
 * @param credentialOwners **(Optional)** - Alias for `challengeContext.credentialOwners`
 * @param requireUserBinding **(Optional)** - Require verification to prove a user identity was bound to the challenge
 */
export async function generateAuthenticationOptions(
  options: {
    rpID: string;
    allowCredentials?: {
      id: Base64URLString;
      transports?: string[];
      /** Owner of this credential, when known. */
      userID?: Base64URLString | Uint8Array_;
      /** Alias for `userID`. */
      userHandle?: Base64URLString | Uint8Array_;
      /** Alias for `userID`. */
      ownerID?: Base64URLString | Uint8Array_;
    }[];
    challenge?: string | Uint8Array_;
    timeout?: number;
    userVerification?: 'required' | 'preferred' | 'discouraged';
    extensions?: AuthenticationExtensionsClientInputs;
    challengeContext?: AuthenticationChallengeContext;
    userID?: Base64URLString | Uint8Array_;
    userHandle?: Base64URLString | Uint8Array_;
    expectedUserID?: Base64URLString | Uint8Array_;
    allowedUserIDs?: (Base64URLString | Uint8Array_)[];
    credentialOwners?: Record<string, Base64URLString | Uint8Array_>;
    requireUserBinding?: boolean;
    /** Explicitly envelope the challenge even if no identity information was supplied. */
    bindUserIdentity?: boolean;
  },
): Promise<PublicKeyCredentialRequestOptionsJSON> {
  const {
    allowCredentials,
    challenge = await generateChallenge(),
    timeout = 60000,
    userVerification = 'preferred',
    extensions,
    rpID,
    challengeContext,
    requireUserBinding,
    bindUserIdentity,
  } = options;
  const challengeWasProvided = options.challenge !== undefined;

  /**
   * Preserve ability to specify `string` values for challenges
   */
  let _challenge = challenge;
  if (typeof _challenge === 'string') {
    _challenge = isoUint8Array.fromUTF8String(_challenge);
  }
  const challengeString = isoBase64URL.fromBuffer(_challenge);

  const descriptors: PublicKeyCredentialDescriptorJSON[] = [];
  const credentialIDs: Base64URLString[] = [];
  for (const credential of allowCredentials ?? []) {
    if (!isoBase64URL.isBase64URL(credential.id)) {
      throw new Error(`allowCredential id "${credential.id}" is not a valid base64url string`);
    }

    const id = isoBase64URL.trimPadding(credential.id);
    credentialIDs.push(id);
    const descriptor: PublicKeyCredentialDescriptorJSON = { id, type: 'public-key' };
    if (credential.transports) {
      descriptor.transports = credential.transports;
    }
    descriptors.push(descriptor);
  }

  const credentialOwners = collectCredentialOwners(options);
  const allowedUserIDs = collectAllowedUserIDs(options);
  const binding: AuthenticationChallengeBinding = {
    credentialIDs: credentialIDs.length > 0 ? credentialIDs : undefined,
    credentialOwners: Object.keys(credentialOwners).length > 0 ? credentialOwners : undefined,
    userIDs: allowedUserIDs.length > 0 ? allowedUserIDs : undefined,
    requireUserBinding: requireUserBinding ??
      challengeContext?.requireUserBinding ??
      bindUserIdentity,
  };

  /**
   * Default-generated challenges are always enveloped so they cannot be replayed after a process
   * restart. Caller-supplied challenges stay byte-for-byte identical unless identity binding was
   * requested, preserving compatibility with RPs that assert on a custom challenge value.
   */
  const bindsIdentity = !!(
    !challengeWasProvided ||
    challengeContext ||
    bindUserIdentity ||
    allowedUserIDs.length ||
    Object.keys(credentialOwners).length ||
    requireUserBinding
  );

  let returnedChallenge: Base64URLString;
  if (bindsIdentity) {
    returnedChallenge = await AuthenticationChallengeService.issueChallenge({
      challenge: challengeString,
      rpID: challengeContext?.rpID ?? rpID,
      binding,
      timeoutMS: timeout,
      bindGeneration: true,
    });
  } else {
    await AuthenticationChallengeService.rememberChallenge({
      challenge: challengeString,
      rpID,
      binding,
      timeoutMS: timeout,
    });
    returnedChallenge = challengeString;
  }

  return {
    rpId: rpID,
    challenge: returnedChallenge,
    allowCredentials: allowCredentials ? descriptors : undefined,
    timeout,
    userVerification,
    extensions,
  };
}
