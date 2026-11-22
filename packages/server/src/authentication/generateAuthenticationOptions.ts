import type {
  AuthenticationExtensionsClientInputs,
  Base64URLString,
  CeremonyJSON,
  PublicKeyCredentialRequestOptionsJSON,
  Uint8Array_,
} from '../types/index.ts';
import { isoBase64URL, isoUint8Array } from '../helpers/iso/index.ts';
import { generateChallenge } from '../helpers/generateChallenge.ts';
import {
  type AuthenticationChallengeBinding,
  type ChallengeContextInput,
  type ChallengeContextRecord,
  ChallengeContextService,
  normalizeChallengeContext,
} from '../services/challengeContextService.ts';

export type GenerateAuthenticationOptionsOpts = Parameters<typeof generateAuthenticationOptions>[0];

/**
 * Ceremony/session information frozen into an authentication challenge.
 *
 * Supplying this context makes repeated `generateAuthenticationOptions()` calls for the same
 * `sessionKey` supersede each other. The newest pending challenge is the only one that can be
 * submitted, and the resulting browser ceremony generation is carried through verification into
 * `authenticationInfo.session`.
 */
export type AuthenticationCeremonyContext = ChallengeContextInput & {
  /** Stable login-session identity. Repeated starts in this session supersede older ones. */
  sessionKey?: string;
  /** Alias for `sessionKey`. */
  sessionID?: string;
  /** Alias for `sessionKey`. */
  loginSessionID?: string;
  /** Alias for `sessionKey`. */
  session?: string;
  /** Browser/tab ceremony identity. A fresh value is generated when omitted. */
  ceremonyID?: string;
  /** Ceremony generation. Advanced automatically when omitted. */
  ceremonyGeneration?: number;
  /** Alias for `ceremonyGeneration`. */
  generation?: number;
};

/** Alias for {@link AuthenticationCeremonyContext}. */
export type AuthenticationChallengeContext = AuthenticationCeremonyContext;

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
 * @param ceremonyContext **(Optional)** - Freeze the origin(s), RP ID, tenant, login session and
 * ceremony generation into the challenge. Repeated starts with the same session supersede older
 * pending challenges.
 * @param challengeContext **(Optional)** - Alias for `ceremonyContext`.
 * @param sessionKey **(Optional)** - Alias for `ceremonyContext.sessionKey`.
 * @param ceremonyID **(Optional)** - Alias for `ceremonyContext.ceremonyID`.
 * @param ceremonyGeneration **(Optional)** - Alias for
 * `ceremonyContext.ceremonyGeneration`.
 * @param bindCeremony **(Optional)** - Track even a caller-supplied challenge. Defaults to
 * tracking generated challenges and any call that supplies ceremony/session context.
 */
export async function generateAuthenticationOptions(
  options: {
    rpID: string;
    allowCredentials?: {
      id: Base64URLString;
      transports?: string[];
    }[];
    challenge?: string | Uint8Array_;
    timeout?: number;
    userVerification?: 'required' | 'preferred' | 'discouraged';
    extensions?: AuthenticationExtensionsClientInputs;
    ceremonyContext?: AuthenticationCeremonyContext;
    /** Alias for `ceremonyContext`. */
    challengeContext?: ChallengeContextInput;
    /** Convenience alias for `ceremonyContext.expectedOrigin`. */
    expectedOrigin?: string | string[];
    /** Convenience alias for `ceremonyContext.expectedRPID`. */
    expectedRPID?: string;
    /** Convenience alias for `ceremonyContext.origin`. */
    origin?: string | string[];
    /** Convenience alias for `ceremonyContext.origin`. */
    origins?: string | string[];
    /** Convenience alias for `ceremonyContext.tenant`. */
    tenant?: string;
    /** Convenience alias for `ceremonyContext.tenant`. */
    tenantID?: string;
    /** Convenience alias for `ceremonyContext.tenant`. */
    tenantId?: string;
    /** Convenience alias for `ceremonyContext.userID`. */
    userID?: Base64URLString;
    /** Stable login-session identity. */
    sessionKey?: string;
    /** Alias for `sessionKey`. */
    sessionID?: string;
    /** Alias for `sessionKey`. */
    loginSessionID?: string;
    /** Alias for `sessionKey`. */
    session?: string;
    /** Browser/tab ceremony identity. */
    ceremonyID?: string;
    /** Aggregated ceremony metadata alias. */
    ceremony?: CeremonyJSON;
    /** Ceremony generation. */
    ceremonyGeneration?: number;
    /** Alias for `ceremonyGeneration`. */
    generation?: number;
    /** Track a caller-supplied challenge even without additional ceremony context. */
    bindCeremony?: boolean;
  },
): Promise<PublicKeyCredentialRequestOptionsJSON> {
  const {
    allowCredentials,
    challenge = await generateChallenge(),
    timeout = 60000,
    userVerification = 'preferred',
    extensions,
    rpID,
    ceremonyContext,
    challengeContext,
    expectedOrigin,
    expectedRPID,
    origin,
    origins,
    tenant,
    tenantID,
    tenantId,
    userID,
    sessionKey,
    sessionID,
    loginSessionID,
    session,
    ceremonyID,
    ceremony: inputCeremony,
    ceremonyGeneration,
    generation,
    bindCeremony,
  } = options;
  const challengeWasProvided = options.challenge !== undefined;

  /**
   * Preserve ability to specify `string` values for challenges
   */
  let _challenge = challenge;
  if (typeof _challenge === 'string') {
    _challenge = isoUint8Array.fromUTF8String(_challenge);
  }

  const hasCeremonyContext = ceremonyContext !== undefined ||
    challengeContext !== undefined ||
    expectedOrigin !== undefined ||
    expectedRPID !== undefined ||
    origin !== undefined ||
    origins !== undefined ||
    tenant !== undefined ||
    tenantID !== undefined ||
    tenantId !== undefined ||
    userID !== undefined ||
    sessionKey !== undefined ||
    sessionID !== undefined ||
    loginSessionID !== undefined ||
    session !== undefined ||
    ceremonyID !== undefined ||
    inputCeremony !== undefined ||
    ceremonyGeneration !== undefined ||
    generation !== undefined ||
    bindCeremony === true;

  const contextInput = ceremonyContext ?? challengeContext ??
    (hasCeremonyContext
      ? {
        expectedOrigin,
        expectedRPID,
        origin,
        origins,
        tenant,
        tenantID,
        tenantId,
        userID,
        rpID,
      }
      : undefined);
  const normalizedContext = normalizeChallengeContext(contextInput, rpID);
  const sessionKeyValue = sessionKey ?? sessionID ?? loginSessionID ??
    session ?? inputCeremony?.sessionKey ??
    ceremonyContext?.sessionKey ?? ceremonyContext?.sessionID ??
    ceremonyContext?.loginSessionID ?? ceremonyContext?.session;
  const binding: AuthenticationChallengeBinding | undefined = allowCredentials?.length
    ? {
      credentialIDs: allowCredentials.map((credential) =>
        isoBase64URL.trimPadding(credential.id)
      ),
    }
    : undefined;

  let returnedChallenge = isoBase64URL.fromBuffer(_challenge);
  let challengeRecord: ChallengeContextRecord | undefined;
  if (hasCeremonyContext || !challengeWasProvided) {
    returnedChallenge = await ChallengeContextService.issueChallenge({
      ceremony: 'authentication',
      challenge: returnedChallenge,
      context: normalizedContext ?? { rpID },
      rpID,
      binding,
      timeoutMS: timeout,
      challengeAliases: typeof challenge === 'string' ? [challenge] : undefined,
      sessionKey: sessionKeyValue,
      ceremonyID: ceremonyID ?? inputCeremony?.id ??
        ceremonyContext?.ceremonyID,
      ceremonyGeneration: ceremonyGeneration ?? generation ??
        inputCeremony?.generation ?? ceremonyContext?.ceremonyGeneration ??
        ceremonyContext?.generation,
      ceremonyMetadataExposed: hasCeremonyContext,
    });
    challengeRecord = ChallengeContextService.getChallenge(returnedChallenge);
  } else {
    /**
     * A caller-supplied challenge keeps its exact historical bytes, but is still remembered so a
     * same-process replay cannot turn it into a second login. After a process restart the raw
     * challenge is treated as legacy/untracked, preserving the old stateless fallback.
     */
    ChallengeContextService.rememberChallenge({
      challenge: returnedChallenge,
      ceremony: 'authentication',
      context: normalizedContext ?? { rpID },
      rpID,
      binding,
      timeoutMS: timeout,
      challengeAliases: typeof challenge === 'string' ? [challenge] : undefined,
      ceremonyMetadataExposed: false,
    });
  }

  return {
    rpId: rpID,
    challenge: returnedChallenge,
    allowCredentials: allowCredentials?.map((cred) => {
      if (!isoBase64URL.isBase64URL(cred.id)) {
        throw new Error(`allowCredential id "${cred.id}" is not a valid base64url string`);
      }

      return {
        ...cred,
        id: isoBase64URL.trimPadding(cred.id),
        type: 'public-key',
      };
    }),
    timeout,
    userVerification,
    extensions,
    ...(hasCeremonyContext && challengeRecord
      ? {
        ceremonyID: challengeRecord.ceremonyID,
        ceremonyGeneration: challengeRecord.ceremonyGeneration,
        challengeID: challengeRecord.challengeID,
        ceremony: {
          id: challengeRecord.ceremonyID,
          generation: challengeRecord.ceremonyGeneration,
          challengeID: challengeRecord.challengeID,
          sessionKey: challengeRecord.sessionKey,
        },
      }
      : {}),
  };
}
