import type {
  AuthenticationExtensionsClientInputs,
  Base64URLString,
  PublicKeyCredentialRequestOptionsJSON,
  Uint8Array_,
} from '../types/index.ts';
import { isoBase64URL, isoUint8Array } from '../helpers/iso/index.ts';
import { generateChallenge } from '../helpers/generateChallenge.ts';
import {
  type ChallengeContextInput,
  ChallengeContextService,
  normalizeChallengeContext,
} from '../services/challengeContextService.ts';

export type GenerateAuthenticationOptionsOpts = Parameters<typeof generateAuthenticationOptions>[0];

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
 * @param challengeContext **(Optional)** - Freeze the origin(s), RP ID and tenant that are allowed
 * to consume this challenge. When provided, `verifyAuthenticationResponse()` rejects a response
 * that is presented from another origin, RP ID, tenant, or process generation.
 * @param expectedOrigin **(Optional)** - Convenience alias for `challengeContext.expectedOrigin`
 * @param tenant **(Optional)** - Convenience alias for `challengeContext.tenant`
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
    challengeContext?: ChallengeContextInput;
    /** Convenience alias for `challengeContext.expectedOrigin` */
    expectedOrigin?: string | string[];
    /** Convenience alias for `challengeContext.origin` */
    origin?: string | string[];
    /** Convenience alias for `challengeContext.origin` */
    origins?: string | string[];
    /** Convenience alias for `challengeContext.tenant` */
    tenant?: string;
    /** Convenience alias for `challengeContext.tenant` */
    tenantID?: string;
    /** Convenience alias for `challengeContext.tenant` */
    tenantId?: string;
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
    expectedOrigin,
    origin,
    origins,
    tenant,
    tenantID,
    tenantId,
  } = options;

  /**
   * Preserve ability to specify `string` values for challenges
   */
  let _challenge = challenge;
  if (typeof _challenge === 'string') {
    _challenge = isoUint8Array.fromUTF8String(_challenge);
  }

  let challengeString = isoBase64URL.fromBuffer(_challenge);

  /**
   * When a context is supplied, wrap the random challenge in an opaque envelope. The browser and
   * authenticator treat the envelope exactly like any other challenge, while the server can use
   * it to distinguish a context-bound challenge from a caller-managed legacy challenge after a
   * restart.
   */
  const hasTopLevelContext = expectedOrigin !== undefined ||
    origin !== undefined ||
    origins !== undefined ||
    tenant !== undefined ||
    tenantID !== undefined ||
    tenantId !== undefined;
  const contextInput = challengeContext ??
    (hasTopLevelContext
      ? { expectedOrigin, origin, origins, tenant, tenantID, tenantId, rpID }
      : undefined);
  const normalizedContext = normalizeChallengeContext(contextInput, rpID);
  if (normalizedContext) {
    challengeString = await ChallengeContextService.issueChallenge({
      ceremony: 'authentication',
      challenge: challengeString,
      context: normalizedContext,
      timeoutMS: timeout,
      challengeAliases: typeof challenge === 'string' ? [challenge] : undefined,
    });
  }

  return {
    rpId: rpID,
    challenge: challengeString,
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
  };
}
