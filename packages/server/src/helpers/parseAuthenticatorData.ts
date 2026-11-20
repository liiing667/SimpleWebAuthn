import {
  type AuthenticationExtensionsAuthenticatorOutputs,
  decodeAuthenticatorExtensions,
} from './decodeAuthenticatorExtensions.ts';
import { SimpleWebAuthnError } from '../errors/index.ts';
import { isoCBOR, isoUint8Array } from './iso/index.ts';
import type { COSEPublicKey } from './cose.ts';
import type { Uint8Array_ } from '../types/index.ts';

/**
 * Make sense of the authData buffer contained in an Attestation
 */
export function parseAuthenticatorData(
  authData: Uint8Array_,
): ParsedAuthenticatorData {
  if (authData.byteLength < 37) {
    throw new SimpleWebAuthnError({
      message: `Authenticator data was ${authData.byteLength} bytes, expected at least 37 bytes`,
      code: 'INVALID_AUTHENTICATOR_DATA',
    });
  }

  let pointer = 0;
  const dataView = isoUint8Array.toDataView(authData);

  const rpIdHash = authData.slice(pointer, pointer += 32);
  if (rpIdHash.byteLength !== 32) {
    throw new SimpleWebAuthnError({
      message: `rpIdHash was ${rpIdHash.byteLength} bytes, expected exactly 32 bytes`,
      code: 'INVALID_AUTHENTICATOR_DATA',
    });
  }

  const flagsBuf = authData.slice(pointer, pointer += 1);
  const flagsInt = flagsBuf[0];

  // Bit positions can be referenced here:
  // https://www.w3.org/TR/webauthn-2/#flags
  const flags = {
    up: !!(flagsInt & (1 << 0)), // User Presence
    uv: !!(flagsInt & (1 << 2)), // User Verified
    be: !!(flagsInt & (1 << 3)), // Backup Eligibility
    bs: !!(flagsInt & (1 << 4)), // Backup State
    at: !!(flagsInt & (1 << 6)), // Attested Credential Data Present
    ed: !!(flagsInt & (1 << 7)), // Extension Data Present
    flagsInt,
  };

  const counterBuf = authData.slice(pointer, pointer + 4);
  const counter = dataView.getUint32(pointer, false);
  pointer += 4;

  let aaguid: Uint8Array_ | undefined = undefined;
  let credentialID: Uint8Array_ | undefined = undefined;
  let credentialPublicKey: Uint8Array_ | undefined = undefined;

  if (flags.at) {
    if (authData.byteLength < pointer + 16) {
      throw new SimpleWebAuthnError({
        message:
          `AT flag was set but AAGUID was truncated: expected 16 bytes at offset ${pointer}, only ${
            authData.byteLength - pointer
          } remained`,
        code: 'INVALID_AUTHENTICATOR_DATA',
      });
    }
    aaguid = authData.slice(pointer, pointer += 16);

    if (authData.byteLength < pointer + 2) {
      throw new SimpleWebAuthnError({
        message:
          `AT flag was set but credential ID length was truncated: expected 2 bytes at offset ${pointer}, only ${
            authData.byteLength - pointer
          } remained`,
        code: 'INVALID_AUTHENTICATOR_DATA',
      });
    }
    const credIDLen = dataView.getUint16(pointer);
    pointer += 2;

    if (authData.byteLength < pointer + credIDLen) {
      throw new SimpleWebAuthnError({
        message: `Credential ID length of ${credIDLen} bytes exceeded the ${
          authData.byteLength - pointer
        } remaining bytes of authenticator data`,
        code: 'INVALID_AUTHENTICATOR_DATA',
      });
    }
    credentialID = authData.slice(pointer, pointer += credIDLen);

    if (authData.byteLength <= pointer) {
      throw new SimpleWebAuthnError({
        message: 'AT flag was set but credential public key was missing',
        code: 'INVALID_AUTHENTICATOR_DATA',
      });
    }

    /**
     * Firefox 117 incorrectly CBOR-encodes authData when EdDSA (-8) is used for the public key.
     * A CBOR "Map of 3 items" (0xa3) should be "Map of 4 items" (0xa4), and if we manually adjust
     * the single byte there's a good chance the authData can be correctly parsed.
     *
     * This browser release also incorrectly uses the string labels "OKP" and "Ed25519" instead of
     * their integer representations for kty and crv respectively. That's why the COSE public key
     * in the hex below looks so odd.
     */
    // Bytes decode to `{ 1: "OKP", 3: -8, -1: "Ed25519" }` (it's missing key -2 a.k.a. COSEKEYS.x)
    const badEdDSACBOR = isoUint8Array.fromHex('a301634f4b500327206745643235353139');
    const bytesAtCurrentPosition = authData.slice(pointer, pointer + badEdDSACBOR.byteLength);
    let foundBadCBOR = false;
    if (isoUint8Array.areEqual(badEdDSACBOR, bytesAtCurrentPosition)) {
      // Change the bad CBOR 0xa3 to 0xa4 so that the credential public key can be recognized
      foundBadCBOR = true;
      authData[pointer] = 0xa4;
    }

    let firstEncoded: Uint8Array_;
    try {
      // Decode the next CBOR item in the buffer, then re-encode it back to a Buffer
      const firstDecoded = isoCBOR.decodeFirst<COSEPublicKey>(
        authData.slice(pointer),
      );
      firstEncoded = Uint8Array.from(
        /**
         * Casting to `Map` via `as unknown` here because TS doesn't make it possible to define Maps
         * with discrete keys and properties with known types per pair, and CBOR libs typically parse
         * CBOR Major Type 5 to `Map` because you can have numbers for keys. A `COSEPublicKey` can be
         * generalized as "a Map with numbers for keys and either numbers or bytes for values" though.
         * If this presumption falls apart then other parts of verification later on will fail so we
         * should be safe doing this here.
         */
        isoCBOR.encode(firstDecoded as unknown as Map<number, number | Uint8Array>),
      );
    } catch (err) {
      const _err = err as Error;
      throw new SimpleWebAuthnError({
        message: `Error decoding credential public key: ${_err.message}`,
        code: 'INVALID_AUTHENTICATOR_DATA',
        cause: _err,
      });
    } finally {
      if (foundBadCBOR) {
        // Restore the bit we changed so that `authData` is the same as it came in and won't break
        // signature verification.
        authData[pointer] = 0xa3;
      }
    }

    credentialPublicKey = firstEncoded;
    pointer += firstEncoded.byteLength;
  }

  let extensionsData: AuthenticationExtensionsAuthenticatorOutputs | undefined = undefined;
  let extensionsDataBuffer: Uint8Array_ | undefined = undefined;

  if (flags.ed) {
    if (authData.byteLength <= pointer) {
      throw new SimpleWebAuthnError({
        message: 'ED flag was set but extension data was missing',
        code: 'INVALID_AUTHENTICATOR_DATA',
      });
    }

    /**
     * Typing here feels a little sloppy but we're immediately CBOR-encoding this back to bytes to
     * more diligently parse via `decodeAuthenticatorExtensions()` so :shrug:
     */
    type AuthenticatorExtensionData = Map<string, Uint8Array>;
    let firstDecoded: AuthenticatorExtensionData;
    try {
      firstDecoded = isoCBOR.decodeFirst<AuthenticatorExtensionData>(authData.slice(pointer));
    } catch (err) {
      const _err = err as Error;
      throw new SimpleWebAuthnError({
        message: `Error decoding extension data: ${_err.message}`,
        code: 'INVALID_AUTHENTICATOR_DATA',
        cause: _err,
      });
    }
    extensionsDataBuffer = Uint8Array.from(isoCBOR.encode(firstDecoded));
    extensionsData = decodeAuthenticatorExtensions(extensionsDataBuffer);
    pointer += extensionsDataBuffer.byteLength;
  }

  // Pointer should be at the end of the authenticator data, otherwise too much data was sent
  if (authData.byteLength > pointer) {
    throw new SimpleWebAuthnError({
      message: 'Leftover bytes detected while parsing authenticator data',
      code: 'INVALID_AUTHENTICATOR_DATA',
    });
  }

  return _parseAuthenticatorDataInternals.stubThis({
    rpIdHash,
    flagsBuf,
    flags,
    counter,
    counterBuf,
    aaguid,
    credentialID,
    credentialPublicKey,
    extensionsData,
    extensionsDataBuffer,
  });
}

export type ParsedAuthenticatorData = {
  rpIdHash: Uint8Array_;
  flagsBuf: Uint8Array_;
  flags: {
    up: boolean;
    uv: boolean;
    be: boolean;
    bs: boolean;
    at: boolean;
    ed: boolean;
    flagsInt: number;
  };
  counter: number;
  counterBuf: Uint8Array_;
  aaguid?: Uint8Array_;
  credentialID?: Uint8Array_;
  credentialPublicKey?: Uint8Array_;
  extensionsData?: AuthenticationExtensionsAuthenticatorOutputs;
  extensionsDataBuffer?: Uint8Array_;
};

/**
 * Make it possible to stub the return value during testing
 * @ignore Don't include this in docs output
 */
export const _parseAuthenticatorDataInternals = {
  stubThis: (value: ParsedAuthenticatorData) => value,
};
