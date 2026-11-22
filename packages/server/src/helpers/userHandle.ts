import type { Base64URLString, Uint8Array_ } from '../types/index.ts';
import { isoBase64URL, isoUint8Array } from './iso/index.ts';
import { toHash } from './toHash.ts';

/**
 * A user handle as it may appear in an RP's database or an authenticator response.
 *
 * Current browsers return a base64url-encoded byte string. Older versions of
 * `@simplewebauthn/browser` returned the raw user handle string, and some RPs have persisted
 * padded or standard-base64 variants over time. Helpers in this module deliberately treat all of
 * those as the same identity when they refer to the same bytes.
 */
export type UserHandleValue = string | Uint8Array_ | null | undefined;

function trim(value: string): string {
  return isoBase64URL.trimPadding(value);
}

function tryDecodeBase64URL(value: string): Uint8Array_ | undefined {
  if (!value || !isoBase64URL.isBase64URL(value)) {
    return undefined;
  }

  try {
    return isoBase64URL.toBuffer(value);
  } catch {
    return undefined;
  }
}

function tryDecodeBase64(value: string): Uint8Array_ | undefined {
  if (!value || !isoBase64URL.isBase64(value)) {
    return undefined;
  }

  try {
    return isoBase64URL.toBuffer(value, 'base64');
  } catch {
    return undefined;
  }
}

function tryDecodeUTF8(value: Uint8Array_): string | undefined {
  try {
    return new globalThis.TextDecoder('utf-8', { fatal: true }).decode(value);
  } catch {
    return undefined;
  }
}

function bytesFor(value: string): Uint8Array_ | undefined {
  return tryDecodeBase64URL(value) ?? tryDecodeBase64(value);
}

/**
 * Return every representation of a user handle that should be considered equivalent.
 *
 * The result includes the value as supplied, its base64url canonical form, and (when the value
 * decodes to valid UTF-8) the legacy raw string representation used by older browser releases.
 */
export function userHandleAliases(value: UserHandleValue): string[] {
  if (value === undefined || value === null) {
    return [];
  }

  const aliases = new Set<string>();
  if (value instanceof Uint8Array) {
    const encoded = isoBase64URL.fromBuffer(value);
    aliases.add(encoded);
    aliases.add(trim(encoded));
    return [...aliases];
  }

  if (typeof value !== 'string' || value.length === 0) {
    return [];
  }

  const supplied = trim(value);
  aliases.add(supplied);

  const decoded = bytesFor(value);
  if (decoded) {
    const canonical = isoBase64URL.fromBuffer(decoded);
    aliases.add(canonical);
    aliases.add(trim(canonical));

    const decodedUTF8 = tryDecodeUTF8(decoded);
    if (decodedUTF8 !== undefined && decodedUTF8.length > 0) {
      aliases.add(decodedUTF8);
    }
  } else {
    // A legacy raw string: compare both its literal form and the base64url form it would have
    // had if it had been encoded by a current browser.
    aliases.add(isoBase64URL.fromUTF8String(value));
  }

  return [...aliases];
}

/**
 * Compare two user handles using byte-equivalent decoding so padded/unpadded base64url, standard
 * base64 and the raw UTF-8 string returned by older browsers all compare correctly.
 */
export function userHandleMatches(
  actual: UserHandleValue,
  expected: UserHandleValue,
): boolean {
  if (actual === undefined || actual === null || expected === undefined || expected === null) {
    return false;
  }

  const actualAliases = new Set(userHandleAliases(actual));
  const expectedAliases = new Set(userHandleAliases(expected));
  for (const alias of actualAliases) {
    if (expectedAliases.has(alias)) {
      return true;
    }
  }

  const actualString = typeof actual === 'string' ? actual : isoBase64URL.fromBuffer(actual);
  const expectedString = typeof expected === 'string' ? expected : isoBase64URL.fromBuffer(expected);
  const actualBytes = bytesFor(actualString);
  const expectedBytes = bytesFor(expectedString);

  return !!actualBytes && !!expectedBytes && isoUint8Array.areEqual(actualBytes, expectedBytes);
}

/**
 * Produce a stable base64url-encoded SHA-256 digest of a user handle for audit logs. User handles
 * can contain identifying information, so verification errors report this digest instead of the
 * raw value.
 */
export async function userHandleDigest(
  value: UserHandleValue,
): Promise<string | undefined> {
  if (value === undefined || value === null) {
    return undefined;
  }

  const aliases = userHandleAliases(value);
  const canonical = aliases.find((alias) => isoBase64URL.isBase64URL(alias)) ?? aliases[0];
  if (!canonical) {
    return undefined;
  }

  return isoBase64URL.fromBuffer(await toHash(canonical));
}

/**
 * Normalize an owner/user ID supplied by an RP into the form persisted on a credential.
 *
 * Strings that are already base64url are treated as encoded user handles. All other strings are
 * preserved as legacy raw values; comparisons should still use {@link userHandleMatches} so both
 * forms are accepted.
 */
export function normalizeUserIdentity(
  value: UserHandleValue,
): Base64URLString | undefined {
  if (value === undefined || value === null) {
    return undefined;
  }

  if (value instanceof Uint8Array) {
    return isoBase64URL.fromBuffer(value);
  }

  if (typeof value !== 'string' || value.length === 0) {
    return undefined;
  }

  return isoBase64URL.isBase64URL(value) ? trim(value) : value;
}
