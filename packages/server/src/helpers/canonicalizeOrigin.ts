/**
 * Canonicalize an origin for comparison. `new URL().origin` lowercases the host and strips a
 * default port, which keeps legitimate origin aliases comparable without weakening the
 * exact-match rule for distinct origins.
 */
export function canonicalizeOrigin(origin: string): string {
  try {
    const url = new URL(origin);
    if (url.protocol === 'https:' || url.protocol === 'http:') {
      return url.origin;
    }
  } catch {
    // Not a URL. Exotic WebAuthn origins (application package identifiers) are compared verbatim.
  }

  return origin;
}

export function originsMatch(a: string, b: string): boolean {
  return canonicalizeOrigin(a) === canonicalizeOrigin(b);
}

/**
 * RP IDs are DNS names, so their comparison is case-insensitive. A trailing root dot is
 * semantically equivalent for a domain name and is ignored here.
 */
export function rpIDsMatch(a: string, b: string): boolean {
  return a.toLowerCase().replace(/\.$/u, '') === b.toLowerCase().replace(/\.$/u, '');
}
