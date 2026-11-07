/**
 * Loopback host predicates for parsed URLs.
 *
 * Callers parse with WHATWG `URL` first and pass `url.hostname`. The parser
 * canonicalizes IPv4 literals (`127.1`, `0x7f000001`, and a trailing dot all
 * become `127.0.0.1`), lowercases names, and keeps lookalike domains such as
 * `127.0.0.1.evil.example` as domains. These predicates compare that parsed
 * value exactly. They never use prefix or substring matching.
 */

const OCTET = '(?:25[0-5]|2[0-4][0-9]|1[0-9]{2}|[1-9]?[0-9])';
const IPV4_LOOPBACK = new RegExp(`^127\\.${OCTET}\\.${OCTET}\\.${OCTET}$`, 'u');

/**
 * `localhost` or a canonical IPv4 address in 127.0.0.0/8. IPv6 hostnames are
 * bracketed by the URL parser and are not accepted here.
 */
export function isLoopbackHostname(hostname: string): boolean {
  return hostname === 'localhost' || IPV4_LOOPBACK.test(hostname);
}

/** Plain `http:` to a loopback host, with no userinfo. */
export function isLoopbackHttpUrl(url: URL): boolean {
  return (
    url.protocol === 'http:' &&
    url.username === '' &&
    url.password === '' &&
    isLoopbackHostname(url.hostname)
  );
}

/**
 * Hostname rule for a plaintext OAuth redirect (RFC 8252 section 7.3):
 * everything `isLoopbackHostname` accepts, plus the bracketed IPv6 loopback
 * `[::1]`. The URL parser canonicalizes the long IPv6 form to `[::1]`.
 * IPv4-mapped forms such as `[::ffff:127.0.0.1]` stay refused.
 */
export function isLoopbackRedirectHostname(hostname: string): boolean {
  return isLoopbackHostname(hostname) || hostname === '[::1]';
}

/**
 * Plain `http:` redirect to a loopback host, with no userinfo. The one rule
 * shared by the downstream grant store and the read handler's config and
 * callback checks, so both accept and refuse the same redirects.
 */
export function isLoopbackRedirectHttpUrl(url: URL): boolean {
  return (
    url.protocol === 'http:' &&
    url.username === '' &&
    url.password === '' &&
    isLoopbackRedirectHostname(url.hostname)
  );
}

/** The only plaintext authorization-server issuer host accepted at startup. */
export const INSECURE_ISSUER_LOOPBACK_HOST = '127.0.0.1' as const;

export type IssuerTransport = 'https' | 'loopback-http';

/**
 * Classify an operator-supplied issuer. Returns `undefined` for anything that
 * must fail closed.
 *
 * - `https:` with a host and no userinfo, query, or fragment is accepted.
 * - `http:` is accepted only when the parsed hostname is exactly `127.0.0.1`
 *   and the issuer string spells that authority literally. Shorthand or
 *   non-canonical spellings that the parser would normalize (`127.1`,
 *   `0x7f000001`, `127.0.0.1.`, uppercase scheme) are refused, so the
 *   advertised issuer always equals what tokens must carry.
 * - Every other scheme or host, including `localhost`, IPv6 loopback, and
 *   IPv4-mapped IPv6, is refused.
 */
export function classifyIssuerTransport(issuer: string): IssuerTransport | undefined {
  let parsed: URL;
  try {
    parsed = new URL(issuer);
  } catch {
    return undefined;
  }
  if (parsed.username !== '' || parsed.password !== '') return undefined;
  if (parsed.search !== '' || parsed.hash !== '') return undefined;
  if (parsed.hostname === '') return undefined;
  if (parsed.protocol === 'https:') return 'https';
  if (parsed.protocol !== 'http:') return undefined;
  if (parsed.hostname !== INSECURE_ISSUER_LOOPBACK_HOST) return undefined;
  const literal = /^http:\/\/([^/?#]*)(?:[/?#]|$)/u.exec(issuer);
  if (literal === null || literal[1] !== parsed.host) return undefined;
  return 'loopback-http';
}
