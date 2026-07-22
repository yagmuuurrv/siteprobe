import { request } from "undici";

import type {
  HttpResult,
  RedirectHop,
  ScanOptions,
  ScanResult,
  Target,
} from "./types.js";

/** Default per-request timeout in milliseconds (CLAUDE.md: 30s). */
const DEFAULT_TIMEOUT_MS = 30_000;

/** Default maximum number of redirects to follow. */
const DEFAULT_MAX_REDIRECTS = 10;

/** HTTP status codes that indicate a redirect. */
const REDIRECT_CODES = new Set([301, 302, 303, 307, 308]);

/**
 * Error codes that mean "the request timed out" — NOT a server error.
 * Includes undici's timeout codes and the underlying Node net codes.
 */
const TIMEOUT_CODES = new Set([
  "ETIMEDOUT",
  "ECONNABORTED",
  "UND_ERR_CONNECT_TIMEOUT",
  "UND_ERR_HEADERS_TIMEOUT",
  "UND_ERR_BODY_TIMEOUT",
]);

/** Error codes that mean "the host could not be reached". */
const UNREACHABLE_CODES = new Set([
  "ENOTFOUND",
  "ECONNRESET",
  "ECONNREFUSED",
  "EAI_AGAIN", // transient DNS failure — common, still not reachable
]);

/** Error codes that mean the TLS handshake / certificate validation failed. */
const TLS_CODES = new Set([
  "CERT_HAS_EXPIRED",
  "DEPTH_ZERO_SELF_SIGNED_CERT",
  "SELF_SIGNED_CERT_IN_CHAIN",
  "UNABLE_TO_VERIFY_LEAF_SIGNATURE",
  "ERR_TLS_CERT_ALTNAME_INVALID",
  "EPROTO",
]);

/** Human-readable explanation for each TLS error code. */
const TLS_MESSAGES: Record<string, string> = {
  CERT_HAS_EXPIRED: "The server's certificate has expired.",
  DEPTH_ZERO_SELF_SIGNED_CERT: "The server's certificate is self-signed.",
  SELF_SIGNED_CERT_IN_CHAIN:
    "A self-signed certificate is present in the certificate chain.",
  UNABLE_TO_VERIFY_LEAF_SIGNATURE:
    "The leaf certificate's signature could not be verified (incomplete chain).",
  ERR_TLS_CERT_ALTNAME_INVALID:
    "The certificate is not valid for the requested hostname.",
  EPROTO: "The TLS handshake failed (protocol error).",
};

/**
 * Run a single passive scan against `target`.
 *
 * In this step only the HTTP/redirect step is implemented; the remaining v1
 * steps (SSL, headers, tech, CVEs) are left `null` / `[]`.
 */
export async function scan(
  target: Target,
  opts: ScanOptions = {},
): Promise<ScanResult> {
  const http = await scanHttp(target, opts);

  return {
    target,
    scannedAt: new Date().toISOString(),
    http,
    ssl: null,
    headers: null,
    tech: [],
    cves: [],
  };
}

/**
 * The HTTP reachability step: send a GET, follow the redirect chain manually
 * (so each hop is recorded), and return the final state.
 *
 * Timeouts, unreachable-host and TLS errors are classified into distinct
 * statuses and are never conflated with a 5xx response (CLAUDE.md). A redirect
 * that exceeds the limit or revisits a URL yields `redirect_loop`.
 */
async function scanHttp(
  target: Target,
  opts: ScanOptions,
): Promise<HttpResult> {
  const timeoutMs = opts.timeoutMs ?? DEFAULT_TIMEOUT_MS;
  const maxRedirects = opts.maxRedirects ?? DEFAULT_MAX_REDIRECTS;

  const redirectChain: RedirectHop[] = [];
  // Canonical URLs already visited, to detect loops (CLAUDE.md req: normalize).
  const visited = new Set<string>([canonicalUrl(normalizeUrl(target))]);
  let currentUrl = normalizeUrl(target);

  try {
    for (let hop = 0; hop <= maxRedirects; hop++) {
      const res = await request(currentUrl, {
        method: "GET",
        // Follow redirects ourselves so we can record the chain.
        maxRedirections: 0,
        headersTimeout: timeoutMs,
        bodyTimeout: timeoutMs,
      });

      // Drain the body so the socket is released back to the pool.
      await res.body.dump();

      const location = headerValue(res.headers.location);

      if (REDIRECT_CODES.has(res.statusCode) && location !== null) {
        const resolved = new URL(location, currentUrl).toString();
        redirectChain.push({
          url: currentUrl,
          statusCode: res.statusCode,
          location: resolved,
        });

        // A URL we've already visited means the chain is cycling.
        if (visited.has(canonicalUrl(resolved))) {
          return { status: "redirect_loop", redirectChain };
        }

        visited.add(canonicalUrl(resolved));
        currentUrl = resolved;
        continue;
      }

      // Non-redirect (or redirect without a Location): this is the final state.
      // NOTE: a 5xx lands here as a normal `ok` result — it is NOT a timeout.
      return {
        status: "ok",
        finalUrl: currentUrl,
        finalStatusCode: res.statusCode,
        redirectChain,
      };
    }

    // Redirect limit exceeded without settling.
    return { status: "redirect_loop", redirectChain };
  } catch (err) {
    const code = extractErrorCode(err);

    if (code !== null && TLS_CODES.has(code)) {
      return {
        status: "tls_error",
        errorCode: code,
        message: TLS_MESSAGES[code] ?? "TLS handshake or certificate error.",
        redirectChain,
      };
    }
    if (code !== null && TIMEOUT_CODES.has(code)) {
      return { status: "timeout", errorCode: code, redirectChain };
    }
    if (code !== null && UNREACHABLE_CODES.has(code)) {
      return { status: "unreachable", errorCode: code, redirectChain };
    }

    // Unknown error: rethrow, never swallow (CLAUDE.md).
    throw err;
  }
}

/** Prepend `https://` when the target has no scheme. */
function normalizeUrl(target: Target): string {
  return /^[a-z][a-z0-9+.-]*:\/\//i.test(target)
    ? target
    : `https://${target}`;
}

/** Canonical form of a URL for loop comparison (scheme/host/path normalized). */
function canonicalUrl(url: string): string {
  return new URL(url).href;
}

/** Reduce an undici header value to a single string, or null when absent. */
function headerValue(value: string | string[] | undefined): string | null {
  if (value === undefined) return null;
  return Array.isArray(value) ? (value[0] ?? null) : value;
}

/**
 * Extract a Node/undici error code from an unknown thrown value, walking the
 * whole `cause` chain (undici wraps the underlying net/TLS error, sometimes
 * several levels deep). Guards against cyclic causes.
 */
function extractErrorCode(err: unknown): string | null {
  let current: unknown = err;
  const seen = new Set<unknown>();

  while (current !== null && current !== undefined && !seen.has(current)) {
    seen.add(current);

    const code = codeOf(current);
    if (code !== null) return code;

    if (typeof current === "object" && "cause" in current) {
      current = (current as { cause: unknown }).cause;
    } else {
      break;
    }
  }
  return null;
}

/** Read a string `code` property off an unknown value, or null. */
function codeOf(value: unknown): string | null {
  if (
    typeof value === "object" &&
    value !== null &&
    "code" in value &&
    typeof (value as { code: unknown }).code === "string"
  ) {
    return (value as { code: string }).code;
  }
  return null;
}
