import { request } from "undici";

import { checkHeaders, type ResponseHeaders } from "./headers.js";
import { checkSsl, type CheckSslOptions, type SslResult } from "./ssl.js";
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

/** Maximum number of body bytes to read from the final response (512 KB). */
const MAX_BODY_BYTES = 512 * 1024;

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
 * Run a single passive scan against `target`: the HTTP/redirect step, the
 * TLS/certificate step and security-header evaluation. Tech detection and CVE
 * matching are not implemented yet (left `[]`).
 */
export async function scan(
  target: Target,
  opts: ScanOptions = {},
): Promise<ScanResult> {
  const { http, finalHeaders } = await scanHttp(target, opts);
  const ssl = await scanTls(target, opts);
  const headers = finalHeaders === null ? null : checkHeaders(finalHeaders);

  return {
    target,
    scannedAt: new Date().toISOString(),
    http,
    ssl,
    headers,
    tech: [],
    cves: [],
  };
}

/**
 * The TLS/certificate step. HTTPS targets are inspected; a plain-HTTP target
 * yields a `not_applicable` SSL result.
 */
async function scanTls(target: Target, opts: ScanOptions): Promise<SslResult> {
  const url = new URL(normalizeUrl(target));

  const sslOpts: CheckSslOptions = {};
  if (opts.timeoutMs !== undefined) sslOpts.timeoutMs = opts.timeoutMs;

  if (url.protocol !== "https:") {
    return checkSsl(url.hostname, 443, { ...sslOpts, httpOnly: true });
  }
  const port = url.port === "" ? 443 : Number.parseInt(url.port, 10);
  return checkSsl(url.hostname, port, sslOpts);
}

/**
 * The HTTP reachability step: send a GET, follow the redirect chain manually
 * (so each hop is recorded), and return the final state.
 *
 * Timeouts, unreachable-host and TLS errors are classified into distinct
 * statuses and are never conflated with a 5xx response (CLAUDE.md). A redirect
 * that exceeds the limit or revisits a URL yields `redirect_loop`.
 */
/**
 * Internal result of the HTTP step: the classified result plus the final
 * response headers (present only on the `ok` path, for header evaluation).
 */
interface HttpStep {
  http: HttpResult;
  finalHeaders: ResponseHeaders | null;
}

async function scanHttp(
  target: Target,
  opts: ScanOptions,
): Promise<HttpStep> {
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

      const location = headerValue(res.headers.location);

      if (REDIRECT_CODES.has(res.statusCode) && location !== null) {
        // Drain the redirect body so the socket is released back to the pool.
        await res.body.dump();

        const resolved = new URL(location, currentUrl).toString();
        redirectChain.push({
          url: currentUrl,
          statusCode: res.statusCode,
          location: resolved,
        });

        // A URL we've already visited means the chain is cycling.
        if (visited.has(canonicalUrl(resolved))) {
          return {
            http: { status: "redirect_loop", redirectChain },
            finalHeaders: null,
          };
        }

        visited.add(canonicalUrl(resolved));
        currentUrl = resolved;
        continue;
      }

      // Non-redirect (or redirect without a Location): this is the final state.
      // NOTE: a 5xx lands here as a normal `ok` result — it is NOT a timeout.
      const { body, bodyTruncated } = await readBody(res);
      return {
        http: {
          status: "ok",
          finalUrl: currentUrl,
          finalStatusCode: res.statusCode,
          redirectChain,
          body,
          bodyTruncated,
        },
        finalHeaders: res.headers,
      };
    }

    // Redirect limit exceeded without settling.
    return {
      http: { status: "redirect_loop", redirectChain },
      finalHeaders: null,
    };
  } catch (err) {
    const code = extractErrorCode(err);

    if (code !== null && TLS_CODES.has(code)) {
      return {
        http: {
          status: "tls_error",
          errorCode: code,
          message: TLS_MESSAGES[code] ?? "TLS handshake or certificate error.",
          redirectChain,
        },
        finalHeaders: null,
      };
    }
    if (code !== null && TIMEOUT_CODES.has(code)) {
      return {
        http: { status: "timeout", errorCode: code, redirectChain },
        finalHeaders: null,
      };
    }
    if (code !== null && UNREACHABLE_CODES.has(code)) {
      return {
        http: { status: "unreachable", errorCode: code, redirectChain },
        finalHeaders: null,
      };
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

/**
 * Read the final response body, capped at MAX_BODY_BYTES. Only text/html and
 * application/* bodies are read; anything else is drained and left `null` so we
 * never pull binary blobs into memory.
 */
async function readBody(
  res: Awaited<ReturnType<typeof request>>,
): Promise<{ body: string | null; bodyTruncated: boolean }> {
  const contentType = headerValue(res.headers["content-type"]);
  if (!isReadableContentType(contentType)) {
    // Drain so the socket is released, but keep nothing.
    await res.body.dump();
    return { body: null, bodyTruncated: false };
  }

  const chunks: Buffer[] = [];
  let total = 0;
  let bodyTruncated = false;

  for await (const chunk of res.body) {
    const buf: Buffer = Buffer.isBuffer(chunk)
      ? chunk
      : Buffer.from(chunk as Uint8Array);

    if (total + buf.length > MAX_BODY_BYTES) {
      chunks.push(buf.subarray(0, MAX_BODY_BYTES - total));
      bodyTruncated = true;
      break;
    }
    chunks.push(buf);
    total += buf.length;
  }

  // Stop pulling the rest of a body we've already capped.
  if (bodyTruncated) res.body.destroy();

  // The cap is byte-based, so a cut can land inside a multi-byte UTF-8
  // character. Drop that trailing partial sequence so it does not decode into a
  // replacement character (the bytes still counted toward the cap).
  const capped = bodyTruncated
    ? trimPartialUtf8(Buffer.concat(chunks))
    : Buffer.concat(chunks);

  return { body: capped.toString("utf8"), bodyTruncated };
}

/**
 * Drop a trailing incomplete UTF-8 sequence from a buffer. A well-formed
 * sequence is a lead byte (0xxxxxxx, or 110/1110/11110xxxx) followed by the
 * right number of continuation bytes (10xxxxxx); if the last sequence is short,
 * remove it so `toString("utf8")` never yields a replacement character.
 */
function trimPartialUtf8(buf: Buffer): Buffer {
  // Walk back over continuation bytes to the lead byte (at most 3 of them).
  let lead = buf.length - 1;
  while (lead >= 0 && (buf[lead]! & 0xc0) === 0x80 && buf.length - lead < 4) {
    lead--;
  }
  if (lead < 0) return buf;

  const first = buf[lead]!;
  const seqLen =
    first < 0x80
      ? 1
      : (first & 0xe0) === 0xc0
        ? 2
        : (first & 0xf0) === 0xe0
          ? 3
          : (first & 0xf8) === 0xf0
            ? 4
            : 1; // invalid lead byte — leave it for toString to handle

  // A complete sequence ends the buffer → keep everything.
  if (buf.length - lead >= seqLen) return buf;
  // Otherwise the trailing sequence is truncated → drop it.
  return buf.subarray(0, lead);
}

/** Only text/html and application/* bodies are worth reading. */
function isReadableContentType(contentType: string | null): boolean {
  if (contentType === null) return false;
  const type = contentType.toLowerCase().trimStart();
  return type.startsWith("text/html") || type.startsWith("application/");
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
