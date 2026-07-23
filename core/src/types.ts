/**
 * Type definitions for the passive external-security scanner core.
 *
 * v1 scope (see CLAUDE.md): HTTP status + redirect chain, SSL/TLS, security
 * headers, passive tech detection, CVE matching, `--json` output.
 *
 * NOTE: `scan()` now populates http, ssl, headers and tech. `cves` is still a
 * placeholder (left `[]`) until that step is implemented.
 */

import type { HeadersResult } from "./headers.js";
import type { SslResult } from "./ssl.js";
import type { TechResult } from "./tech.js";

/** Scanned target: a single domain or IP (scheme optional). */
export type Target = string;

/** Options for a single scan run. */
export interface ScanOptions {
  /** Per-request timeout in milliseconds. Default 30000 (CLAUDE.md). */
  timeoutMs?: number;
  /** Maximum number of redirects to follow. Default 10. */
  maxRedirects?: number;
}

/** A single hop in the redirect chain. */
export interface RedirectHop {
  /** URL the request was sent to. */
  url: string;
  /** Redirect status code (3xx). */
  statusCode: number;
  /** Resolved (absolute) target of the `Location` header. */
  location: string;
}

/**
 * Outcome of the HTTP reachability step. Discriminated union:
 *
 * - `ok`:          a normal HTTP response was received. This INCLUDES 5xx —
 *                  a slow-but-healthy or erroring server is still `ok` with the
 *                  actual `finalStatusCode`. A 5xx is NOT a timeout (CLAUDE.md).
 * - `timeout`:     the request timed out (ETIMEDOUT / ECONNABORTED /
 *                  undici UND_ERR_*_TIMEOUT).
 * - `unreachable`:   the host could not be reached (ENOTFOUND / ECONNRESET /
 *                    ECONNREFUSED / EAI_AGAIN).
 * - `tls_error`:     the TLS handshake / certificate validation failed. Carries
 *                    the raw code plus a human-readable `message`.
 * - `redirect_loop`: the redirect chain exceeded the limit or revisited a URL.
 *                    Carries the chain recorded up to that point.
 */
export type HttpResult =
  | {
      status: "ok";
      finalUrl: string;
      finalStatusCode: number;
      redirectChain: RedirectHop[];
      /**
       * Final response body, capped at 512 KB. `null` when the body was not
       * read — the content-type was not text/html or application/*.
       */
      body: string | null;
      /** True when the body was cut off at the 512 KB cap. */
      bodyTruncated: boolean;
    }
  | {
      status: "timeout";
      errorCode: string;
      redirectChain: RedirectHop[];
    }
  | {
      status: "unreachable";
      errorCode: string;
      redirectChain: RedirectHop[];
    }
  | {
      status: "tls_error";
      errorCode: string;
      /** Human-readable explanation of the TLS failure. */
      message: string;
      redirectChain: RedirectHop[];
    }
  | {
      status: "redirect_loop";
      redirectChain: RedirectHop[];
    };

// The SSL, header and tech results live with their modules; re-export them so
// consumers get everything from `types` / the barrel.
export type { SslResult, HeadersResult, TechResult };

// --- v1 placeholder: typed here, not populated yet ---

/** A CVE matched against a detected product/version. */
export interface CveMatch {
  /** CVE identifier, e.g. `CVE-2021-44228`. */
  id: string;
  product: string;
  version: string;
  /**
   * Always true in v1: the match is based on a banner version and is NOT
   * verified. Distros backport security fixes, so this may be a false positive
   * (CLAUDE.md red line — never claim certainty).
   */
  unverified: true;
  description: string;
}

/** The full, single-shot, stateless scan report. */
export interface ScanResult {
  target: Target;
  /** When the scan ran, ISO 8601. */
  scannedAt: string;
  http: HttpResult;
  /** TLS/certificate result (`not_applicable` for plain-HTTP targets). */
  ssl: SslResult;
  /** Security-header findings, or null when no response body was reached. */
  headers: HeadersResult | null;
  /** Passively detected products; empty when nothing matched. */
  tech: TechResult[];
  /** empty until the CVE step is implemented. */
  cves: CveMatch[];
}
