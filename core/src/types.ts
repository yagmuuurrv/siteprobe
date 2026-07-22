/**
 * Type definitions for the passive external-security scanner core.
 *
 * v1 scope (see CLAUDE.md): HTTP status + redirect chain, SSL/TLS, security
 * headers, passive tech detection, CVE matching, `--json` output.
 *
 * NOTE: In this step only the HTTP part is populated by `scan()`. The `ssl`,
 * `headers`, `tech` and `cves` types are defined here as placeholders for the
 * remaining v1 steps; `scan()` leaves them `null` / `[]` for now.
 */

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

// --- v1 placeholders: typed here, not populated in this step ---

/** SSL/TLS validity result. */
export interface SslResult {
  valid: boolean;
  /** Certificate expiry, ISO 8601. */
  validTo: string;
  issuer: string;
  /** Chain error message, or null when the chain is valid. */
  chainError: string | null;
}

/** Presence/value of the tracked security headers. `null` = header absent. */
export interface SecurityHeaders {
  hsts: string | null;
  csp: string | null;
  xFrameOptions: string | null;
  xContentTypeOptions: string | null;
  referrerPolicy: string | null;
  permissionsPolicy: string | null;
}

/** A passively detected product/version. */
export interface TechDetection {
  name: string;
  /** Detected version, or null when only the product could be identified. */
  version: string | null;
  /** Signal the detection came from. */
  source: "header" | "html";
}

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
  /** null until the SSL step is implemented. */
  ssl: SslResult | null;
  /** null until the headers step is implemented. */
  headers: SecurityHeaders | null;
  /** empty until the tech-detection step is implemented. */
  tech: TechDetection[];
  /** empty until the CVE step is implemented. */
  cves: CveMatch[];
}
