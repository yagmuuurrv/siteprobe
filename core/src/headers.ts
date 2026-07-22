/**
 * Security-header evaluation step.
 *
 * Pure function: it takes the response headers that `scan()` already fetched and
 * returns a flat list of findings. NO network I/O. v1 scope is a finding list
 * only — there is deliberately no score or letter grade (CLAUDE.md).
 */

/** Response headers as delivered by the HTTP client (undici `IncomingHttpHeaders`). */
export type ResponseHeaders = Record<string, string | string[] | undefined>;

export type Severity = "high" | "medium" | "low" | "info";

export interface HeaderFinding {
  /** The header this finding is about (lower-case). */
  header: string;
  present: boolean;
  /** The combined header value, or null when absent. */
  value: string | null;
  severity: Severity;
  /** Short English explanation. */
  finding: string;
}

export interface HeadersResult {
  findings: HeaderFinding[];
}

/** Recommended minimum HSTS max-age: 180 days, in seconds. */
const MIN_HSTS_MAX_AGE = 15_552_000;

/**
 * Evaluate the security headers of a single response.
 *
 * Emits exactly one finding per rule (HSTS, CSP, clickjacking protection,
 * X-Content-Type-Options, Referrer-Policy, Permissions-Policy).
 */
export function checkHeaders(responseHeaders: ResponseHeaders): HeadersResult {
  return {
    findings: [
      hsts(responseHeaders),
      csp(responseHeaders),
      clickjacking(responseHeaders),
      contentTypeOptions(responseHeaders),
      referrerPolicy(responseHeaders),
      permissionsPolicy(responseHeaders),
    ],
  };
}

function hsts(headers: ResponseHeaders): HeaderFinding {
  const header = "strict-transport-security";
  const value = getHeader(headers, header);

  if (value === null) {
    return {
      header,
      present: false,
      value: null,
      severity: "high",
      finding:
        "Strict-Transport-Security is missing; connections may be downgraded to plaintext HTTP.",
    };
  }

  const maxAge = parseMaxAge(value);
  const includesSubdomains = /includeSubDomains/i.test(value);

  if (maxAge === null || maxAge < MIN_HSTS_MAX_AGE) {
    return {
      header,
      present: true,
      value,
      severity: "medium",
      finding: `HSTS max-age is below the recommended ${MIN_HSTS_MAX_AGE} seconds (180 days).`,
    };
  }
  if (!includesSubdomains) {
    return {
      header,
      present: true,
      value,
      severity: "low",
      finding: "HSTS is set but does not cover subdomains (includeSubDomains missing).",
    };
  }
  return {
    header,
    present: true,
    value,
    severity: "info",
    finding: "HSTS is configured with a strong max-age and includeSubDomains.",
  };
}

function csp(headers: ResponseHeaders): HeaderFinding {
  const header = "content-security-policy";
  const value = getHeader(headers, header);

  if (value === null) {
    return {
      header,
      present: false,
      value: null,
      severity: "medium",
      finding:
        "Content-Security-Policy is missing; no policy restricts where resources may load from.",
    };
  }

  const lower = value.toLowerCase();
  const hasUnsafe = /unsafe-inline|unsafe-eval/.test(lower);
  // A standalone `*` source (not `*.example.com`) is overly permissive.
  const hasWildcard = /(^|[\s;])\*([\s;]|$)/.test(value);

  if (hasUnsafe || hasWildcard) {
    return {
      header,
      present: true,
      value,
      severity: "medium",
      finding:
        "CSP is present but weakened by unsafe-inline, unsafe-eval, or a wildcard (*) source.",
    };
  }
  return {
    header,
    present: true,
    value,
    severity: "info",
    finding: "Content-Security-Policy is present.",
  };
}

function clickjacking(headers: ResponseHeaders): HeaderFinding {
  // The rule is satisfied by X-Frame-Options OR a CSP frame-ancestors directive.
  const header = "x-frame-options";
  const xfo = getHeader(headers, header);
  const cspValue = getHeader(headers, "content-security-policy");
  const hasFrameAncestors =
    cspValue !== null && /frame-ancestors/i.test(cspValue);

  if (xfo === null && !hasFrameAncestors) {
    return {
      header,
      present: false,
      value: null,
      severity: "medium",
      finding:
        "No clickjacking protection: neither X-Frame-Options nor CSP frame-ancestors is set.",
    };
  }
  return {
    header,
    present: true,
    value: xfo ?? "CSP frame-ancestors",
    severity: "info",
    finding:
      "Clickjacking protection is present via X-Frame-Options or CSP frame-ancestors.",
  };
}

function contentTypeOptions(headers: ResponseHeaders): HeaderFinding {
  const header = "x-content-type-options";
  const value = getHeader(headers, header);

  if (value === null) {
    return {
      header,
      present: false,
      value: null,
      severity: "low",
      finding: "X-Content-Type-Options is missing; the browser may MIME-sniff responses.",
    };
  }
  if (value.trim().toLowerCase() !== "nosniff") {
    return {
      header,
      present: true,
      value,
      severity: "low",
      finding: "X-Content-Type-Options is present but not set to 'nosniff'.",
    };
  }
  return {
    header,
    present: true,
    value,
    severity: "info",
    finding: "X-Content-Type-Options is set to nosniff.",
  };
}

function referrerPolicy(headers: ResponseHeaders): HeaderFinding {
  const header = "referrer-policy";
  const value = getHeader(headers, header);

  if (value === null) {
    return {
      header,
      present: false,
      value: null,
      severity: "low",
      finding:
        "Referrer-Policy is missing; the browser default may leak the full URL to other origins.",
    };
  }
  if (/unsafe-url/i.test(value)) {
    return {
      header,
      present: true,
      value,
      severity: "medium",
      finding: "Referrer-Policy is set to unsafe-url, which leaks the full URL cross-origin.",
    };
  }
  return {
    header,
    present: true,
    value,
    severity: "info",
    finding: "Referrer-Policy is present.",
  };
}

function permissionsPolicy(headers: ResponseHeaders): HeaderFinding {
  const header = "permissions-policy";
  const value = getHeader(headers, header);

  if (value === null) {
    return {
      header,
      present: false,
      value: null,
      severity: "low",
      finding: "Permissions-Policy is missing; browser features are not restricted.",
    };
  }
  return {
    header,
    present: true,
    value,
    severity: "info",
    finding: "Permissions-Policy is present.",
  };
}

/**
 * Look a header up case-insensitively, folding a repeated header (delivered as
 * an array or under multiple keys) into a single comma-joined value.
 */
function getHeader(headers: ResponseHeaders, name: string): string | null {
  const target = name.toLowerCase();
  const values: string[] = [];

  for (const [key, value] of Object.entries(headers)) {
    if (key.toLowerCase() !== target || value === undefined) continue;
    if (Array.isArray(value)) {
      values.push(...value);
    } else {
      values.push(value);
    }
  }

  return values.length === 0 ? null : values.join(", ");
}

/** Extract the numeric `max-age` directive from an HSTS value. */
function parseMaxAge(value: string): number | null {
  const match = /max-age\s*=\s*"?(\d+)"?/i.exec(value);
  const digits = match?.[1];
  return digits === undefined ? null : Number.parseInt(digits, 10);
}
