import { setTimeout as delay } from "node:timers/promises";

import { request } from "undici";

import type { TechResult } from "./tech.js";

/**
 * CVE matching step.
 *
 * Takes the products `detectTech` found and asks the NVD 2.0 API which CVEs are
 * registered against that exact CPE. Two rules govern this module:
 *
 * 1. NO VERSION, NO QUERY. A detection without a version is reported as
 *    `version_unknown` and never queried. Listing every CVE ever filed against a
 *    product — with no version to narrow it — is noise, not a finding.
 *
 * 2. EVERY RESULT IS UNVERIFIED. A banner version cannot see backported
 *    security patches: Debian/RHEL ship "nginx 1.18" with the fix already
 *    applied while the banner still reads vulnerable. So every entry carries
 *    `versionVerified: false` and the `UNVERIFIED_NOTE` text. Nothing in this
 *    module may claim certainty (CLAUDE.md red line).
 *
 * A failing NVD query degrades that one product to `query_failed`; it never
 * aborts the scan.
 */

/** Attached to every CVE entry. Reports must surface this verbatim. */
export const UNVERIFIED_NOTE = "based on banner version, unverified";

/**
 * Attached to a `no_cves` result. An empty NVD response is NOT proof the
 * product is safe — NVD may simply have no CPE record for it. Reports must not
 * turn "no records" into "no vulnerabilities".
 */
export const NO_CVES_NOTE =
  "NVD returned no records for this CPE. This does not confirm the product is unaffected — NVD may have no CPE entry for it.";

/** NVD 2.0 CVE endpoint. */
export const NVD_API_URL = "https://services.nvd.nist.gov/rest/json/cves/2.0";

/** Default per-request timeout in milliseconds (CLAUDE.md: 30s). */
const DEFAULT_TIMEOUT_MS = 30_000;

/**
 * Pause between requests. NVD's published limits are 5 requests per 30 seconds
 * without an API key and 50 per 30 seconds with one; these delays stay just
 * inside both (6000ms → 5/30s, 600ms → 50/30s).
 */
const DELAY_WITHOUT_KEY_MS = 6_000;
const DELAY_WITH_KEY_MS = 600;

/** CVSS severity as NVD reports it, plus a fallback when no metric is present. */
export type CveSeverity =
  | "CRITICAL"
  | "HIGH"
  | "MEDIUM"
  | "LOW"
  | "NONE"
  | "UNKNOWN";

/** Why a detection was not queried. */
export type NotCheckedReason =
  /** Tech detection could not read a version off the banner/markup. */
  | "version_not_detected"
  /** The signature carries no CPE vendor/product, so no CPE can be built. */
  | "no_cpe_identifier";

/** A single CVE reported against a CPE. Never a verified finding — see above. */
export interface CveEntry {
  cveId: string;
  /** The CPE this CVE was matched against. */
  cpe: string;
  /** CVSS base score, or null when NVD published no metric. */
  baseScore: number | null;
  severity: CveSeverity;
  /** Publication date as returned by NVD (ISO 8601), or null. */
  publishedDate: string | null;
  /** English description from NVD. */
  description: string;
  /**
   * ALWAYS false. The match rests on a banner version that may already be
   * patched via a distro backport. There is no code path that sets this true.
   */
  versionVerified: false;
  /** Always `UNVERIFIED_NOTE`; carried so a report cannot drop the caveat. */
  note: typeof UNVERIFIED_NOTE;
}

/** Fields shared by every outcome, identifying which detection it belongs to. */
interface CveResultBase {
  /** Product name as reported by tech detection, e.g. `nginx`. */
  name: string;
  /** Version as detected, or null when none was found. */
  version: string | null;
}

/**
 * Per-detection outcome:
 *
 * - `matched`:          NVD returned at least one CVE for the CPE.
 * - `no_cves`:          the query succeeded and NVD returned nothing.
 * - `version_unknown`:  not queried — see `reason`.
 * - `query_failed`:     the NVD lookup failed. Other detections still ran.
 */
export type CveResult =
  | (CveResultBase & { status: "matched"; cpe: string; cves: CveEntry[] })
  | (CveResultBase & {
      status: "no_cves";
      cpe: string;
      /** Always `NO_CVES_NOTE`; carried so a report cannot read this as "safe". */
      note: typeof NO_CVES_NOTE;
    })
  | (CveResultBase & {
      status: "version_unknown";
      reason: NotCheckedReason;
      /** Human-readable explanation, safe to print in a report. */
      detail: string;
    })
  | (CveResultBase & { status: "query_failed"; cpe: string; error: string });

export interface MatchCvesOptions {
  /** NVD API key. Defaults to `process.env.NVD_API_KEY`; never hard-code one. */
  apiKey?: string;
  /** Per-request timeout in milliseconds. Default 30000. */
  timeoutMs?: number;
  /** Override the inter-request pause. Defaults to the rate-limit-safe value. */
  requestDelayMs?: number;
  /**
   * CPE → entries cache. Pass one in to reuse lookups across calls; a fresh Map
   * is used otherwise. Failed queries are never cached.
   */
  cache?: Map<string, CveEntry[]>;
  /** Injectable pause, so tests do not wait out the real rate limit. */
  sleep?: (ms: number) => Promise<void>;
}

/**
 * Look up CVEs for each detected product, one CPE at a time.
 *
 * Returns one result per input detection, in the same order. Never throws for a
 * network/NVD failure — that detection comes back as `query_failed`.
 */
export async function matchCves(
  tech: TechResult[],
  opts: MatchCvesOptions = {},
): Promise<CveResult[]> {
  const apiKey = opts.apiKey ?? readEnvApiKey();
  const timeoutMs = opts.timeoutMs ?? DEFAULT_TIMEOUT_MS;
  const delayMs =
    opts.requestDelayMs ??
    (apiKey === null ? DELAY_WITHOUT_KEY_MS : DELAY_WITH_KEY_MS);
  const sleep = opts.sleep ?? defaultSleep;
  const cache = opts.cache ?? new Map<string, CveEntry[]>();

  const results: CveResult[] = [];
  // Only real requests are rate-limited; cache hits must not pay the delay.
  let requestsSent = 0;

  for (const item of tech) {
    const skip = reasonToSkip(item);
    if (skip !== null) {
      results.push({
        name: item.name,
        version: item.version,
        status: "version_unknown",
        reason: skip.reason,
        detail: skip.detail,
      });
      continue;
    }

    // `reasonToSkip` guarantees these are non-null.
    const cpe = buildCpe(item.vendor!, item.product!, item.version!);

    const cached = cache.get(cpe);
    if (cached !== undefined) {
      results.push(toResult(item, cpe, cached));
      continue;
    }

    if (requestsSent > 0) await sleep(delayMs);
    requestsSent++;

    try {
      const entries = await queryNvd(cpe, apiKey, timeoutMs);
      cache.set(cpe, entries);
      results.push(toResult(item, cpe, entries));
    } catch (err) {
      // One product's lookup failing must not take the scan down (spec 6).
      results.push({
        name: item.name,
        version: item.version,
        status: "query_failed",
        cpe,
        error: errorMessage(err),
      });
    }
  }

  return results;
}

/** The key from the environment; an unset OR empty variable means "no key". */
function readEnvApiKey(): string | null {
  const key = process.env["NVD_API_KEY"];
  return key === undefined || key === "" ? null : key;
}

/** Whether a detection can be queried at all, and why not when it cannot. */
function reasonToSkip(
  item: TechResult,
): { reason: NotCheckedReason; detail: string } | null {
  if (item.vendor === null || item.product === null) {
    return {
      reason: "no_cpe_identifier",
      detail: `${item.name} has no CPE vendor/product mapping, so no CVE lookup was performed.`,
    };
  }
  if (item.version === null) {
    return {
      reason: "version_not_detected",
      detail: `${item.name} was detected but no version could be read, so no CVE lookup was performed.`,
    };
  }
  return null;
}

/** `matched` when NVD returned entries, `no_cves` when it returned none. */
function toResult(
  item: TechResult,
  cpe: string,
  entries: CveEntry[],
): CveResult {
  const base = { name: item.name, version: item.version };
  return entries.length === 0
    ? { ...base, status: "no_cves", cpe, note: NO_CVES_NOTE }
    : { ...base, status: "matched", cpe, cves: entries };
}

/**
 * Build a CPE 2.3 application URI: 13 components, everything after the version
 * left as a wildcard.
 */
function buildCpe(vendor: string, product: string, version: string): string {
  const parts = [vendor, product, version].map(escapeCpeComponent);
  return `cpe:2.3:a:${parts.join(":")}:*:*:*:*:*:*:*`;
}

/**
 * Escape the CPE 2.3 delimiters inside a component. Our signature data is plain
 * lower-case text, but a stray colon would silently shift every field along.
 */
function escapeCpeComponent(value: string): string {
  return value.toLowerCase().replace(/[\\:]/g, (char) => `\\${char}`);
}

/** Ask NVD for every CVE registered against one CPE. Throws on failure. */
async function queryNvd(
  cpe: string,
  apiKey: string | null,
  timeoutMs: number,
): Promise<CveEntry[]> {
  const url = `${NVD_API_URL}?cpeName=${encodeURIComponent(cpe)}`;

  const headers: Record<string, string> = { accept: "application/json" };
  // NVD expects the key in an `apiKey` header; absent, we run at the low limit.
  if (apiKey !== null) headers["apiKey"] = apiKey;

  const res = await request(url, {
    method: "GET",
    headers,
    headersTimeout: timeoutMs,
    bodyTimeout: timeoutMs,
  });

  if (res.statusCode !== 200) {
    // Drain so the socket is released before we bail out.
    await res.body.dump();
    throw new Error(`NVD responded with HTTP ${res.statusCode}`);
  }

  return parseNvdResponse(await res.body.text(), cpe);
}

/**
 * Parse an NVD 2.0 payload into entries. All external data is narrowed from
 * `unknown` (CLAUDE.md: no `any`). A malformed envelope throws; an individual
 * vulnerability that is unreadable is skipped rather than failing the product.
 */
export function parseNvdResponse(raw: string, cpe: string): CveEntry[] {
  let payload: unknown;
  try {
    payload = JSON.parse(raw);
  } catch (err) {
    throw new Error(`NVD returned malformed JSON: ${errorMessage(err)}`);
  }

  if (!isRecord(payload)) {
    throw new Error("NVD response was not a JSON object");
  }

  const vulnerabilities = payload["vulnerabilities"];
  if (!Array.isArray(vulnerabilities)) {
    throw new Error("NVD response has no `vulnerabilities` array");
  }

  const entries: CveEntry[] = [];
  for (const vulnerability of vulnerabilities) {
    const entry = parseVulnerability(vulnerability, cpe);
    if (entry !== null) entries.push(entry);
  }
  return entries;
}

/** One `vulnerabilities[]` element, or null when it carries no usable CVE id. */
function parseVulnerability(value: unknown, cpe: string): CveEntry | null {
  if (!isRecord(value)) return null;

  const cve = value["cve"];
  if (!isRecord(cve)) return null;

  const cveId = asString(cve["id"]);
  if (cveId === null) return null;

  const metric = readMetric(cve["metrics"]);

  return {
    cveId,
    cpe,
    baseScore: metric.baseScore,
    severity: metric.severity,
    publishedDate: asString(cve["published"]),
    description: readDescription(cve["descriptions"]),
    versionVerified: false,
    note: UNVERIFIED_NOTE,
  };
}

/** Prefer the English description; fall back to the first one, then to "". */
function readDescription(value: unknown): string {
  if (!Array.isArray(value)) return "";

  let fallback = "";
  for (const item of value) {
    if (!isRecord(item)) continue;
    const text = asString(item["value"]);
    if (text === null) continue;

    if (asString(item["lang"]) === "en") return text;
    if (fallback === "") fallback = text;
  }
  return fallback;
}

/**
 * Read the CVSS base score/severity, preferring v3.1, then v3.0, then v2.
 * In the v2 block the severity sits on the metric, not on `cvssData`.
 */
function readMetric(value: unknown): {
  baseScore: number | null;
  severity: CveSeverity;
} {
  const empty = { baseScore: null, severity: "UNKNOWN" as CveSeverity };
  if (!isRecord(value)) return empty;

  for (const key of ["cvssMetricV31", "cvssMetricV30", "cvssMetricV2"]) {
    const list = value[key];
    if (!Array.isArray(list) || list.length === 0) continue;

    const metric = list[0];
    if (!isRecord(metric)) continue;

    const cvssData = isRecord(metric["cvssData"]) ? metric["cvssData"] : {};
    const baseScore = asNumber(cvssData["baseScore"]);
    const severity =
      asString(cvssData["baseSeverity"]) ?? asString(metric["baseSeverity"]);

    return { baseScore, severity: toSeverity(severity) };
  }
  return empty;
}

const SEVERITIES = new Set<CveSeverity>([
  "CRITICAL",
  "HIGH",
  "MEDIUM",
  "LOW",
  "NONE",
]);

/** Narrow an NVD severity string, defaulting to UNKNOWN rather than guessing. */
function toSeverity(value: string | null): CveSeverity {
  if (value === null) return "UNKNOWN";
  const upper = value.toUpperCase();
  return SEVERITIES.has(upper as CveSeverity)
    ? (upper as CveSeverity)
    : "UNKNOWN";
}

function isRecord(value: unknown): value is Record<string, unknown> {
  return typeof value === "object" && value !== null && !Array.isArray(value);
}

function asString(value: unknown): string | null {
  return typeof value === "string" ? value : null;
}

function asNumber(value: unknown): number | null {
  return typeof value === "number" && Number.isFinite(value) ? value : null;
}

/** Readable message for an unknown thrown value (never swallow the error). */
function errorMessage(err: unknown): string {
  if (err instanceof Error) return err.message;
  return String(err);
}

/** Real pause between requests; tests inject their own. */
async function defaultSleep(ms: number): Promise<void> {
  await delay(ms);
}
