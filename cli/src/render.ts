/**
 * Output rendering for the CLI. Pure string producers, no I/O.
 *
 * Two shapes:
 *   renderJson — a stable, machine-readable envelope for CI / scripts.
 *   renderText — a human report for the terminal.
 *
 * The raw response body is NEVER serialized. It can be up to 512 KB of markup
 * and is only an intermediate for tech detection; the report keeps just its
 * size (`bodyBytes`) and whether it was capped (`bodyTruncated`).
 */

import { Buffer } from "node:buffer";

import type {
  CveResult,
  HeadersResult,
  HttpResult,
  RedirectHop,
  ScanResult,
  SslFlags,
  SslResult,
  TechResult,
} from "core";

/** Bumped whenever the JSON envelope changes shape, so consumers can adapt. */
export const SCHEMA_VERSION = 1;

/** The `ok` HTTP result as serialized: body content swapped for its size. */
interface SerializableOkHttp {
  status: "ok";
  finalUrl: string;
  finalStatusCode: number;
  redirectChain: RedirectHop[];
  /** Byte length of the retained body (0 when no body was read). */
  bodyBytes: number;
  /** True when the body hit the 512 KB cap. */
  bodyTruncated: boolean;
}

/** HTTP result as it appears in JSON: `ok` loses its body, others unchanged. */
type SerializableHttp = SerializableOkHttp | Exclude<HttpResult, { status: "ok" }>;

/** The top-level JSON envelope. */
export interface JsonReport {
  /** Envelope version. Consumers should check this before parsing. */
  schemaVersion: typeof SCHEMA_VERSION;
  /** When the scan ran (ISO 8601). */
  scannedAt: string;
  target: string;
  http: SerializableHttp;
  ssl: SslResult;
  headers: HeadersResult | null;
  tech: TechResult[];
  cves: CveResult[];
}

/** Replace an `ok` result's body with its byte size; pass others through. */
function stripBody(http: HttpResult): SerializableHttp {
  if (http.status !== "ok") return http;

  const { body, bodyTruncated, ...rest } = http;
  return {
    ...rest,
    bodyBytes: body === null ? 0 : Buffer.byteLength(body, "utf8"),
    bodyTruncated,
  };
}

/** Build the JSON envelope from a scan result (body stripped). */
export function toJsonReport(result: ScanResult): JsonReport {
  return {
    schemaVersion: SCHEMA_VERSION,
    scannedAt: result.scannedAt,
    target: result.target,
    http: stripBody(result.http),
    ssl: result.ssl,
    headers: result.headers,
    tech: result.tech,
    cves: result.cves,
  };
}

/** Machine-readable report: the JSON envelope, pretty-printed. */
export function renderJson(result: ScanResult): string {
  return JSON.stringify(toJsonReport(result), null, 2);
}

/** Human-readable report for the terminal. */
export function renderText(result: ScanResult): string {
  const lines: string[] = [
    `Scan report for ${result.target}`,
    `Scanned at ${result.scannedAt}`,
    "",
    ...httpSection(result.http),
    "",
    ...sslSection(result.ssl),
    "",
    ...headersSection(result.headers),
    "",
    ...techSection(result.tech),
    "",
    ...cveSection(result.cves),
  ];
  return lines.join("\n");
}

function httpSection(http: HttpResult): string[] {
  const out = ["HTTP"];
  switch (http.status) {
    case "ok": {
      out.push(`  Status: ok — HTTP ${http.finalStatusCode}`);
      out.push(`  Final URL: ${http.finalUrl}`);
      out.push(`  Redirects: ${http.redirectChain.length}`);
      for (const hop of http.redirectChain) out.push(`    ${redirectLine(hop)}`);
      const size = http.body === null ? 0 : Buffer.byteLength(http.body, "utf8");
      out.push(`  Body: ${size} bytes${http.bodyTruncated ? " (truncated)" : ""}`);
      return out;
    }
    case "timeout":
      out.push(`  Status: timeout (${http.errorCode})`);
      return out;
    case "unreachable":
      out.push(`  Status: unreachable (${http.errorCode})`);
      return out;
    case "tls_error":
      out.push(`  Status: TLS error (${http.errorCode}) — ${http.message}`);
      return out;
    case "redirect_loop":
      out.push(`  Status: redirect loop (${http.redirectChain.length} hops)`);
      for (const hop of http.redirectChain) out.push(`    ${redirectLine(hop)}`);
      return out;
  }
}

function redirectLine(hop: RedirectHop): string {
  return `${hop.statusCode} ${hop.url} -> ${hop.location}`;
}

function sslSection(ssl: SslResult): string[] {
  const out = ["TLS/SSL"];
  switch (ssl.status) {
    case "ok": {
      const { cert, flags } = ssl;
      out.push(`  Issuer: ${cert.issuer || "(unknown)"}`);
      if (cert.subjectCN !== null) out.push(`  Subject: ${cert.subjectCN}`);
      out.push(`  Valid until: ${cert.validTo} (${cert.daysRemaining} days remaining)`);
      if (cert.protocol !== null) out.push(`  Protocol: ${cert.protocol}`);

      const problems = flagProblems(flags);
      out.push(
        problems.length === 0
          ? "  Validation: no issues detected"
          : `  Validation issues: ${problems.join(", ")}`,
      );
      return out;
    }
    case "timeout":
      out.push(`  timeout (${ssl.errorCode})`);
      return out;
    case "unreachable":
      out.push(`  unreachable (${ssl.errorCode})`);
      return out;
    case "not_applicable":
      out.push(`  not applicable — ${ssl.reason}`);
      return out;
  }
}

/** Names of the validation flags that are set to true. */
function flagProblems(flags: SslFlags): string[] {
  return Object.entries(flags)
    .filter(([, on]) => on)
    .map(([name]) => name);
}

function headersSection(headers: HeadersResult | null): string[] {
  if (headers === null) {
    return ["Security headers", "  not evaluated (no response body reached)"];
  }
  const out = ["Security headers"];
  for (const f of headers.findings) {
    out.push(`  [${f.severity}] ${f.header}: ${f.finding}`);
  }
  return out;
}

function techSection(tech: TechResult[]): string[] {
  if (tech.length === 0) return ["Technology", "  none detected"];

  const out = ["Technology"];
  for (const t of tech) {
    const version = t.version ?? "(version unknown)";
    out.push(`  ${t.name} ${version} — ${t.confidence}, ${t.evidence}`);
  }
  return out;
}

function cveSection(cves: CveResult[]): string[] {
  if (cves.length === 0) {
    return ["CVE", "  no lookups performed (step skipped or no products to check)"];
  }

  const out = ["CVE"];
  for (const result of cves) {
    switch (result.status) {
      case "matched": {
        out.push(`  ${result.name} ${result.version} — ${result.cves.length} CVE(s):`);
        for (const cve of result.cves) {
          const score = cve.baseScore === null ? "n/a" : String(cve.baseScore);
          out.push(`    ${cve.cveId} [${cve.severity}, score ${score}] — ${cve.note}`);
        }
        break;
      }
      case "no_cves":
        out.push(`  ${result.name} ${result.version} — ${result.note}`);
        break;
      case "version_unknown":
        out.push(`  ${result.name} — not checked: ${result.detail}`);
        break;
      case "query_failed":
        out.push(`  ${result.name} ${result.version} — lookup failed: ${result.error}`);
        break;
    }
  }
  return out;
}
