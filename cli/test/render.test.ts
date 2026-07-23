import { describe, expect, it } from "vitest";

import type { CveResult, ScanResult, SslResult, TechResult } from "core";

import {
  renderJson,
  renderText,
  SCHEMA_VERSION,
  toJsonReport,
} from "../src/render.js";

/** A distinctive marker so we can assert the body never leaks into output. */
const SECRET_BODY = "<html>THE-SECRET-BODY-MARKER</html>";

/** An `ok` HTTP result whose body carries the marker above. */
function okResult(overrides: Partial<ScanResult> = {}): ScanResult {
  return {
    target: "example.com",
    scannedAt: "2026-07-24T10:00:00.000Z",
    http: {
      status: "ok",
      finalUrl: "https://example.com/",
      finalStatusCode: 200,
      redirectChain: [],
      body: SECRET_BODY,
      bodyTruncated: false,
    },
    ssl: { status: "not_applicable", reason: "target is HTTP-only" },
    headers: null,
    tech: [],
    cves: [],
    ...overrides,
  };
}

const nginxTech: TechResult = {
  name: "nginx",
  version: "1.24.0",
  confidence: "high",
  evidence: "Server: nginx/1.24.0",
  vendor: "nginx",
  product: "nginx",
};

describe("renderJson", () => {
  it("produces valid JSON with the schema envelope", () => {
    const parsed = JSON.parse(renderJson(okResult())) as Record<string, unknown>;

    expect(parsed["schemaVersion"]).toBe(SCHEMA_VERSION);
    expect(parsed["schemaVersion"]).toBe(1);
    expect(parsed["scannedAt"]).toBe("2026-07-24T10:00:00.000Z");
    expect(parsed["target"]).toBe("example.com");
  });

  it("never serializes the raw body", () => {
    const json = renderJson(okResult());

    // The body content must not appear anywhere in the output.
    expect(json).not.toContain("THE-SECRET-BODY-MARKER");

    const http = toJsonReport(okResult()).http;
    expect(http).not.toHaveProperty("body");
  });

  it("replaces the body with bodyBytes and bodyTruncated", () => {
    const http = toJsonReport(okResult()).http;
    if (http.status !== "ok") throw new Error("expected ok");

    expect(http.bodyBytes).toBe(Buffer.byteLength(SECRET_BODY, "utf8"));
    expect(http.bodyTruncated).toBe(false);
  });

  it("reports bodyBytes 0 when no body was read", () => {
    const result = okResult();
    if (result.http.status !== "ok") throw new Error("expected ok");
    result.http.body = null;

    const http = toJsonReport(result).http;
    if (http.status !== "ok") throw new Error("expected ok");
    expect(http.bodyBytes).toBe(0);
  });

  it("carries the truncated flag through", () => {
    const result = okResult();
    if (result.http.status !== "ok") throw new Error("expected ok");
    result.http.bodyTruncated = true;

    const http = toJsonReport(result).http;
    if (http.status !== "ok") throw new Error("expected ok");
    expect(http.bodyTruncated).toBe(true);
  });

  it("passes a non-ok HTTP result through unchanged (no bodyBytes)", () => {
    const result = okResult({
      http: { status: "timeout", errorCode: "ETIMEDOUT", redirectChain: [] },
    });

    const http = toJsonReport(result).http;
    expect(http.status).toBe("timeout");
    expect(http).not.toHaveProperty("body");
    expect(http).not.toHaveProperty("bodyBytes");
  });

  it("includes tech and cve results in the envelope", () => {
    const cves: CveResult[] = [
      {
        status: "matched",
        name: "nginx",
        version: "1.24.0",
        cpe: "cpe:2.3:a:nginx:nginx:1.24.0:*:*:*:*:*:*:*",
        cves: [
          {
            cveId: "CVE-2023-44487",
            cpe: "cpe:2.3:a:nginx:nginx:1.24.0:*:*:*:*:*:*:*",
            baseScore: 7.5,
            severity: "HIGH",
            publishedDate: "2023-10-10T00:00:00.000",
            description: "desc",
            versionVerified: false,
            note: "based on banner version, unverified",
          },
        ],
      },
    ];
    const report = toJsonReport(okResult({ tech: [nginxTech], cves }));

    expect(report.tech).toHaveLength(1);
    expect(report.cves).toHaveLength(1);
  });
});

describe("renderText", () => {
  it("never prints the raw body, only its size", () => {
    const text = renderText(okResult());

    expect(text).not.toContain("THE-SECRET-BODY-MARKER");
    expect(text).toContain(`Body: ${Buffer.byteLength(SECRET_BODY, "utf8")} bytes`);
  });

  it("marks a truncated body", () => {
    const result = okResult();
    if (result.http.status !== "ok") throw new Error("expected ok");
    result.http.bodyTruncated = true;

    expect(renderText(result)).toContain("(truncated)");
  });

  it("renders every section header", () => {
    const text = renderText(okResult());
    for (const heading of [
      "Scan report for example.com",
      "HTTP",
      "TLS/SSL",
      "Security headers",
      "Technology",
      "CVE",
    ]) {
      expect(text).toContain(heading);
    }
  });

  it("shows HTTP status and final code for an ok result", () => {
    const text = renderText(okResult());
    expect(text).toContain("Status: ok — HTTP 200");
    expect(text).toContain("Final URL: https://example.com/");
  });

  it("renders a timeout result", () => {
    const text = renderText(
      okResult({
        http: { status: "timeout", errorCode: "ETIMEDOUT", redirectChain: [] },
      }),
    );
    expect(text).toContain("Status: timeout (ETIMEDOUT)");
  });

  it("lists TLS validation issues from the flags", () => {
    const ssl: SslResult = {
      status: "ok",
      cert: {
        subjectCN: "example.com",
        san: ["DNS:example.com"],
        issuer: "Test CA",
        validFrom: "2026-01-01T00:00:00.000Z",
        validTo: "2026-12-31T00:00:00.000Z",
        daysRemaining: 160,
        serial: "01",
        signatureAlgorithm: "sha256WithRSAEncryption",
        keyBits: 2048,
        protocol: "TLSv1.3",
      },
      flags: {
        expired: false,
        notYetValid: false,
        selfSigned: true,
        hostnameMismatch: false,
        chainIncomplete: false,
        weakSignature: false,
        weakKey: false,
        deprecatedProtocol: false,
      },
    };
    const text = renderText(okResult({ ssl }));
    expect(text).toContain("Issuer: Test CA");
    expect(text).toContain("selfSigned");
  });

  it("says 'no issues' when no TLS flags are set", () => {
    const ssl: SslResult = {
      status: "ok",
      cert: {
        subjectCN: null,
        san: [],
        issuer: "Test CA",
        validFrom: "2026-01-01T00:00:00.000Z",
        validTo: "2026-12-31T00:00:00.000Z",
        daysRemaining: 160,
        serial: "01",
        signatureAlgorithm: null,
        keyBits: null,
        protocol: "TLSv1.3",
      },
      flags: {
        expired: false,
        notYetValid: false,
        selfSigned: false,
        hostnameMismatch: false,
        chainIncomplete: false,
        weakSignature: false,
        weakKey: false,
        deprecatedProtocol: false,
      },
    };
    expect(renderText(okResult({ ssl }))).toContain("no issues detected");
  });

  it("notes when security headers were not evaluated", () => {
    expect(renderText(okResult({ headers: null }))).toContain(
      "not evaluated",
    );
  });

  it("lists detected technology", () => {
    const text = renderText(okResult({ tech: [nginxTech] }));
    expect(text).toContain("nginx 1.24.0 — high, Server: nginx/1.24.0");
  });

  it("says none detected when there is no tech", () => {
    expect(renderText(okResult({ tech: [] }))).toContain("none detected");
  });

  it("renders each CVE outcome and keeps the unverified note", () => {
    const cves: CveResult[] = [
      {
        status: "matched",
        name: "nginx",
        version: "1.24.0",
        cpe: "cpe",
        cves: [
          {
            cveId: "CVE-2023-1",
            cpe: "cpe",
            baseScore: 9.8,
            severity: "CRITICAL",
            publishedDate: null,
            description: "d",
            versionVerified: false,
            note: "based on banner version, unverified",
          },
        ],
      },
      {
        status: "no_cves",
        name: "PHP",
        version: "8.2.0",
        cpe: "cpe",
        note: "NVD returned no records for this CPE. This does not confirm the product is unaffected — NVD may have no CPE entry for it.",
      },
      {
        status: "version_unknown",
        name: "Laravel",
        version: null,
        reason: "no_cpe_identifier",
        detail: "Laravel has no CPE vendor/product mapping...",
      },
      {
        status: "query_failed",
        name: "Apache",
        version: "2.4.58",
        cpe: "cpe",
        error: "NVD responded with HTTP 503",
      },
    ];
    const text = renderText(okResult({ cves }));

    expect(text).toContain("CVE-2023-1 [CRITICAL, score 9.8]");
    expect(text).toContain("based on banner version, unverified");
    expect(text).toContain("PHP 8.2.0 — NVD returned no records");
    expect(text).toContain("Laravel — not checked");
    expect(text).toContain("Apache 2.4.58 — lookup failed: NVD responded with HTTP 503");
  });

  it("notes when the CVE step produced nothing", () => {
    expect(renderText(okResult({ cves: [] }))).toContain(
      "no lookups performed",
    );
  });
});
