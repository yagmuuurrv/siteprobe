import { afterEach, beforeEach, describe, expect, it, vi } from "vitest";

// The network is mocked; no test in this file may reach the real NVD API.
vi.mock("undici", () => ({
  request: vi.fn(),
}));

import { request } from "undici";

import {
  matchCves,
  NO_CVES_NOTE,
  UNVERIFIED_NOTE,
  type CveEntry,
} from "../src/cve.js";
import type { TechResult } from "../src/tech.js";

const requestMock = vi.mocked(request);

/** A never-waiting sleep, so the rate-limit delays cost nothing in tests. */
const sleepMock = vi.fn<(ms: number) => Promise<void>>();

/** Build a detection; defaults are a fully-identified, versioned product. */
function tech(overrides: Partial<TechResult> = {}): TechResult {
  return {
    name: "nginx",
    version: "1.24.0",
    confidence: "high",
    evidence: "Server: nginx/1.24.0",
    vendor: "nginx",
    product: "nginx",
    ...overrides,
  };
}

/** Build one NVD `vulnerabilities[]` element. */
function vulnerability(
  id: string,
  extra: Record<string, unknown> = {},
): Record<string, unknown> {
  return {
    cve: {
      id,
      published: "2023-10-17T00:15:00.000",
      descriptions: [{ lang: "en", value: `Description of ${id}` }],
      metrics: {
        cvssMetricV31: [
          { cvssData: { baseScore: 9.8, baseSeverity: "CRITICAL" } },
        ],
      },
      ...extra,
    },
  };
}

/** Build a fake undici response carrying an NVD payload. */
function nvdResponse(vulnerabilities: unknown[]) {
  return jsonResponse({ vulnerabilities });
}

function jsonResponse(payload: unknown, statusCode = 200) {
  return {
    statusCode,
    headers: { "content-type": "application/json" },
    body: {
      text: vi.fn().mockResolvedValue(JSON.stringify(payload)),
      dump: vi.fn().mockResolvedValue(undefined),
    },
  };
}

function rawResponse(raw: string, statusCode = 200) {
  return {
    statusCode,
    headers: {},
    body: {
      text: vi.fn().mockResolvedValue(raw),
      dump: vi.fn().mockResolvedValue(undefined),
    },
  };
}

/** The URL the nth request was sent to. */
function requestedUrl(index = 0): string {
  const call = requestMock.mock.calls[index];
  if (call === undefined) throw new Error(`no request at index ${index}`);
  return String(call[0]);
}

/** The headers the nth request was sent with. */
function requestedHeaders(index = 0): Record<string, string> {
  const call = requestMock.mock.calls[index];
  if (call === undefined) throw new Error(`no request at index ${index}`);
  const options = call[1];
  const headers =
    options !== undefined && "headers" in options ? options.headers : {};
  return (headers ?? {}) as Record<string, string>;
}

/** Options every test passes: a stubbed sleep and no ambient API key. */
const BASE_OPTS = { sleep: sleepMock };

let savedApiKey: string | undefined;

beforeEach(() => {
  requestMock.mockReset();
  sleepMock.mockReset();
  sleepMock.mockResolvedValue(undefined);

  // A key in the developer's real environment must not change test behaviour.
  savedApiKey = process.env["NVD_API_KEY"];
  delete process.env["NVD_API_KEY"];
});

afterEach(() => {
  if (savedApiKey === undefined) delete process.env["NVD_API_KEY"];
  else process.env["NVD_API_KEY"] = savedApiKey;
  vi.clearAllMocks();
});

describe("matchCves — rule 1: no version, no query", () => {
  it("never queries a detection without a version", async () => {
    const results = await matchCves([tech({ version: null })], BASE_OPTS);

    expect(requestMock).not.toHaveBeenCalled();
    expect(results).toHaveLength(1);
    expect(results[0]?.status).toBe("version_unknown");
    if (results[0]?.status !== "version_unknown") throw new Error("expected version_unknown");
    expect(results[0].reason).toBe("version_not_detected");
    expect(results[0].detail).toContain("no version");
  });

  it("never queries a detection with no CPE vendor/product", async () => {
    const results = await matchCves(
      [tech({ name: "Laravel", vendor: null, product: null, version: "10.0" })],
      BASE_OPTS,
    );

    expect(requestMock).not.toHaveBeenCalled();
    if (results[0]?.status !== "version_unknown") throw new Error("expected version_unknown");
    expect(results[0].reason).toBe("no_cpe_identifier");
  });

  it("treats a missing vendor as unqueryable even when the product is known", async () => {
    const results = await matchCves(
      [tech({ vendor: null, product: "nginx", version: "1.24.0" })],
      BASE_OPTS,
    );

    expect(requestMock).not.toHaveBeenCalled();
    expect(results[0]?.status).toBe("version_unknown");
  });

  it("makes no request at all when nothing is queryable", async () => {
    await matchCves(
      [tech({ version: null }), tech({ vendor: null })],
      BASE_OPTS,
    );

    expect(requestMock).not.toHaveBeenCalled();
    expect(sleepMock).not.toHaveBeenCalled();
  });
});

describe("matchCves — rule 2: every result is unverified", () => {
  it("marks every entry versionVerified: false with the caveat note", async () => {
    requestMock.mockResolvedValueOnce(
      nvdResponse([vulnerability("CVE-2023-44487"), vulnerability("CVE-2021-23017")]) as never,
    );

    const results = await matchCves([tech()], BASE_OPTS);

    if (results[0]?.status !== "matched") throw new Error("expected matched");
    expect(results[0].cves).toHaveLength(2);
    for (const cve of results[0].cves) {
      expect(cve.versionVerified).toBe(false);
      expect(cve.note).toBe(UNVERIFIED_NOTE);
    }
  });

  it("states the caveat in plain English", () => {
    expect(UNVERIFIED_NOTE).toBe("based on banner version, unverified");
  });
});

describe("matchCves — NVD query", () => {
  it("queries the exact CPE 2.3 string for the detection", async () => {
    requestMock.mockResolvedValueOnce(nvdResponse([]) as never);

    await matchCves([tech()], BASE_OPTS);

    const url = requestedUrl();
    expect(url).toContain("https://services.nvd.nist.gov/rest/json/cves/2.0");
    expect(decodeURIComponent(url)).toContain(
      "cpeName=cpe:2.3:a:nginx:nginx:1.24.0:*:*:*:*:*:*:*",
    );
  });

  it("lower-cases the CPE vendor and product", async () => {
    requestMock.mockResolvedValueOnce(nvdResponse([]) as never);

    await matchCves(
      [tech({ vendor: "Apache", product: "HTTP_Server", version: "2.4.58" })],
      BASE_OPTS,
    );

    expect(decodeURIComponent(requestedUrl())).toContain(
      "cpe:2.3:a:apache:http_server:2.4.58:",
    );
  });

  it("parses id, score, severity, date and description", async () => {
    requestMock.mockResolvedValueOnce(
      nvdResponse([vulnerability("CVE-2023-44487")]) as never,
    );

    const results = await matchCves([tech()], BASE_OPTS);

    if (results[0]?.status !== "matched") throw new Error("expected matched");
    const cve = results[0].cves[0] as CveEntry;
    expect(cve.cveId).toBe("CVE-2023-44487");
    expect(cve.cpe).toBe("cpe:2.3:a:nginx:nginx:1.24.0:*:*:*:*:*:*:*");
    expect(cve.baseScore).toBe(9.8);
    expect(cve.severity).toBe("CRITICAL");
    expect(cve.publishedDate).toBe("2023-10-17T00:15:00.000");
    expect(cve.description).toBe("Description of CVE-2023-44487");
  });

  it("returns no_cves with the not-a-clean-bill note when NVD reports nothing", async () => {
    requestMock.mockResolvedValueOnce(nvdResponse([]) as never);

    const results = await matchCves([tech()], BASE_OPTS);

    if (results[0]?.status !== "no_cves") throw new Error("expected no_cves");
    expect(results[0].note).toBe(NO_CVES_NOTE);
    expect(results[0].note).toContain("does not confirm the product is unaffected");
    expect(results[0].cpe).toBe("cpe:2.3:a:nginx:nginx:1.24.0:*:*:*:*:*:*:*");
  });

  it("returns one result per detection, in input order", async () => {
    requestMock
      .mockResolvedValueOnce(nvdResponse([vulnerability("CVE-1")]) as never)
      .mockResolvedValueOnce(nvdResponse([]) as never);

    const results = await matchCves(
      [
        tech(),
        tech({ name: "PHP", vendor: "php", product: "php", version: "8.2.12" }),
        tech({ name: "Next.js", version: null }),
      ],
      BASE_OPTS,
    );

    expect(results.map((r) => r.name)).toEqual(["nginx", "PHP", "Next.js"]);
    expect(results.map((r) => r.status)).toEqual([
      "matched",
      "no_cves",
      "version_unknown",
    ]);
  });

  describe("CVSS metric selection", () => {
    it("prefers v3.1", async () => {
      requestMock.mockResolvedValueOnce(
        nvdResponse([
          vulnerability("CVE-1", {
            metrics: {
              cvssMetricV31: [{ cvssData: { baseScore: 9.8, baseSeverity: "CRITICAL" } }],
              cvssMetricV2: [{ cvssData: { baseScore: 5 }, baseSeverity: "MEDIUM" }],
            },
          }),
        ]) as never,
      );

      const results = await matchCves([tech()], BASE_OPTS);

      if (results[0]?.status !== "matched") throw new Error("expected matched");
      expect(results[0].cves[0]?.baseScore).toBe(9.8);
      expect(results[0].cves[0]?.severity).toBe("CRITICAL");
    });

    it("falls back to v3.0, then to v2 (whose severity sits on the metric)", async () => {
      requestMock
        .mockResolvedValueOnce(
          nvdResponse([
            vulnerability("CVE-1", {
              metrics: {
                cvssMetricV30: [{ cvssData: { baseScore: 7.5, baseSeverity: "HIGH" } }],
              },
            }),
          ]) as never,
        )
        .mockResolvedValueOnce(
          nvdResponse([
            vulnerability("CVE-2", {
              metrics: {
                cvssMetricV2: [{ cvssData: { baseScore: 5 }, baseSeverity: "MEDIUM" }],
              },
            }),
          ]) as never,
        );

      const [first, second] = await matchCves(
        [tech(), tech({ vendor: "php", product: "php", version: "8.2.12" })],
        BASE_OPTS,
      );

      if (first?.status !== "matched" || second?.status !== "matched") {
        throw new Error("expected both matched");
      }
      expect(first.cves[0]?.severity).toBe("HIGH");
      expect(second.cves[0]?.baseScore).toBe(5);
      expect(second.cves[0]?.severity).toBe("MEDIUM");
    });

    it("reports UNKNOWN with a null score when no metric is published", async () => {
      requestMock.mockResolvedValueOnce(
        nvdResponse([vulnerability("CVE-1", { metrics: {} })]) as never,
      );

      const results = await matchCves([tech()], BASE_OPTS);

      if (results[0]?.status !== "matched") throw new Error("expected matched");
      expect(results[0].cves[0]?.baseScore).toBeNull();
      expect(results[0].cves[0]?.severity).toBe("UNKNOWN");
    });
  });

  describe("description selection", () => {
    it("prefers the English description", async () => {
      requestMock.mockResolvedValueOnce(
        nvdResponse([
          vulnerability("CVE-1", {
            descriptions: [
              { lang: "es", value: "descripción" },
              { lang: "en", value: "the english one" },
            ],
          }),
        ]) as never,
      );

      const results = await matchCves([tech()], BASE_OPTS);

      if (results[0]?.status !== "matched") throw new Error("expected matched");
      expect(results[0].cves[0]?.description).toBe("the english one");
    });

    it("falls back to an empty string when there is no description", async () => {
      requestMock.mockResolvedValueOnce(
        nvdResponse([vulnerability("CVE-1", { descriptions: [] })]) as never,
      );

      const results = await matchCves([tech()], BASE_OPTS);

      if (results[0]?.status !== "matched") throw new Error("expected matched");
      expect(results[0].cves[0]?.description).toBe("");
    });
  });
});

describe("matchCves — rate limiting", () => {
  it("does not pause before the first request", async () => {
    requestMock.mockResolvedValueOnce(nvdResponse([]) as never);

    await matchCves([tech()], BASE_OPTS);

    expect(sleepMock).not.toHaveBeenCalled();
  });

  it("pauses ~6s between requests without an API key", async () => {
    requestMock
      .mockResolvedValueOnce(nvdResponse([]) as never)
      .mockResolvedValueOnce(nvdResponse([]) as never);

    await matchCves(
      [tech(), tech({ vendor: "php", product: "php", version: "8.2.12" })],
      BASE_OPTS,
    );

    expect(sleepMock).toHaveBeenCalledTimes(1);
    expect(sleepMock).toHaveBeenCalledWith(6000);
  });

  it("pauses ~0.6s between requests with an API key", async () => {
    requestMock
      .mockResolvedValueOnce(nvdResponse([]) as never)
      .mockResolvedValueOnce(nvdResponse([]) as never);

    await matchCves(
      [tech(), tech({ vendor: "php", product: "php", version: "8.2.12" })],
      { ...BASE_OPTS, apiKey: "secret-key" },
    );

    expect(sleepMock).toHaveBeenCalledWith(600);
  });

  it("honours an explicit requestDelayMs override", async () => {
    requestMock
      .mockResolvedValueOnce(nvdResponse([]) as never)
      .mockResolvedValueOnce(nvdResponse([]) as never);

    await matchCves(
      [tech(), tech({ vendor: "php", product: "php", version: "8.2.12" })],
      { ...BASE_OPTS, requestDelayMs: 10 },
    );

    expect(sleepMock).toHaveBeenCalledWith(10);
  });

  it("does not pause for skipped detections", async () => {
    requestMock.mockResolvedValueOnce(nvdResponse([]) as never);

    await matchCves([tech({ version: null }), tech()], BASE_OPTS);

    expect(requestMock).toHaveBeenCalledTimes(1);
    expect(sleepMock).not.toHaveBeenCalled();
  });
});

describe("matchCves — API key handling", () => {
  it("sends the apiKey header when a key is given", async () => {
    requestMock.mockResolvedValueOnce(nvdResponse([]) as never);

    await matchCves([tech()], { ...BASE_OPTS, apiKey: "secret-key" });

    expect(requestedHeaders()["apiKey"]).toBe("secret-key");
  });

  it("reads the key from NVD_API_KEY when none is passed", async () => {
    process.env["NVD_API_KEY"] = "env-key";
    requestMock.mockResolvedValueOnce(nvdResponse([]) as never);

    await matchCves([tech()], BASE_OPTS);

    expect(requestedHeaders()["apiKey"]).toBe("env-key");
  });

  it("prefers an explicit key over the environment", async () => {
    process.env["NVD_API_KEY"] = "env-key";
    requestMock.mockResolvedValueOnce(nvdResponse([]) as never);

    await matchCves([tech()], { ...BASE_OPTS, apiKey: "explicit-key" });

    expect(requestedHeaders()["apiKey"]).toBe("explicit-key");
  });

  it("sends no apiKey header when there is no key", async () => {
    requestMock.mockResolvedValueOnce(nvdResponse([]) as never);

    await matchCves([tech()], BASE_OPTS);

    expect(requestedHeaders()["apiKey"]).toBeUndefined();
  });

  it("treats an empty NVD_API_KEY as no key", async () => {
    process.env["NVD_API_KEY"] = "";
    requestMock
      .mockResolvedValueOnce(nvdResponse([]) as never)
      .mockResolvedValueOnce(nvdResponse([]) as never);

    await matchCves(
      [tech(), tech({ vendor: "php", product: "php", version: "8.2.12" })],
      BASE_OPTS,
    );

    expect(requestedHeaders()["apiKey"]).toBeUndefined();
    // ...and it must fall back to the unauthenticated rate limit.
    expect(sleepMock).toHaveBeenCalledWith(6000);
  });
});

describe("matchCves — failures never abort the scan", () => {
  it("reports query_failed for a non-200 NVD response", async () => {
    requestMock.mockResolvedValueOnce(jsonResponse({}, 503) as never);

    const results = await matchCves([tech()], BASE_OPTS);

    if (results[0]?.status !== "query_failed") throw new Error("expected query_failed");
    expect(results[0].error).toContain("503");
    expect(results[0].cpe).toBe("cpe:2.3:a:nginx:nginx:1.24.0:*:*:*:*:*:*:*");
  });

  it("reports query_failed when the request throws", async () => {
    requestMock.mockRejectedValueOnce(new Error("ETIMEDOUT"));

    const results = await matchCves([tech()], BASE_OPTS);

    if (results[0]?.status !== "query_failed") throw new Error("expected query_failed");
    expect(results[0].error).toContain("ETIMEDOUT");
  });

  it("reports query_failed on malformed JSON", async () => {
    requestMock.mockResolvedValueOnce(rawResponse("<html>rate limited</html>") as never);

    const results = await matchCves([tech()], BASE_OPTS);

    expect(results[0]?.status).toBe("query_failed");
  });

  it("reports query_failed when the payload has no vulnerabilities array", async () => {
    requestMock.mockResolvedValueOnce(jsonResponse({ message: "no" }) as never);

    const results = await matchCves([tech()], BASE_OPTS);

    if (results[0]?.status !== "query_failed") throw new Error("expected query_failed");
    expect(results[0].error).toContain("vulnerabilities");
  });

  it("keeps scanning the remaining detections after a failure", async () => {
    requestMock
      .mockRejectedValueOnce(new Error("ECONNRESET"))
      .mockResolvedValueOnce(nvdResponse([vulnerability("CVE-2")]) as never);

    const results = await matchCves(
      [tech(), tech({ name: "PHP", vendor: "php", product: "php", version: "8.2.12" })],
      BASE_OPTS,
    );

    expect(results[0]?.status).toBe("query_failed");
    expect(results[1]?.status).toBe("matched");
  });

  it("skips an unreadable vulnerability entry instead of failing the product", async () => {
    requestMock.mockResolvedValueOnce(
      nvdResponse([
        { cve: { published: "2023-01-01" } }, // no id
        "not an object",
        vulnerability("CVE-2023-44487"),
      ]) as never,
    );

    const results = await matchCves([tech()], BASE_OPTS);

    if (results[0]?.status !== "matched") throw new Error("expected matched");
    expect(results[0].cves.map((c) => c.cveId)).toEqual(["CVE-2023-44487"]);
  });
});

describe("matchCves — caching", () => {
  it("queries a repeated CPE only once", async () => {
    requestMock.mockResolvedValueOnce(
      nvdResponse([vulnerability("CVE-2023-44487")]) as never,
    );

    const results = await matchCves([tech(), tech()], BASE_OPTS);

    expect(requestMock).toHaveBeenCalledTimes(1);
    expect(results[0]?.status).toBe("matched");
    expect(results[1]?.status).toBe("matched");
    // A cache hit costs no rate-limit pause either.
    expect(sleepMock).not.toHaveBeenCalled();
  });

  it("still queries a different version of the same product", async () => {
    requestMock
      .mockResolvedValueOnce(nvdResponse([]) as never)
      .mockResolvedValueOnce(nvdResponse([]) as never);

    await matchCves([tech(), tech({ version: "1.25.0" })], BASE_OPTS);

    expect(requestMock).toHaveBeenCalledTimes(2);
  });

  it("reuses a caller-supplied cache across calls", async () => {
    const cache = new Map<string, CveEntry[]>();
    requestMock.mockResolvedValueOnce(
      nvdResponse([vulnerability("CVE-2023-44487")]) as never,
    );

    await matchCves([tech()], { ...BASE_OPTS, cache });
    const results = await matchCves([tech()], { ...BASE_OPTS, cache });

    expect(requestMock).toHaveBeenCalledTimes(1);
    expect(results[0]?.status).toBe("matched");
    expect(cache.size).toBe(1);
  });

  it("does not cache a failed query", async () => {
    const cache = new Map<string, CveEntry[]>();
    requestMock
      .mockRejectedValueOnce(new Error("ETIMEDOUT"))
      .mockResolvedValueOnce(nvdResponse([vulnerability("CVE-1")]) as never);

    const first = await matchCves([tech()], { ...BASE_OPTS, cache });
    const second = await matchCves([tech()], { ...BASE_OPTS, cache });

    expect(first[0]?.status).toBe("query_failed");
    expect(second[0]?.status).toBe("matched");
    expect(requestMock).toHaveBeenCalledTimes(2);
  });
});
