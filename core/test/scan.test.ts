import { Readable } from "node:stream";

import { afterEach, beforeEach, describe, expect, it, vi } from "vitest";

import { scan } from "../src/scan.js";

// Mock undici and the TLS step so no real network requests are made
// (CLAUDE.md: network mocked). checkHeaders is pure, so it runs for real.
vi.mock("undici", () => ({
  request: vi.fn(),
}));
vi.mock("../src/ssl.js", () => ({
  checkSsl: vi.fn(),
}));

import { request } from "undici";

import { checkSsl } from "../src/ssl.js";

const requestMock = vi.mocked(request);
const checkSslMock = vi.mocked(checkSsl);

/** A canned SSL result the mocked checkSsl returns unless overridden. */
const SSL_STUB = { status: "not_applicable", reason: "mocked" } as const;

/** Build a fake undici response with a drainable body. */
function fakeResponse(
  statusCode: number,
  headers: Record<string, string | string[]> = {},
) {
  return {
    statusCode,
    headers,
    body: { dump: vi.fn().mockResolvedValue(undefined) },
  };
}

/** Build a fake undici response whose body is a real readable stream. */
function streamResponse(
  statusCode: number,
  body: string,
  contentType: string,
) {
  return {
    statusCode,
    headers: { "content-type": contentType },
    body: Readable.from([Buffer.from(body)]),
  };
}

/** Build an error carrying a Node/undici `code`. */
function errorWithCode(code: string): Error {
  return Object.assign(new Error(code), { code });
}

beforeEach(() => {
  requestMock.mockReset();
  checkSslMock.mockReset();
  checkSslMock.mockResolvedValue(SSL_STUB);
});

afterEach(() => {
  vi.clearAllMocks();
});

describe("scan() — HTTP step", () => {
  it("returns ok with the final status code for a simple 200", async () => {
    requestMock.mockResolvedValueOnce(fakeResponse(200) as never);

    const result = await scan("example.com");

    expect(result.target).toBe("example.com");
    expect(result.http.status).toBe("ok");
    if (result.http.status !== "ok") throw new Error("expected ok");
    expect(result.http.finalStatusCode).toBe(200);
    expect(result.http.redirectChain).toEqual([]);
    expect(result.http.finalUrl).toBe("https://example.com");

    // ssl comes from the (mocked) TLS step; headers are evaluated from the
    // response; tech/cves are still placeholders.
    expect(result.ssl).toEqual(SSL_STUB);
    expect(result.headers).not.toBeNull();
    expect(result.tech).toEqual([]);
    expect(result.cves).toEqual([]);
  });

  it("follows a 301 redirect and records the chain", async () => {
    requestMock
      .mockResolvedValueOnce(
        fakeResponse(301, { location: "https://example.com/next" }) as never,
      )
      .mockResolvedValueOnce(fakeResponse(200) as never);

    const result = await scan("https://example.com");

    expect(result.http.status).toBe("ok");
    if (result.http.status !== "ok") throw new Error("expected ok");
    expect(result.http.finalStatusCode).toBe(200);
    expect(result.http.finalUrl).toBe("https://example.com/next");
    expect(result.http.redirectChain).toEqual([
      {
        url: "https://example.com",
        statusCode: 301,
        location: "https://example.com/next",
      },
    ]);
  });

  it("resolves a relative Location against the current URL", async () => {
    requestMock
      .mockResolvedValueOnce(
        fakeResponse(302, { location: "/next" }) as never,
      )
      .mockResolvedValueOnce(fakeResponse(200) as never);

    const result = await scan("https://example.com/start");

    if (result.http.status !== "ok") throw new Error("expected ok");
    expect(result.http.finalUrl).toBe("https://example.com/next");
    expect(result.http.redirectChain[0]?.location).toBe(
      "https://example.com/next",
    );
  });

  it("treats a 5xx as a normal ok result, NOT a timeout", async () => {
    requestMock.mockResolvedValueOnce(fakeResponse(500) as never);

    const result = await scan("example.com");

    expect(result.http.status).toBe("ok");
    if (result.http.status !== "ok") throw new Error("expected ok");
    expect(result.http.finalStatusCode).toBe(500);
  });

  it("classifies ETIMEDOUT as timeout", async () => {
    requestMock.mockRejectedValueOnce(errorWithCode("ETIMEDOUT"));

    const result = await scan("example.com");

    expect(result.http.status).toBe("timeout");
    if (result.http.status !== "timeout") throw new Error("expected timeout");
    expect(result.http.errorCode).toBe("ETIMEDOUT");
  });

  it("classifies an undici timeout code carried on cause", async () => {
    const err = Object.assign(new Error("headers timeout"), {
      code: "UND_ERR_HEADERS_TIMEOUT",
    });
    requestMock.mockRejectedValueOnce(err);

    const result = await scan("example.com");

    expect(result.http.status).toBe("timeout");
  });

  it("classifies ENOTFOUND as unreachable", async () => {
    requestMock.mockRejectedValueOnce(errorWithCode("ENOTFOUND"));

    const result = await scan("does-not-exist.invalid");

    expect(result.http.status).toBe("unreachable");
    if (result.http.status !== "unreachable") {
      throw new Error("expected unreachable");
    }
    expect(result.http.errorCode).toBe("ENOTFOUND");
  });

  it("classifies ECONNRESET as unreachable", async () => {
    requestMock.mockRejectedValueOnce(errorWithCode("ECONNRESET"));

    const result = await scan("example.com");

    expect(result.http.status).toBe("unreachable");
  });

  it("reads the error code from cause when not on the error itself", async () => {
    const wrapped = Object.assign(new Error("socket hang up"), {
      cause: errorWithCode("ECONNREFUSED"),
    });
    requestMock.mockRejectedValueOnce(wrapped);

    const result = await scan("example.com");

    expect(result.http.status).toBe("unreachable");
    if (result.http.status !== "unreachable") {
      throw new Error("expected unreachable");
    }
    expect(result.http.errorCode).toBe("ECONNREFUSED");
  });

  it("rethrows an unknown error instead of swallowing it", async () => {
    requestMock.mockRejectedValueOnce(errorWithCode("EACCES"));

    await expect(scan("example.com")).rejects.toThrow("EACCES");
  });

  it("classifies EAI_AGAIN (transient DNS) as unreachable", async () => {
    requestMock.mockRejectedValueOnce(errorWithCode("EAI_AGAIN"));

    const result = await scan("example.com");

    expect(result.http.status).toBe("unreachable");
    if (result.http.status !== "unreachable") {
      throw new Error("expected unreachable");
    }
    expect(result.http.errorCode).toBe("EAI_AGAIN");
  });

  it("finds the error code deep in the cause chain", async () => {
    const inner = errorWithCode("ECONNRESET");
    const mid = Object.assign(new Error("mid"), { cause: inner });
    const outer = Object.assign(new Error("outer"), { cause: mid });
    requestMock.mockRejectedValueOnce(outer);

    const result = await scan("example.com");

    expect(result.http.status).toBe("unreachable");
    if (result.http.status !== "unreachable") {
      throw new Error("expected unreachable");
    }
    expect(result.http.errorCode).toBe("ECONNRESET");
  });

  describe("TLS errors", () => {
    it("classifies CERT_HAS_EXPIRED as tls_error with a message", async () => {
      requestMock.mockRejectedValueOnce(errorWithCode("CERT_HAS_EXPIRED"));

      const result = await scan("expired.example.com");

      expect(result.http.status).toBe("tls_error");
      if (result.http.status !== "tls_error") {
        throw new Error("expected tls_error");
      }
      expect(result.http.errorCode).toBe("CERT_HAS_EXPIRED");
      expect(result.http.message).toMatch(/expired/i);
    });

    it("classifies ERR_TLS_CERT_ALTNAME_INVALID as tls_error", async () => {
      requestMock.mockRejectedValueOnce(
        errorWithCode("ERR_TLS_CERT_ALTNAME_INVALID"),
      );

      const result = await scan("example.com");

      expect(result.http.status).toBe("tls_error");
      if (result.http.status !== "tls_error") {
        throw new Error("expected tls_error");
      }
      expect(result.http.message).toMatch(/hostname/i);
    });

    it("classifies EPROTO (handshake protocol error) as tls_error", async () => {
      requestMock.mockRejectedValueOnce(errorWithCode("EPROTO"));

      const result = await scan("example.com");

      expect(result.http.status).toBe("tls_error");
    });

    it("finds a TLS code carried on the cause chain", async () => {
      const wrapped = Object.assign(new Error("tls fail"), {
        cause: errorWithCode("SELF_SIGNED_CERT_IN_CHAIN"),
      });
      requestMock.mockRejectedValueOnce(wrapped);

      const result = await scan("example.com");

      expect(result.http.status).toBe("tls_error");
      if (result.http.status !== "tls_error") {
        throw new Error("expected tls_error");
      }
      expect(result.http.errorCode).toBe("SELF_SIGNED_CERT_IN_CHAIN");
    });
  });

  describe("redirect_loop", () => {
    it("returns redirect_loop when the redirect limit is exceeded", async () => {
      // Each hop points to a fresh URL, so only the limit — not a revisit —
      // ends the chain.
      let i = 0;
      requestMock.mockImplementation(async () => {
        i += 1;
        return fakeResponse(302, {
          location: `https://example.com/step-${i}`,
        }) as never;
      });

      const result = await scan("example.com", { maxRedirects: 3 });

      expect(result.http.status).toBe("redirect_loop");
      if (result.http.status !== "redirect_loop") {
        throw new Error("expected redirect_loop");
      }
      // 4 requests (hops 0..3) were recorded before giving up.
      expect(result.http.redirectChain).toHaveLength(4);
    });

    it("returns redirect_loop when a URL repeats before the limit", async () => {
      requestMock
        .mockResolvedValueOnce(
          fakeResponse(302, { location: "https://example.com/b" }) as never,
        )
        .mockResolvedValueOnce(
          fakeResponse(302, { location: "https://example.com/a" }) as never,
        );

      // a -> b -> a : the second /a is a revisit, well under the default 10.
      const result = await scan("https://example.com/a");

      expect(result.http.status).toBe("redirect_loop");
      if (result.http.status !== "redirect_loop") {
        throw new Error("expected redirect_loop");
      }
      expect(result.http.redirectChain).toEqual([
        {
          url: "https://example.com/a",
          statusCode: 302,
          location: "https://example.com/b",
        },
        {
          url: "https://example.com/b",
          statusCode: 302,
          location: "https://example.com/a",
        },
      ]);
    });
  });

  describe("response body", () => {
    it("reads the HTML body of the final response", async () => {
      requestMock.mockResolvedValueOnce(
        streamResponse(200, "<html>hi</html>", "text/html; charset=utf-8") as never,
      );

      const result = await scan("example.com");

      if (result.http.status !== "ok") throw new Error("expected ok");
      expect(result.http.body).toBe("<html>hi</html>");
      expect(result.http.bodyTruncated).toBe(false);
    });

    it("reads an application/* body", async () => {
      requestMock.mockResolvedValueOnce(
        streamResponse(200, '{"a":1}', "application/json") as never,
      );

      const result = await scan("example.com");

      if (result.http.status !== "ok") throw new Error("expected ok");
      expect(result.http.body).toBe('{"a":1}');
    });

    it("does not read a non-text/non-application body", async () => {
      requestMock.mockResolvedValueOnce(
        fakeResponse(200, { "content-type": "image/png" }) as never,
      );

      const result = await scan("example.com");

      if (result.http.status !== "ok") throw new Error("expected ok");
      expect(result.http.body).toBeNull();
      expect(result.http.bodyTruncated).toBe(false);
    });

    it("leaves the body null when there is no content-type", async () => {
      requestMock.mockResolvedValueOnce(fakeResponse(200) as never);

      const result = await scan("example.com");

      if (result.http.status !== "ok") throw new Error("expected ok");
      expect(result.http.body).toBeNull();
    });

    it("truncates a 600KB body to exactly 512KB (bytes)", async () => {
      const big = "a".repeat(600 * 1024); // ASCII: 1 byte == 1 char
      requestMock.mockResolvedValueOnce(
        streamResponse(200, big, "text/html") as never,
      );

      const result = await scan("example.com");

      if (result.http.status !== "ok") throw new Error("expected ok");
      expect(result.http.bodyTruncated).toBe(true);
      expect(result.http.body?.length).toBe(512 * 1024);
      expect(Buffer.byteLength(result.http.body ?? "", "utf8")).toBe(512 * 1024);
    });

    it("does not split a multi-byte UTF-8 character at the cap", async () => {
      // "€" is 3 bytes in UTF-8; 512KB is not a multiple of 3, so a byte-level
      // cut would land mid-character.
      const body = "€".repeat(200 * 1024); // 600K chars -> 1.8 MB, well over cap
      requestMock.mockResolvedValueOnce(
        streamResponse(200, body, "text/html") as never,
      );

      const result = await scan("example.com");

      if (result.http.status !== "ok") throw new Error("expected ok");
      expect(result.http.bodyTruncated).toBe(true);
      // No replacement character from a mid-character cut.
      expect(result.http.body).not.toContain("�");
      // Only whole "€" characters survived.
      expect(result.http.body).toMatch(/^€+$/);
      // Byte length stays within the cap (a few bytes shy after trimming).
      const bytes = Buffer.byteLength(result.http.body ?? "", "utf8");
      expect(bytes).toBeLessThanOrEqual(512 * 1024);
      expect(bytes).toBeGreaterThan(512 * 1024 - 3);
    });

    it("drains redirect bodies and reads only the final one", async () => {
      requestMock
        .mockResolvedValueOnce(
          fakeResponse(301, { location: "https://example.com/final" }) as never,
        )
        .mockResolvedValueOnce(
          streamResponse(200, "<html>final</html>", "text/html") as never,
        );

      const result = await scan("https://example.com");

      if (result.http.status !== "ok") throw new Error("expected ok");
      expect(result.http.finalUrl).toBe("https://example.com/final");
      expect(result.http.body).toBe("<html>final</html>");
    });
  });

  describe("ssl + headers wiring", () => {
    it("runs the TLS step on the target host over port 443 for https", async () => {
      requestMock.mockResolvedValueOnce(fakeResponse(200) as never);

      const result = await scan("example.com");

      expect(checkSslMock).toHaveBeenCalledWith(
        "example.com",
        443,
        expect.any(Object),
      );
      expect(result.ssl).toEqual(SSL_STUB);
    });

    it("marks TLS not_applicable for a plain-HTTP target", async () => {
      requestMock.mockResolvedValueOnce(fakeResponse(200) as never);

      await scan("http://example.com");

      expect(checkSslMock).toHaveBeenCalledWith(
        "example.com",
        443,
        expect.objectContaining({ httpOnly: true }),
      );
    });

    it("evaluates the response headers into findings", async () => {
      requestMock.mockResolvedValueOnce(
        fakeResponse(200, {
          "strict-transport-security": "max-age=31536000; includeSubDomains",
        }) as never,
      );

      const result = await scan("example.com");

      expect(result.headers).not.toBeNull();
      const hsts = result.headers?.findings.find(
        (f) => f.header === "strict-transport-security",
      );
      expect(hsts?.present).toBe(true);
      expect(hsts?.severity).toBe("info");
    });

    it("leaves headers null when no response was reached (timeout)", async () => {
      requestMock.mockRejectedValueOnce(errorWithCode("ETIMEDOUT"));

      const result = await scan("example.com");

      expect(result.http.status).toBe("timeout");
      expect(result.headers).toBeNull();
      // The TLS step is independent and still runs.
      expect(checkSslMock).toHaveBeenCalled();
    });
  });

  describe("tech step", () => {
    it("detects products from the final response headers and body", async () => {
      requestMock.mockResolvedValueOnce({
        statusCode: 200,
        headers: {
          "content-type": "text/html",
          server: "nginx/1.24.0",
        },
        body: Readable.from([
          Buffer.from('<meta name="generator" content="WordPress 6.5.2">'),
        ]),
      } as never);

      // skipCves keeps this focused on the tech step (and avoids the CVE
      // step's real inter-request pause); CVE wiring is covered separately.
      const result = await scan("example.com", { skipCves: true });

      const names = result.tech.map((t) => t.name);
      expect(names).toContain("nginx");
      expect(names).toContain("WordPress");

      const wp = result.tech.find((t) => t.name === "WordPress");
      expect(wp?.version).toBe("6.5.2");
      expect(wp?.confidence).toBe("high");
    });

    it("detects from Set-Cookie even when the body was not read", async () => {
      // No readable content-type → body stays null, but cookies still match.
      requestMock.mockResolvedValueOnce(
        fakeResponse(200, {
          "content-type": "image/png",
          "set-cookie": ["PHPSESSID=abc123; path=/"],
        }) as never,
      );

      const result = await scan("example.com", { skipCves: true });

      if (result.http.status !== "ok") throw new Error("expected ok");
      expect(result.http.body).toBeNull();
      expect(result.tech.map((t) => t.name)).toContain("PHP");
    });

    it("leaves tech empty when no response was reached", async () => {
      requestMock.mockRejectedValueOnce(errorWithCode("ENOTFOUND"));

      const result = await scan("example.com");

      expect(result.http.status).toBe("unreachable");
      expect(result.tech).toEqual([]);
    });

    it("makes no extra request for tech detection", async () => {
      requestMock.mockResolvedValueOnce(
        fakeResponse(200, { server: "nginx/1.24.0" }) as never,
      );

      // skipCves so the only request that could fire is the tech step's (none).
      await scan("example.com", { skipCves: true });

      // Passive only: the already-fetched response is reused (CLAUDE.md).
      expect(requestMock).toHaveBeenCalledTimes(1);
    });
  });

  describe("CVE step", () => {
    /** A response that fingerprints as exactly one queryable product (nginx). */
    function nginxResponse() {
      return fakeResponse(200, { server: "nginx/1.24.0" });
    }

    /** A fake undici response carrying an NVD payload for the CVE lookup. */
    function nvdResponse(vulnerabilities: unknown[]) {
      return {
        statusCode: 200,
        headers: { "content-type": "application/json" },
        body: {
          text: vi
            .fn()
            .mockResolvedValue(JSON.stringify({ vulnerabilities })),
          dump: vi.fn().mockResolvedValue(undefined),
        },
      };
    }

    function vulnerability(id: string) {
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
        },
      };
    }

    it("runs matchCves on the detected tech and fills result.cves", async () => {
      // First request: the page (tech = nginx). Second: the NVD lookup.
      requestMock
        .mockResolvedValueOnce(nginxResponse() as never)
        .mockResolvedValueOnce(
          nvdResponse([vulnerability("CVE-2023-44487")]) as never,
        );

      const result = await scan("example.com");

      expect(requestMock).toHaveBeenCalledTimes(2);
      // The second request went to NVD for the nginx CPE.
      expect(String(requestMock.mock.calls[1]?.[0])).toContain(
        "services.nvd.nist.gov",
      );

      expect(result.cves).toHaveLength(1);
      const cve = result.cves[0];
      if (cve?.status !== "matched") throw new Error("expected matched");
      expect(cve.name).toBe("nginx");
      expect(cve.cves[0]?.cveId).toBe("CVE-2023-44487");
      expect(cve.cves[0]?.versionVerified).toBe(false);
    });

    it("skips the CVE step entirely when skipCves is set", async () => {
      requestMock.mockResolvedValueOnce(nginxResponse() as never);

      const result = await scan("example.com", { skipCves: true });

      // Only the page was fetched; NVD was never contacted.
      expect(requestMock).toHaveBeenCalledTimes(1);
      expect(result.tech.map((t) => t.name)).toContain("nginx");
      expect(result.cves).toEqual([]);
    });

    it("makes no NVD request when no tech was detected", async () => {
      // A bare 200 with no fingerprints → no tech → nothing to look up.
      requestMock.mockResolvedValueOnce(fakeResponse(200) as never);

      const result = await scan("example.com");

      expect(requestMock).toHaveBeenCalledTimes(1);
      expect(result.tech).toEqual([]);
      expect(result.cves).toEqual([]);
    });

    it("makes no NVD request when the host was unreachable", async () => {
      requestMock.mockRejectedValueOnce(errorWithCode("ENOTFOUND"));

      const result = await scan("example.com");

      expect(requestMock).toHaveBeenCalledTimes(1);
      expect(result.cves).toEqual([]);
    });

    it("forwards the NVD API key from options", async () => {
      requestMock
        .mockResolvedValueOnce(nginxResponse() as never)
        .mockResolvedValueOnce(nvdResponse([]) as never);

      await scan("example.com", { nvdApiKey: "secret-key" });

      const nvdCall = requestMock.mock.calls[1];
      const headers = (
        nvdCall?.[1] as { headers?: Record<string, string> } | undefined
      )?.headers;
      expect(headers?.["apiKey"]).toBe("secret-key");
    });
  });
});
