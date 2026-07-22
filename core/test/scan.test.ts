import { Readable } from "node:stream";

import { afterEach, beforeEach, describe, expect, it, vi } from "vitest";

import { scan } from "../src/scan.js";

// Mock undici so no real network requests are made (CLAUDE.md: network mocked).
vi.mock("undici", () => ({
  request: vi.fn(),
}));

import { request } from "undici";

const requestMock = vi.mocked(request);

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

    // Placeholder fields untouched in this step.
    expect(result.ssl).toBeNull();
    expect(result.headers).toBeNull();
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

    it("truncates a body larger than 512KB", async () => {
      const big = "a".repeat(512 * 1024 + 1000);
      requestMock.mockResolvedValueOnce(
        streamResponse(200, big, "text/html") as never,
      );

      const result = await scan("example.com");

      if (result.http.status !== "ok") throw new Error("expected ok");
      expect(result.http.bodyTruncated).toBe(true);
      expect(result.http.body?.length).toBe(512 * 1024);
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
});
