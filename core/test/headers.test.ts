import { describe, expect, it } from "vitest";

import {
  checkHeaders,
  type HeaderFinding,
  type ResponseHeaders,
} from "../src/headers.js";

/** Grab the finding for a given rule header. */
function find(headers: ResponseHeaders, header: string): HeaderFinding {
  const match = checkHeaders(headers).findings.find((f) => f.header === header);
  if (match === undefined) throw new Error(`no finding for ${header}`);
  return match;
}

describe("checkHeaders", () => {
  it("always emits exactly one finding per rule", () => {
    const result = checkHeaders({});
    expect(result.findings).toHaveLength(6);
    expect(result.findings.map((f) => f.header)).toEqual([
      "strict-transport-security",
      "content-security-policy",
      "x-frame-options",
      "x-content-type-options",
      "referrer-policy",
      "permissions-policy",
    ]);
  });

  describe("strict-transport-security", () => {
    const H = "strict-transport-security";

    it("flags a missing header as high", () => {
      const f = find({}, H);
      expect(f.present).toBe(false);
      expect(f.value).toBeNull();
      expect(f.severity).toBe("high");
    });

    it("flags a max-age below 180 days as medium", () => {
      const f = find({ "strict-transport-security": "max-age=3600" }, H);
      expect(f.severity).toBe("medium");
    });

    it("flags a strong max-age without includeSubDomains as low", () => {
      const f = find({ "strict-transport-security": "max-age=31536000" }, H);
      expect(f.severity).toBe("low");
    });

    it("treats a strong max-age with includeSubDomains as info", () => {
      const f = find(
        { "strict-transport-security": "max-age=31536000; includeSubDomains" },
        H,
      );
      expect(f.severity).toBe("info");
      expect(f.present).toBe(true);
    });
  });

  describe("content-security-policy", () => {
    const H = "content-security-policy";

    it("flags a missing header as medium", () => {
      expect(find({}, H).severity).toBe("medium");
    });

    it("flags unsafe-inline as medium", () => {
      const f = find(
        { "content-security-policy": "default-src 'self' 'unsafe-inline'" },
        H,
      );
      expect(f.severity).toBe("medium");
    });

    it("flags unsafe-eval as medium", () => {
      const f = find(
        { "content-security-policy": "script-src 'unsafe-eval'" },
        H,
      );
      expect(f.severity).toBe("medium");
    });

    it("flags a standalone wildcard source as medium", () => {
      const f = find({ "content-security-policy": "default-src *" }, H);
      expect(f.severity).toBe("medium");
    });

    it("does NOT flag a subdomain wildcard like *.example.com", () => {
      const f = find(
        { "content-security-policy": "default-src 'self'; img-src *.example.com" },
        H,
      );
      expect(f.severity).toBe("info");
    });

    it("treats a strict policy as info", () => {
      const f = find({ "content-security-policy": "default-src 'self'" }, H);
      expect(f.severity).toBe("info");
    });
  });

  describe("clickjacking protection", () => {
    const H = "x-frame-options";

    it("flags the absence of both XFO and frame-ancestors as medium", () => {
      const f = find({}, H);
      expect(f.present).toBe(false);
      expect(f.severity).toBe("medium");
    });

    it("is satisfied by X-Frame-Options", () => {
      const f = find({ "x-frame-options": "DENY" }, H);
      expect(f.present).toBe(true);
      expect(f.severity).toBe("info");
      expect(f.value).toBe("DENY");
    });

    it("is satisfied by CSP frame-ancestors", () => {
      const f = find(
        { "content-security-policy": "frame-ancestors 'none'" },
        H,
      );
      expect(f.present).toBe(true);
      expect(f.severity).toBe("info");
    });
  });

  describe("x-content-type-options", () => {
    const H = "x-content-type-options";

    it("flags a missing header as low", () => {
      expect(find({}, H).severity).toBe("low");
    });

    it("flags a non-nosniff value as low", () => {
      expect(find({ "x-content-type-options": "sniff" }, H).severity).toBe("low");
    });

    it("treats nosniff as info", () => {
      const f = find({ "x-content-type-options": "nosniff" }, H);
      expect(f.severity).toBe("info");
    });
  });

  describe("referrer-policy", () => {
    const H = "referrer-policy";

    it("flags a missing header as low", () => {
      expect(find({}, H).severity).toBe("low");
    });

    it("flags unsafe-url as medium", () => {
      expect(find({ "referrer-policy": "unsafe-url" }, H).severity).toBe("medium");
    });

    it("treats a safe value as info", () => {
      const f = find({ "referrer-policy": "no-referrer" }, H);
      expect(f.severity).toBe("info");
    });
  });

  describe("permissions-policy", () => {
    const H = "permissions-policy";

    it("flags a missing header as low", () => {
      expect(find({}, H).severity).toBe("low");
    });

    it("treats a present header as info", () => {
      const f = find({ "permissions-policy": "geolocation=()" }, H);
      expect(f.severity).toBe("info");
    });
  });

  describe("header normalization", () => {
    it("compares header names case-insensitively", () => {
      const f = find(
        { "Strict-Transport-Security": "max-age=31536000; includeSubDomains" },
        "strict-transport-security",
      );
      expect(f.present).toBe(true);
      expect(f.severity).toBe("info");
    });

    it("handles a header delivered as an array of values", () => {
      const f = find(
        { "x-frame-options": ["DENY", "SAMEORIGIN"] },
        "x-frame-options",
      );
      expect(f.present).toBe(true);
      expect(f.value).toBe("DENY, SAMEORIGIN");
    });
  });
});
