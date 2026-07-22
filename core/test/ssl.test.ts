import { describe, expect, it } from "vitest";
import type { DetailedPeerCertificate } from "node:tls";

import {
  checkSsl,
  computeFlags,
  extractCertInfo,
  signatureAlgorithm,
  type SslCertInfo,
} from "../src/ssl.js";

const DAY = 86_400_000;

/** A GMT date string in the form Node's cert `valid_from`/`valid_to` use. */
function gmt(offsetMs: number): string {
  return new Date(Date.now() + offsetMs).toUTCString();
}

/**
 * A healthy leaf certificate chained to a self-signed root: valid dates,
 * matching hostname, complete chain, 2048-bit RSA, SHA-256 signature.
 * Every validation flag should be false for this one.
 */
function healthyCert(
  overrides: Partial<DetailedPeerCertificate> = {},
): DetailedPeerCertificate {
  const root = {
    subject: { CN: "Test Root CA" },
    issuer: { CN: "Test Root CA" },
    raw: Buffer.from([0x30, 0x00]),
  } as unknown as DetailedPeerCertificate;
  // Self-referential issuer, as Node represents a root.
  (root as { issuerCertificate: DetailedPeerCertificate }).issuerCertificate =
    root;

  const leaf = {
    subject: { CN: "example.com" },
    issuer: { CN: "Test Root CA" },
    subjectaltname: "DNS:example.com, DNS:www.example.com",
    valid_from: gmt(-DAY),
    valid_to: gmt(45 * DAY),
    serialNumber: "0A1B2C3D",
    bits: 2048,
    raw: Buffer.from([0x30, 0x00]),
    issuerCertificate: root,
    ...overrides,
  } as unknown as DetailedPeerCertificate;

  return leaf;
}

/** Matching info for a healthy cert (SHA-256 signature). */
function healthyInfo(overrides: Partial<SslCertInfo> = {}): SslCertInfo {
  return {
    subjectCN: "example.com",
    san: ["DNS:example.com"],
    issuer: "Test Root CA",
    validFrom: new Date(Date.now() - DAY).toISOString(),
    validTo: new Date(Date.now() + 45 * DAY).toISOString(),
    daysRemaining: 45,
    serial: "0A1B2C3D",
    signatureAlgorithm: "sha256WithRSAEncryption",
    keyBits: 2048,
    protocol: "TLSv1.2",
    ...overrides,
  };
}

describe("computeFlags", () => {
  it("reports all-clear for a healthy certificate", () => {
    const flags = computeFlags(
      healthyCert(),
      healthyInfo(),
      "TLSv1.2",
      "example.com",
    );

    expect(flags).toEqual({
      expired: false,
      notYetValid: false,
      selfSigned: false,
      hostnameMismatch: false,
      chainIncomplete: false,
      weakSignature: false,
      weakKey: false,
      deprecatedProtocol: false,
    });
  });

  it("flags an expired certificate", () => {
    const cert = healthyCert({ valid_from: gmt(-10 * DAY), valid_to: gmt(-DAY) });
    const flags = computeFlags(cert, healthyInfo(), "TLSv1.2", "example.com");

    expect(flags.expired).toBe(true);
    expect(flags.notYetValid).toBe(false);
  });

  it("flags a not-yet-valid certificate", () => {
    const cert = healthyCert({ valid_from: gmt(DAY), valid_to: gmt(45 * DAY) });
    const flags = computeFlags(cert, healthyInfo(), "TLSv1.2", "example.com");

    expect(flags.notYetValid).toBe(true);
    expect(flags.expired).toBe(false);
  });

  it("flags a self-signed certificate", () => {
    const cert = healthyCert({
      subject: { CN: "example.com" } as DetailedPeerCertificate["subject"],
      issuer: { CN: "example.com" } as DetailedPeerCertificate["issuer"],
    });

    const flags = computeFlags(cert, healthyInfo(), "TLSv1.2", "example.com");

    expect(flags.selfSigned).toBe(true);
  });

  it("flags a hostname mismatch (SAN does not cover the host)", () => {
    const cert = healthyCert({ subjectaltname: "DNS:elsewhere.example" });
    const flags = computeFlags(cert, healthyInfo(), "TLSv1.2", "example.com");

    expect(flags.hostnameMismatch).toBe(true);
  });

  it("does NOT flag a mismatch when the SAN covers the host", () => {
    const cert = healthyCert({ subjectaltname: "DNS:example.com" });
    const flags = computeFlags(cert, healthyInfo(), "TLSv1.2", "example.com");

    expect(flags.hostnameMismatch).toBe(false);
  });

  // Wildcard rules (RFC 6125, via tls.checkServerIdentity): `*.a.com` matches
  // exactly one left-most label.
  it("matches a wildcard SAN against a single sub-label (*.a.com -> b.a.com)", () => {
    const cert = healthyCert({ subjectaltname: "DNS:*.a.com" });
    const flags = computeFlags(cert, healthyInfo(), "TLSv1.2", "b.a.com");

    expect(flags.hostnameMismatch).toBe(false);
  });

  it("does NOT match a wildcard SAN against the bare domain (*.a.com -> a.com)", () => {
    const cert = healthyCert({ subjectaltname: "DNS:*.a.com" });
    const flags = computeFlags(cert, healthyInfo(), "TLSv1.2", "a.com");

    expect(flags.hostnameMismatch).toBe(true);
  });

  it("does NOT match a wildcard SAN across multiple labels (*.a.com -> c.b.a.com)", () => {
    const cert = healthyCert({ subjectaltname: "DNS:*.a.com" });
    const flags = computeFlags(cert, healthyInfo(), "TLSv1.2", "c.b.a.com");

    expect(flags.hostnameMismatch).toBe(true);
  });

  it("honours multiple SAN entries (DNS:a.com, DNS:*.a.com)", () => {
    const cert = healthyCert({ subjectaltname: "DNS:a.com, DNS:*.a.com" });

    expect(
      computeFlags(cert, healthyInfo(), "TLSv1.2", "a.com").hostnameMismatch,
    ).toBe(false);
    expect(
      computeFlags(cert, healthyInfo(), "TLSv1.2", "b.a.com").hostnameMismatch,
    ).toBe(false);
  });

  it("flags an incomplete chain (no issuer available)", () => {
    const cert = healthyCert({
      issuerCertificate: {} as DetailedPeerCertificate,
    });
    const flags = computeFlags(cert, healthyInfo(), "TLSv1.2", "example.com");

    expect(flags.chainIncomplete).toBe(true);
  });

  it("detects a chain that cycles by fingerprint256 (distinct objects, no root)", () => {
    const der = Buffer.from([0x30, 0x00]);
    // leaf -> mid -> leafClone, where leafClone is a DIFFERENT object that
    // shares leaf's fingerprint256. None is self-signed, so only fingerprint
    // dedup stops the walk. Must terminate and report the chain as incomplete.
    const mid = {
      subject: { CN: "Intermediate" },
      issuer: { CN: "Root" },
      subjectaltname: "DNS:example.com",
      fingerprint256: "MID",
      raw: der,
    } as unknown as DetailedPeerCertificate;

    const leafClone = {
      subject: { CN: "example.com" },
      issuer: { CN: "Intermediate" },
      subjectaltname: "DNS:example.com",
      fingerprint256: "LEAF", // same print as the leaf below
      raw: der,
      issuerCertificate: mid,
    } as unknown as DetailedPeerCertificate;
    (mid as { issuerCertificate: DetailedPeerCertificate }).issuerCertificate =
      leafClone;

    const leaf = healthyCert({
      fingerprint256: "LEAF",
      issuerCertificate: mid,
    } as Partial<DetailedPeerCertificate>);

    const flags = computeFlags(leaf, healthyInfo(), "TLSv1.2", "example.com");

    expect(flags.chainIncomplete).toBe(true);
  });

  it("flags a weak (SHA-1) signature", () => {
    const flags = computeFlags(
      healthyCert(),
      healthyInfo({ signatureAlgorithm: "sha1WithRSAEncryption" }),
      "TLSv1.2",
      "example.com",
    );

    expect(flags.weakSignature).toBe(true);
  });

  it("flags a weak (RSA < 2048) key", () => {
    const cert = healthyCert({ bits: 1024 });
    const flags = computeFlags(cert, healthyInfo(), "TLSv1.2", "example.com");

    expect(flags.weakKey).toBe(true);
  });

  it("does NOT flag an EC key as weak despite a small bit count", () => {
    const cert = healthyCert({
      bits: 256,
      nistCurve: "P-256",
    } as Partial<DetailedPeerCertificate>);
    const flags = computeFlags(cert, healthyInfo(), "TLSv1.2", "example.com");

    expect(flags.weakKey).toBe(false);
  });

  it("flags a deprecated protocol (TLSv1.1)", () => {
    const flags = computeFlags(
      healthyCert(),
      healthyInfo(),
      "TLSv1.1",
      "example.com",
    );

    expect(flags.deprecatedProtocol).toBe(true);
  });
});

describe("extractCertInfo", () => {
  it("pulls subject, SAN, issuer, dates and days remaining", () => {
    const info = extractCertInfo(healthyCert(), "TLSv1.3");

    expect(info.subjectCN).toBe("example.com");
    expect(info.san).toEqual(["DNS:example.com", "DNS:www.example.com"]);
    expect(info.issuer).toBe("Test Root CA");
    expect(info.serial).toBe("0A1B2C3D");
    expect(info.keyBits).toBe(2048);
    expect(info.protocol).toBe("TLSv1.3");
    expect(info.daysRemaining).toBeGreaterThanOrEqual(44);
    expect(info.daysRemaining).toBeLessThanOrEqual(45);
  });
});

describe("signatureAlgorithm (DER parse)", () => {
  it("decodes a sha1WithRSAEncryption OID from raw DER", () => {
    // Certificate SEQUENCE { tbs SEQUENCE {}, sigAlg SEQUENCE { OID, NULL } }
    const der = Buffer.from([
      0x30, 0x11, // Certificate
      0x30, 0x00, // tbsCertificate (empty)
      0x30, 0x0d, // signatureAlgorithm
      0x06, 0x09, 0x2a, 0x86, 0x48, 0x86, 0xf7, 0x0d, 0x01, 0x01, 0x05, // OID
      0x05, 0x00, // NULL
    ]);

    expect(signatureAlgorithm(der)).toBe("sha1WithRSAEncryption");
  });

  it("returns null for non-DER input", () => {
    expect(signatureAlgorithm(Buffer.from([0x00, 0x01]))).toBeNull();
    expect(signatureAlgorithm(Buffer.alloc(0))).toBeNull();
  });
});

describe("checkSsl", () => {
  it("returns not_applicable for an HTTP-only target", async () => {
    const result = await checkSsl("example.com", 80, { httpOnly: true });

    expect(result).toEqual({
      status: "not_applicable",
      reason: "target is HTTP-only",
    });
  });
});
