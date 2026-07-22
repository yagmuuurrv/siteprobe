import { checkServerIdentity, connect } from "node:tls";
import type { DetailedPeerCertificate } from "node:tls";

/**
 * SSL/TLS inspection step.
 *
 * The point is NOT to reject broken certificates but to READ them: we connect
 * with `rejectUnauthorized: false`, pull the whole chain, and compute the
 * validation flags ourselves so a broken cert still yields a full report.
 *
 * NOTE: this file defines its own `SslResult` (discriminated union). The
 * placeholder `SslResult` in `types.ts` is the old stub and should be
 * reconciled with this one in a later step (per the "only touch ssl.ts"
 * instruction, `types.ts` is left untouched here).
 */

/** Default per-connection timeout in milliseconds (CLAUDE.md: 30s, same as HTTP). */
const DEFAULT_TIMEOUT_MS = 30_000;

const MS_PER_DAY = 86_400_000;

/** Codes that mean the connection timed out. */
const TIMEOUT_CODES = new Set(["ETIMEDOUT"]);

/** Codes that mean the host could not be reached / TLS could not be spoken. */
const UNREACHABLE_CODES = new Set([
  "ENOTFOUND",
  "ECONNREFUSED",
  "ECONNRESET",
  "EAI_AGAIN", // transient DNS failure
  "EPROTO", // TLS protocol failure (e.g. plaintext on the port)
  "EHOSTUNREACH",
  "ENETUNREACH",
]);

export interface CheckSslOptions {
  /** Per-connection timeout in milliseconds. Default 30000. */
  timeoutMs?: number;
  /** When the target is known to be HTTP-only, skip TLS and report not_applicable. */
  httpOnly?: boolean;
}

/** Facts read off the peer certificate / negotiated connection. */
export interface SslCertInfo {
  /** Subject common name, or null when absent. */
  subjectCN: string | null;
  /** Subject alternative names, e.g. `["DNS:example.com", "DNS:www.example.com"]`. */
  san: string[];
  /** Issuer common name (falls back to organization). */
  issuer: string;
  /** Not-before, ISO 8601. */
  validFrom: string;
  /** Not-after, ISO 8601. */
  validTo: string;
  /** Whole days until expiry (negative once expired). */
  daysRemaining: number;
  serial: string;
  /** Signature algorithm (resolved name, or raw OID, or null if unparseable). */
  signatureAlgorithm: string | null;
  /** Public-key size in bits (RSA modulus / DSA), or null for EC / unknown. */
  keyBits: number | null;
  /** Negotiated TLS protocol version, e.g. `"TLSv1.2"`. */
  protocol: string | null;
}

/**
 * Validation flags, computed INDEPENDENTLY of whether the socket was accepted
 * (we never tear the connection down over a bad cert — CLAUDE.md).
 */
export interface SslFlags {
  expired: boolean;
  notYetValid: boolean;
  selfSigned: boolean;
  hostnameMismatch: boolean;
  chainIncomplete: boolean;
  /** SHA-1 (or MD5) based signature. */
  weakSignature: boolean;
  /** RSA key smaller than 2048 bits. */
  weakKey: boolean;
  /** Negotiated TLSv1 or TLSv1.1. */
  deprecatedProtocol: boolean;
}

/** Outcome of the SSL step. Discriminated union. */
export type SslResult =
  | { status: "ok"; cert: SslCertInfo; flags: SslFlags }
  | { status: "unreachable"; errorCode: string }
  | { status: "timeout"; errorCode: string }
  | { status: "not_applicable"; reason: string };

/**
 * Open an SNI TLS connection to `hostname:port`, read the certificate chain and
 * report the certificate facts plus independently-computed validation flags.
 */
export async function checkSsl(
  hostname: string,
  port = 443,
  opts: CheckSslOptions = {},
): Promise<SslResult> {
  if (opts.httpOnly === true) {
    return { status: "not_applicable", reason: "target is HTTP-only" };
  }

  const timeoutMs = opts.timeoutMs ?? DEFAULT_TIMEOUT_MS;

  return await new Promise<SslResult>((resolve, reject) => {
    let settled = false;

    const socket = connect({
      host: hostname,
      port,
      servername: hostname, // SNI
      // Read broken certs too; validation is done by us, not by the socket.
      rejectUnauthorized: false,
    });
    socket.setTimeout(timeoutMs);

    const finish = (result: SslResult): void => {
      if (settled) return;
      settled = true;
      socket.destroy();
      resolve(result);
    };
    const fail = (err: Error): void => {
      if (settled) return;
      settled = true;
      socket.destroy();
      reject(err);
    };

    socket.once("secureConnect", () => {
      const cert = socket.getPeerCertificate(true);
      if (!cert || !Buffer.isBuffer(cert.raw) || cert.raw.length === 0) {
        finish({ status: "unreachable", errorCode: "ERR_NO_PEER_CERT" });
        return;
      }
      const protocol = socket.getProtocol();
      const info = extractCertInfo(cert, protocol);
      const flags = computeFlags(cert, info, protocol, hostname);
      finish({ status: "ok", cert: info, flags });
    });

    socket.once("timeout", () => {
      finish({ status: "timeout", errorCode: "ETIMEDOUT" });
    });

    socket.once("error", (err: NodeJS.ErrnoException) => {
      const code = typeof err.code === "string" ? err.code : null;
      if (code !== null && TIMEOUT_CODES.has(code)) {
        finish({ status: "timeout", errorCode: code });
        return;
      }
      if (
        code !== null &&
        (UNREACHABLE_CODES.has(code) || code.startsWith("ERR_SSL_"))
      ) {
        finish({ status: "unreachable", errorCode: code });
        return;
      }
      // Unknown error: do not swallow (CLAUDE.md).
      fail(err);
    });
  });
}

/** Read the certificate facts off a peer certificate. Pure. */
export function extractCertInfo(
  cert: DetailedPeerCertificate,
  protocol: string | null,
): SslCertInfo {
  const validFrom = new Date(cert.valid_from);
  const validTo = new Date(cert.valid_to);

  return {
    subjectCN: firstString(cert.subject?.CN),
    san: parseSan(cert.subjectaltname),
    issuer: firstString(cert.issuer?.CN) ?? firstString(cert.issuer?.O) ?? "",
    validFrom: validFrom.toISOString(),
    validTo: validTo.toISOString(),
    daysRemaining: Math.floor((validTo.getTime() - Date.now()) / MS_PER_DAY),
    serial: cert.serialNumber ?? "",
    signatureAlgorithm: signatureAlgorithm(cert.raw),
    keyBits: typeof cert.bits === "number" ? cert.bits : null,
    protocol,
  };
}

/**
 * Compute the validation flags from the certificate, its info, the negotiated
 * protocol and the requested hostname. Pure — no I/O, no socket teardown.
 */
export function computeFlags(
  cert: DetailedPeerCertificate,
  info: SslCertInfo,
  protocol: string | null,
  hostname: string,
): SslFlags {
  const now = Date.now();
  const validFrom = new Date(cert.valid_from).getTime();
  const validTo = new Date(cert.valid_to).getTime();

  return {
    expired: now > validTo,
    notYetValid: now < validFrom,
    selfSigned: sameName(cert.subject, cert.issuer),
    // rejectUnauthorized is off, so we must check the hostname ourselves.
    hostnameMismatch: checkServerIdentity(hostname, cert) !== undefined,
    chainIncomplete: !isChainComplete(cert),
    weakSignature: isWeakSignature(info.signatureAlgorithm),
    weakKey: isWeakKey(cert),
    deprecatedProtocol: protocol === "TLSv1" || protocol === "TLSv1.1",
  };
}

/** Node types some cert name fields as `string | string[]`; take the first string. */
function firstString(value: string | string[] | undefined): string | null {
  if (value === undefined) return null;
  return Array.isArray(value) ? (value[0] ?? null) : value;
}

/** Split a `subjectaltname` string into individual entries. */
function parseSan(san: string | undefined): string[] {
  if (san === undefined || san.length === 0) return [];
  return san
    .split(",")
    .map((entry) => entry.trim())
    .filter((entry) => entry.length > 0);
}

/** True when subject and issuer are the same distinguished name (self-signed). */
function sameName(a: unknown, b: unknown): boolean {
  return JSON.stringify(a) === JSON.stringify(b);
}

/**
 * Walk the chain to a self-signed root; incomplete if the chain runs dry first.
 *
 * `getPeerCertificate(true)` returns a CYCLIC structure — the root's
 * `issuerCertificate` points back at itself. We dedup by `fingerprint256` so
 * the same certificate (even as a distinct object instance) is only visited
 * once; the object-identity set is kept as a termination backstop for the rare
 * cert that carries no fingerprint.
 */
function isChainComplete(leaf: DetailedPeerCertificate): boolean {
  let cert: DetailedPeerCertificate | undefined = leaf;
  const seenObjects = new Set<DetailedPeerCertificate>();
  const seenPrints = new Set<string>();

  while (cert !== undefined && hasRaw(cert) && !seenObjects.has(cert)) {
    seenObjects.add(cert);

    const fingerprint = cert.fingerprint256;
    if (typeof fingerprint === "string" && fingerprint.length > 0) {
      if (seenPrints.has(fingerprint)) return false; // cycled without a root
      seenPrints.add(fingerprint);
    }

    if (sameName(cert.subject, cert.issuer)) return true; // reached a root
    const issuerCert: DetailedPeerCertificate | undefined =
      cert.issuerCertificate;
    if (issuerCert === undefined || !hasRaw(issuerCert) || issuerCert === cert) {
      return false;
    }
    cert = issuerCert;
  }
  return false;
}

/** True when the cert object carries actual DER bytes (Node uses `{}` for "missing"). */
function hasRaw(cert: DetailedPeerCertificate | undefined): boolean {
  return cert !== undefined && Buffer.isBuffer(cert.raw) && cert.raw.length > 0;
}

/** RSA keys under 2048 bits are weak; EC keys are not judged by this rule. */
function isWeakKey(cert: DetailedPeerCertificate): boolean {
  const isEc =
    typeof cert.asn1Curve === "string" || typeof cert.nistCurve === "string";
  if (isEc) return false;
  return typeof cert.bits === "number" && cert.bits < 2048;
}

/** SHA-1 / MD5 based signatures are weak. */
function isWeakSignature(algorithm: string | null): boolean {
  if (algorithm === null) return false;
  const a = algorithm.toLowerCase();
  return a.includes("sha1") || a.includes("md5");
}

/** Known signature-algorithm OIDs → human-readable names. */
const SIGNATURE_OIDS: Record<string, string> = {
  "1.2.840.113549.1.1.4": "md5WithRSAEncryption",
  "1.2.840.113549.1.1.5": "sha1WithRSAEncryption",
  "1.2.840.113549.1.1.10": "rsassaPss",
  "1.2.840.113549.1.1.11": "sha256WithRSAEncryption",
  "1.2.840.113549.1.1.12": "sha384WithRSAEncryption",
  "1.2.840.113549.1.1.13": "sha512WithRSAEncryption",
  "1.2.840.10040.4.3": "dsa-with-sha1",
  "1.2.840.10045.4.1": "ecdsa-with-SHA1",
  "1.2.840.10045.4.3.2": "ecdsa-with-SHA256",
  "1.2.840.10045.4.3.3": "ecdsa-with-SHA384",
  "1.2.840.10045.4.3.4": "ecdsa-with-SHA512",
};

/**
 * Extract the certificate's signature algorithm from its raw DER, since Node's
 * cert object does not expose it. Returns the mapped name, the raw OID, or null
 * when the DER can't be walked. Uses a minimal, bounds-checked DER reader.
 */
export function signatureAlgorithm(raw: Buffer | undefined): string | null {
  if (!Buffer.isBuffer(raw) || raw.length === 0) return null;

  // Certificate ::= SEQUENCE { tbsCertificate, signatureAlgorithm, signature }
  const certificate = readTlv(raw, 0);
  if (certificate === null || certificate.tag !== 0x30) return null;

  const tbs = readTlv(raw, certificate.contentStart);
  if (tbs === null) return null;

  const sigAlg = readTlv(raw, tbs.next); // AlgorithmIdentifier SEQUENCE
  if (sigAlg === null || sigAlg.tag !== 0x30) return null;

  const oid = readTlv(raw, sigAlg.contentStart);
  if (oid === null || oid.tag !== 0x06) return null;

  const oidStr = decodeOid(
    raw.subarray(oid.contentStart, oid.contentStart + oid.contentLength),
  );
  return SIGNATURE_OIDS[oidStr] ?? (oidStr.length > 0 ? oidStr : null);
}

interface Tlv {
  tag: number;
  contentStart: number;
  contentLength: number;
  next: number;
}

/** Read one DER TLV at `offset`, or null if it would run past the buffer. */
function readTlv(buf: Buffer, offset: number): Tlv | null {
  if (offset < 0 || offset + 2 > buf.length) return null;

  const tag = buf[offset]!;
  let idx = offset + 1;
  let len = buf[idx]!;
  idx += 1;

  if ((len & 0x80) !== 0) {
    const numBytes = len & 0x7f;
    if (numBytes === 0 || numBytes > 4 || idx + numBytes > buf.length) {
      return null;
    }
    len = 0;
    for (let i = 0; i < numBytes; i++) {
      len = (len << 8) | buf[idx]!;
      idx += 1;
    }
  }

  const next = idx + len;
  if (next > buf.length) return null;
  return { tag, contentStart: idx, contentLength: len, next };
}

/** Decode a DER OID body into dotted-decimal notation. */
function decodeOid(bytes: Buffer): string {
  if (bytes.length === 0) return "";

  const first = bytes[0]!;
  const parts: number[] = [Math.floor(first / 40), first % 40];

  let value = 0;
  for (let i = 1; i < bytes.length; i++) {
    const b = bytes[i]!;
    value = (value << 7) | (b & 0x7f);
    if ((b & 0x80) === 0) {
      parts.push(value);
      value = 0;
    }
  }
  return parts.join(".");
}
