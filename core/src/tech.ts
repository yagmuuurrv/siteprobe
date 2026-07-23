/**
 * Passive technology detection.
 *
 * `detectTech` runs the data-only fingerprints from `signatures.ts` against a
 * response and returns one result per matched product. No network I/O, no HTML
 * parser dependency — regex over the already-fetched response (CLAUDE.md).
 */

import type { ResponseHeaders } from "./headers.js";
import { SIGNATURES, type Signature } from "./signatures.js";

export type Confidence = "high" | "medium" | "low";

export interface TechResult {
  name: string;
  /** Extracted version, or null when none could be inferred. */
  version: string | null;
  confidence: Confidence;
  /** What matched, e.g. `Server: nginx/1.24.0`. */
  evidence: string;
  vendor: string | null;
  product: string | null;
}

/** Which match source produced a hit. */
type MatchSource = "header" | "metaGenerator" | "cookie" | "html" | "scriptSrc";

/**
 * Confidence implied by the KIND of evidence (task spec):
 * high   = the server's own declaration (Server, X-Powered-By, meta generator)
 * medium = a characteristic path or cookie (/wp-content/, PHPSESSID)
 * low    = inferred from a script filename (jquery-3.7.1.min.js)
 */
const CONFIDENCE_BY_SOURCE: Record<MatchSource, Confidence> = {
  header: "high",
  metaGenerator: "high",
  cookie: "medium",
  html: "medium",
  scriptSrc: "low",
};

const RANK: Record<Confidence, number> = { high: 3, medium: 2, low: 1 };

/** Detect technologies from an already-fetched response. */
export function detectTech(
  headers: ResponseHeaders,
  html: string,
  cookies: string[],
): TechResult[] {
  const metaGenerator = extractMetaGenerator(html);
  const scriptSrcs = extractScriptSrcs(html);
  const versionHaystack = buildVersionHaystack(headers, html, cookies);

  const results: TechResult[] = [];
  for (const sig of SIGNATURES) {
    const hit = matchSignature(
      sig,
      headers,
      html,
      cookies,
      metaGenerator,
      scriptSrcs,
    );
    if (hit === null) continue;

    results.push({
      name: sig.name,
      version: extractVersion(sig.versionPatterns, versionHaystack),
      confidence: CONFIDENCE_BY_SOURCE[hit.source],
      evidence: hit.evidence,
      vendor: sig.vendor,
      product: sig.product,
    });
  }
  return results;
}

interface Hit {
  source: MatchSource;
  evidence: string;
}

/** Evaluate every match field; return the highest-confidence hit, or null. */
function matchSignature(
  sig: Signature,
  headers: ResponseHeaders,
  html: string,
  cookies: string[],
  metaGenerator: string | null,
  scriptSrcs: string[],
): Hit | null {
  const hits: Hit[] = [];
  const m = sig.match;

  if (m.header !== undefined) {
    const value = getHeader(headers, m.header.name);
    if (
      value !== null &&
      (m.header.pattern === undefined || m.header.pattern.test(value))
    ) {
      hits.push({ source: "header", evidence: `${m.header.name}: ${value}` });
    }
  }

  if (
    m.metaGenerator !== undefined &&
    metaGenerator !== null &&
    m.metaGenerator.test(metaGenerator)
  ) {
    hits.push({
      source: "metaGenerator",
      evidence: `meta generator: ${metaGenerator}`,
    });
  }

  if (m.cookie !== undefined) {
    for (const cookie of cookies) {
      const cm = m.cookie.exec(cookie);
      if (cm !== null) {
        hits.push({ source: "cookie", evidence: `Cookie: ${cm[0] ?? cookie}` });
        break;
      }
    }
  }

  if (m.scriptSrc !== undefined) {
    for (const src of scriptSrcs) {
      if (m.scriptSrc.test(src)) {
        hits.push({ source: "scriptSrc", evidence: `script src: ${src}` });
        break;
      }
    }
  }

  if (m.html !== undefined) {
    const hm = m.html.exec(html);
    if (hm !== null) {
      hits.push({ source: "html", evidence: `HTML: ${truncate(hm[0] ?? "")}` });
    }
  }

  if (hits.length === 0) return null;

  let best = hits[0]!;
  for (const hit of hits) {
    if (
      RANK[CONFIDENCE_BY_SOURCE[hit.source]] >
      RANK[CONFIDENCE_BY_SOURCE[best.source]]
    ) {
      best = hit;
    }
  }
  return best;
}

/** Case-insensitive header lookup, folding repeats into one comma-joined value. */
function getHeader(headers: ResponseHeaders, name: string): string | null {
  const target = name.toLowerCase();
  const values: string[] = [];

  for (const [key, value] of Object.entries(headers)) {
    if (key.toLowerCase() !== target || value === undefined) continue;
    if (Array.isArray(value)) values.push(...value);
    else values.push(value);
  }
  return values.length === 0 ? null : values.join(", ");
}

/** Pull the `<meta name="generator">` content, whichever attribute order. */
function extractMetaGenerator(html: string): string | null {
  const nameFirst =
    /<meta\s+[^>]*name=["']generator["'][^>]*content=["']([^"']*)["']/i.exec(
      html,
    );
  if (nameFirst !== null && nameFirst[1] !== undefined) return nameFirst[1];

  const contentFirst =
    /<meta\s+[^>]*content=["']([^"']*)["'][^>]*name=["']generator["']/i.exec(
      html,
    );
  if (contentFirst !== null && contentFirst[1] !== undefined) {
    return contentFirst[1];
  }
  return null;
}

/** Collect every `<script src>` URL from the HTML. */
function extractScriptSrcs(html: string): string[] {
  const srcs: string[] = [];
  for (const match of html.matchAll(/<script[^>]+src=["']([^"']+)["']/gi)) {
    if (match[1] !== undefined) srcs.push(match[1]);
  }
  return srcs;
}

/** All the text a version pattern might live in: header values, cookies, HTML. */
function buildVersionHaystack(
  headers: ResponseHeaders,
  html: string,
  cookies: string[],
): string {
  const headerValues: string[] = [];
  for (const value of Object.values(headers)) {
    if (value === undefined) continue;
    if (Array.isArray(value)) headerValues.push(...value);
    else headerValues.push(value);
  }
  return [...headerValues, ...cookies, html].join("\n");
}

/** First version pattern that captures a group wins. */
function extractVersion(patterns: RegExp[], haystack: string): string | null {
  for (const pattern of patterns) {
    const match = pattern.exec(haystack);
    if (match !== null && match[1] !== undefined) return match[1];
  }
  return null;
}

function truncate(text: string, max = 80): string {
  return text.length > max ? `${text.slice(0, max)}…` : text;
}
