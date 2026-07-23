# siteprobe

Point it at a domain or IP and get a single, one-shot report on the target's externally visible security posture — HTTP, TLS, security headers, detected technologies, and matching CVEs.

## ⚠️ Two things to read first

**1. Passive only.** siteprobe makes only the requests a normal browser would: it fetches the page, reads the response headers, and completes a TLS handshake. It does **not** scan ports, brute-force directories or subdomains, submit forms, attempt authentication, or run exploits. You are responsible for having a legitimate reason to scan a target.

**2. CVE results are unverified.** CVE matches are derived from the version in the server's banner and are **not confirmed**. Distributions backport security fixes without changing the banner — e.g. Debian/RHEL may ship "nginx 1.18" with the vulnerability already patched while the banner still reads as vulnerable. Every CVE finding is labeled *"based on banner version, unverified"*. Treat it as a lead, not proof.

## Install & run

No install needed:

```
npx siteprobe <domain>
```

## Example

```
npx siteprobe example.com
```

```
Scan report for example.com
Scanned at 2026-07-23T21:12:35.348Z

HTTP
  Status: ok — HTTP 200
  Final URL: https://example.com
  Redirects: 0
  Body: 559 bytes

TLS/SSL
  Issuer: Cloudflare TLS Issuing ECC CA 3
  Subject: example.com
  Valid until: 2026-08-29T21:41:26.000Z (37 days remaining)
  Protocol: TLSv1.3
  Validation issues: chainIncomplete

Security headers
  [high] strict-transport-security: Strict-Transport-Security is missing; connections may be downgraded to plaintext HTTP.
  [medium] content-security-policy: Content-Security-Policy is missing; no policy restricts where resources may load from.
  [medium] x-frame-options: No clickjacking protection: neither X-Frame-Options nor CSP frame-ancestors is set.
  [low] x-content-type-options: X-Content-Type-Options is missing; the browser may MIME-sniff responses.
  [low] referrer-policy: Referrer-Policy is missing; the browser default may leak the full URL to other origins.
  [low] permissions-policy: Permissions-Policy is missing; browser features are not restricted.

Technology
  Cloudflare (version unknown) — high, Server: cloudflare

CVE
  Cloudflare — not checked: Cloudflare was detected but no version could be read, so no CVE lookup was performed.
```

## What it checks

- **HTTP & redirects** — status code and the full redirect chain to the final URL.
- **TLS certificate** — validity, expiry date, issuer, and chain/validation problems.
- **Security headers** — HSTS, CSP, X-Frame-Options, X-Content-Type-Options, Referrer-Policy, Permissions-Policy.
- **Technology & version** — passive fingerprinting from response headers and HTML markers.
- **CVE matching** — detected product/versions are looked up against the NVD database (unverified — see the warning above).

## Flags

| Flag | Description |
| --- | --- |
| `--json` | Output machine-readable JSON instead of the text report. |
| `--no-cve` | Skip the CVE step (no NVD network calls) — useful offline or when rate-limited. |
| `-h`, `--help` | Show help. |
| `-v`, `--version` | Show the version. |

## NVD API key

The CVE step queries the [NVD 2.0 API](https://nvd.nist.gov/developers/vulnerabilities). NVD enforces a strict rate limit: **5 requests per 30 seconds without a key, 50 per 30 seconds with one**. siteprobe spaces its requests to stay within these limits (~6s apart without a key, ~0.6s with one), so a scan of a target with several versioned products can take a while unauthenticated.

Set a key to speed this up:

```
export NVD_API_KEY=your-key-here
npx siteprobe example.com
```

The key is read only from the environment (never a flag), so it doesn't land in your shell history. Get one for free at <https://nvd.nist.gov/developers/request-an-api-key>.

## Status

**v1, work in progress.** The scan engine and CLI are functional; a web interface and further signatures are planned. Interfaces may still change.

## License

[MIT](./LICENSE) © 2026 Yagmur Ceren
