/** Static help text printed for `--help`. */
export const HELP_TEXT = `scan — passive external security report for a single domain or IP

Usage:
  scan <domain-or-ip> [options]

Options:
  --json         Output machine-readable JSON instead of the text report
  --no-cve       Skip the CVE lookup step (no NVD network calls)
  -h, --help     Show this help
  -v, --version  Show the version

Environment:
  NVD_API_KEY    NVD API key for the CVE step (optional; raises the rate limit)

Notes:
  Passive only: the scan makes the requests a normal browser would — it never
  probes ports, brute-forces paths, or sends exploits. CVE matches are based on
  banner versions and are unverified (distros backport fixes).`;
