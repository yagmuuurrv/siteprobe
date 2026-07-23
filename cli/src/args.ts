/**
 * CLI argument parsing — a pure function, no I/O (CLAUDE.md: the CLI is a thin
 * shell; `index.ts` does the printing and exiting).
 *
 * The grammar is deliberately tiny (v1 scope): exactly one target plus a
 * handful of flags. The NVD API key is intentionally NOT a flag — it is read
 * from the environment so a secret never lands in shell history.
 */

/** A parse that resolved to "go and scan this target". */
export interface RunArgs {
  kind: "run";
  /** The single domain or IP to scan. */
  target: string;
  /** Emit machine-readable JSON instead of the human report. */
  json: boolean;
  /** Skip the CVE step (maps to `ScanOptions.skipCves`). */
  skipCves: boolean;
}

/** Result of parsing argv. A discriminated union so `index.ts` can switch. */
export type ParsedArgs =
  | RunArgs
  | { kind: "help" }
  | { kind: "version" }
  | { kind: "error"; message: string };

/** Usage line reused in error messages. */
const USAGE = "Usage: scan <domain-or-ip> [--json] [--no-cve]";

/**
 * Parse the argument list (already sliced past `node script`).
 *
 * `--help` / `--version` win over everything else, even a malformed rest, so a
 * confused user always gets help. Any unknown `-flag` is an error rather than
 * being silently treated as a target.
 */
export function parseArgs(argv: string[]): ParsedArgs {
  // First pass: --help / --version win over everything, even a malformed rest,
  // so a confused user always gets help. First occurrence wins by position.
  for (const arg of argv) {
    if (arg === "-h" || arg === "--help") return { kind: "help" };
    if (arg === "-v" || arg === "--version") return { kind: "version" };
  }

  let json = false;
  let skipCves = false;
  const targets: string[] = [];

  for (const arg of argv) {
    switch (arg) {
      case "--json":
        json = true;
        break;
      case "--no-cve":
        skipCves = true;
        break;
      default:
        if (arg.startsWith("-")) {
          return { kind: "error", message: `Unknown option: ${arg}\n${USAGE}` };
        }
        targets.push(arg);
    }
  }

  if (targets.length === 0) {
    return { kind: "error", message: `No target given.\n${USAGE}` };
  }
  if (targets.length > 1) {
    return {
      kind: "error",
      message: `Expected a single target, got ${targets.length}: ${targets.join(", ")}\n${USAGE}`,
    };
  }

  return { kind: "run", target: targets[0]!, json, skipCves };
}
