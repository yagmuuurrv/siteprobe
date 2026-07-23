#!/usr/bin/env node
/**
 * CLI entry point — a thin shell over `core` (CLAUDE.md: no business logic
 * here). It parses argv, calls `scan`, prints, and picks an exit code. All the
 * work lives in `core`; all the pure formatting lives in `args`/`render`.
 *
 * Exit codes:
 *   0  the scan completed (including timeout / unreachable — a valid result)
 *   1  an unexpected error while scanning
 *   2  a usage error (bad or missing arguments)
 */

import { createRequire } from "node:module";

import { scan, type ScanOptions } from "core";

import { parseArgs } from "./args.js";
import { renderJson, renderText } from "./render.js";
import { HELP_TEXT } from "./usage.js";

const require = createRequire(import.meta.url);
const pkg = require("../package.json") as { version: string };

async function main(): Promise<number> {
  const parsed = parseArgs(process.argv.slice(2));

  switch (parsed.kind) {
    case "help":
      process.stdout.write(`${HELP_TEXT}\n`);
      return 0;
    case "version":
      process.stdout.write(`${pkg.version}\n`);
      return 0;
    case "error":
      process.stderr.write(`${parsed.message}\n`);
      return 2;
    case "run": {
      // Only set optional fields when true (exactOptionalPropertyTypes).
      const opts: ScanOptions = {};
      if (parsed.skipCves) opts.skipCves = true;

      const result = await scan(parsed.target, opts);
      const output = parsed.json ? renderJson(result) : renderText(result);
      process.stdout.write(`${output}\n`);
      return 0;
    }
  }
}

main()
  .then((code) => {
    process.exitCode = code;
  })
  .catch((err: unknown) => {
    const message = err instanceof Error ? err.message : String(err);
    process.stderr.write(`scan failed: ${message}\n`);
    process.exitCode = 1;
  });
