import { describe, expect, it } from "vitest";

import { parseArgs, type RunArgs } from "../src/args.js";

/** Parse and assert it resolved to a `run`, returning the narrowed value. */
function run(argv: string[]): RunArgs {
  const parsed = parseArgs(argv);
  if (parsed.kind !== "run") {
    throw new Error(`expected run, got ${parsed.kind}`);
  }
  return parsed;
}

describe("parseArgs", () => {
  it("parses a bare target with defaults", () => {
    const args = run(["example.com"]);
    expect(args.target).toBe("example.com");
    expect(args.json).toBe(false);
    expect(args.skipCves).toBe(false);
  });

  it("accepts an IP or a full URL as the target", () => {
    expect(run(["203.0.113.5"]).target).toBe("203.0.113.5");
    expect(run(["https://example.com/path"]).target).toBe(
      "https://example.com/path",
    );
  });

  it("sets json on --json", () => {
    expect(run(["--json", "example.com"]).json).toBe(true);
    // Flag order does not matter.
    expect(run(["example.com", "--json"]).json).toBe(true);
  });

  it("sets skipCves on --no-cve", () => {
    expect(run(["example.com", "--no-cve"]).skipCves).toBe(true);
  });

  it("accepts all flags together", () => {
    const args = run(["--json", "--no-cve", "example.com"]);
    expect(args.json).toBe(true);
    expect(args.skipCves).toBe(true);
    expect(args.target).toBe("example.com");
  });

  describe("help and version", () => {
    it("returns help for -h / --help", () => {
      expect(parseArgs(["-h"]).kind).toBe("help");
      expect(parseArgs(["--help"]).kind).toBe("help");
    });

    it("returns version for -v / --version", () => {
      expect(parseArgs(["-v"]).kind).toBe("version");
      expect(parseArgs(["--version"]).kind).toBe("version");
    });

    it("lets --help win over an otherwise invalid argument list", () => {
      // No target and an unknown flag, but help still comes back.
      expect(parseArgs(["--bogus", "--help"]).kind).toBe("help");
      expect(parseArgs(["--help", "a", "b"]).kind).toBe("help");
    });
  });

  describe("errors", () => {
    it("errors when no target is given", () => {
      const parsed = parseArgs([]);
      expect(parsed.kind).toBe("error");
      if (parsed.kind !== "error") throw new Error("expected error");
      expect(parsed.message).toContain("No target");
      expect(parsed.message).toContain("Usage:");
    });

    it("errors when only flags are given", () => {
      expect(parseArgs(["--json"]).kind).toBe("error");
    });

    it("errors on an unknown option", () => {
      const parsed = parseArgs(["--wat", "example.com"]);
      if (parsed.kind !== "error") throw new Error("expected error");
      expect(parsed.message).toContain("Unknown option: --wat");
    });

    it("errors on more than one target", () => {
      const parsed = parseArgs(["a.com", "b.com"]);
      if (parsed.kind !== "error") throw new Error("expected error");
      expect(parsed.message).toContain("single target");
      expect(parsed.message).toContain("a.com, b.com");
    });
  });
});
