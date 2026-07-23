import { defineConfig } from "tsup";

/**
 * Bundle the CLI into a single self-contained file for publishing.
 *
 * `core` is a private, in-repo workspace package, so its code is inlined here;
 * the published `siteprobe` package has no `core` dependency. `undici` stays
 * external — it is a real runtime dependency, installed normally and deduped.
 * Node built-ins (node:tls, node:module, …) are external automatically.
 */
export default defineConfig({
  entry: ["src/index.ts"],
  format: ["esm"],
  target: "node20",
  outDir: "dist",
  clean: true,
  external: ["undici"],
  dts: false,
  // Force dist/index.js so it matches the `bin` path regardless of defaults.
  outExtension() {
    return { js: ".js" };
  },
});
