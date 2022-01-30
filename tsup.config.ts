import type { Options } from "tsup";

export const tsup: Options = {
  splitting: false,
  sourcemap: true,
  clean: true,
  target: "node12",
  entryPoints: ["src/app.ts"],
  format: ["cjs"],
  skipNodeModulesBundle: true,
  outDir: "build",
};
