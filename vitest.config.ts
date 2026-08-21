import { defineConfig } from "vitest/config";

export default defineConfig({
  test: {
    // Collect ONLY from src/. vitest 1 did not pick up the compiled copies in
    // dist/, but vitest 4's default exclude no longer covers them, so an
    // unscoped run collects every test twice (146 files / 1928 tests instead of
    // 73 / 964) and reports failures from stale build output.
    include: ["src/**/*.{test,spec}.?(c|m)[jt]s?(x)"],
    exclude: ["**/node_modules/**", "dist/**", "demos/**"],
  },
});
