import { describe, it, expect, vi } from "vitest";
import { saveOversizedOutput, MAX_SAVED_OUTPUT_SIZE } from "../output-spill.js";
import { createMockDeps } from "./helpers.js";

describe("saveOversizedOutput", () => {
  it("writes the text to <outputDir>/<name> and reports saved", async () => {
    const deps = createMockDeps({ outputDir: "/output" });
    const r = await saveOversizedOutput(deps.connector, "/output", "pestr-x.txt", "hello");
    expect(r).toEqual({ saved: true, path: "/output/pestr-x.txt" });
    expect(deps.connector.writeFile).toHaveBeenCalledWith("/output/pestr-x.txt", Buffer.from("hello", "utf-8"));
  });

  it("does not write when no output directory is configured", async () => {
    const deps = createMockDeps({ outputDir: "" });
    const r = await saveOversizedOutput(deps.connector, "", "pestr-x.txt", "hello");
    expect(r).toEqual({ saved: false, reason: "no_output_dir" });
    expect(deps.connector.writeFile).not.toHaveBeenCalled();
  });

  it("does not write text over the 500 KiB cap", async () => {
    const deps = createMockDeps({ outputDir: "/output" });
    const r = await saveOversizedOutput(deps.connector, "/output", "big.txt", "x".repeat(MAX_SAVED_OUTPUT_SIZE + 1));
    expect(r).toEqual({ saved: false, reason: "too_large" });
    expect(deps.connector.writeFile).not.toHaveBeenCalled();
  });

  it("degrades to saved:false when the write fails, without throwing", async () => {
    const deps = createMockDeps({ outputDir: "/output" });
    vi.mocked(deps.connector.writeFile).mockRejectedValue(new Error("EACCES"));
    const r = await saveOversizedOutput(deps.connector, "/output", "pestr-x.txt", "hello");
    expect(r).toEqual({ saved: false, reason: "write_failed" });
  });

  it("caps by UTF-8 bytes, not UTF-16 units", async () => {
    const deps = createMockDeps({ outputDir: "/output" });
    // 3 bytes per char in UTF-8: 200K chars = 600 KB > cap although under it in code units
    const r = await saveOversizedOutput(deps.connector, "/output", "x.txt", "\u0800".repeat(200 * 1024));
    expect(r).toEqual({ saved: false, reason: "too_large" });
    expect(deps.connector.writeFile).not.toHaveBeenCalled();
  });

  it("gives up on a write that never settles", async () => {
    const deps = createMockDeps({ outputDir: "/output" });
    vi.mocked(deps.connector.writeFile).mockReturnValue(new Promise(() => {}));
    const r = await saveOversizedOutput(deps.connector, "/output", "x.txt", "hello", { timeoutMs: 20 });
    expect(r).toEqual({ saved: false, reason: "write_failed" });
  });

  it("refuses a name that is not a plain filename", async () => {
    const deps = createMockDeps({ outputDir: "/output" });
    for (const bad of ["../x.txt", "a/b.txt", "", "x y.txt", ".hidden"]) {
      const r = await saveOversizedOutput(deps.connector, "/output", bad, "hello");
      expect(r, bad).toEqual({ saved: false, reason: "bad_name" });
    }
    expect(deps.connector.writeFile).not.toHaveBeenCalled();
  });
});
