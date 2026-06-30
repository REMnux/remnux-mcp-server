import { describe, it, expect, vi } from "vitest";
import { handleVerifyStringUsage } from "../verify-string-usage.js";
import { createMockDeps, ok, fail, parseEnvelope } from "./helpers.js";
import { R2_MARKERS } from "../../parsers/r2.js";
import type { HandlerDeps } from "../types.js";

const PE = "/samples/x.exe: PE32 executable (GUI) Intel 80386, for MS Windows";
const STR_VADDR = 0x402048;

function izj() {
  return JSON.stringify([{ vaddr: STR_VADDR, section: ".rdata", type: "ascii", string: "secret-marker" }]);
}
/** Build the marked Pass-2 stdout with a given xref array for the queried vaddr. */
function pass2(xrefsJson: string, opts: { version?: boolean } = {}) {
  return [
    opts.version === false ? "" : "radare2 6.1.6 +1 abi:107 @ linux-x86_64",
    R2_MARKERS.sections,
    '[{"name":".text","vaddr":4096,"vsize":512,"perm":"-r-x"},{"name":".rdata","vaddr":8192,"vsize":4096,"perm":"-r--"}]',
    R2_MARKERS.functions,
    '[{"addr":4150,"name":"main","size":20}]',
    `${R2_MARKERS.xref} 0x${STR_VADDR.toString(16)}`,
    xrefsJson,
  ].join("\n");
}
const CODE_XREF = '[{"from":4198,"type":"STRN","fcn_addr":4150,"fcn_name":"main","opcode":"lea rax, str.secret"}]';

function mockConn(
  deps: HandlerDeps,
  opts: { fileType?: string; izjOut?: string; diecOut?: string; pass2Out?: string; r2Missing?: boolean },
) {
  vi.mocked(deps.connector.execute).mockImplementation(async (cmd) => {
    const c = cmd as string[];
    if (c[0] === "test") return ok("", 0);
    if (c[0] === "file") return ok(opts.fileType ?? PE);
    if (c[0] === "diec") return ok(opts.diecOut ?? "{}");
    if (c[0] === "r2") {
      if (opts.r2Missing) return fail("r2: not found", 127);
      const cIdx = c.indexOf("-c");
      const sub = c[cIdx + 1];
      if (sub === "izj" || sub === "izzj") return ok(opts.izjOut ?? izj());
      return ok(opts.pass2Out ?? pass2("[]")); // the analyzed pass
    }
    return ok("");
  });
}

describe("verify_string_usage", () => {
  it("referenced_from_code when an instruction references the string", async () => {
    const deps = createMockDeps();
    mockConn(deps, { pass2Out: pass2(CODE_XREF) });
    const env = parseEnvelope(await handleVerifyStringUsage(deps, { file: "x.exe", query: "secret-marker" }));
    expect(env.success).toBe(true);
    expect(env.data.matches[0].xref_status).toBe("referenced_from_code");
    expect(env.data.matches[0].xref_sources[0].fcn).toBe("main");
  });

  it("no_code_xrefs_detected when analysis is complete and there is no code xref", async () => {
    const deps = createMockDeps();
    mockConn(deps, { pass2Out: pass2("[]") });
    const env = parseEnvelope(await handleVerifyStringUsage(deps, { file: "x.exe", query: "secret-marker" }));
    expect(env.data.matches[0].xref_status).toBe("no_code_xrefs_detected");
    expect(env.data.matches[0].note).toContain("This is NOT evidence the string is unused");
  });

  it("packed binary + no xref → unknown, not a false negative (the invariant, end to end)", async () => {
    const deps = createMockDeps();
    mockConn(deps, { diecOut: JSON.stringify({ detects: [{ values: [{ name: "UPX", type: "Packer" }] }] }), pass2Out: pass2("[]") });
    const env = parseEnvelope(await handleVerifyStringUsage(deps, { file: "x.exe", query: "secret-marker" }));
    expect(env.data.packer_detected).toBe(true);
    expect(env.data.matches[0].xref_status).toBe("unknown");
  });

  it("reports engine_available=false when radare2 is missing (string presence not faked as a negative)", async () => {
    const deps = createMockDeps();
    mockConn(deps, { r2Missing: true });
    const env = parseEnvelope(await handleVerifyStringUsage(deps, { file: "x.exe", query: "secret-marker" }));
    expect(env.data.engine_available).toBe(false);
  });

  it("data_only for a non-code file", async () => {
    const deps = createMockDeps();
    mockConn(deps, { fileType: "/samples/x.bin: data", izjOut: izj() });
    const env = parseEnvelope(await handleVerifyStringUsage(deps, { file: "x.bin", query: "secret-marker" }));
    expect(env.data.is_code_file).toBe(false);
    expect(env.data.matches[0].xref_status).toBe("data_only");
  });

  it("UNKNOWN file type is code-capable, not a confident non-code verdict (H2 regression)", async () => {
    const deps = createMockDeps();
    // The `file` probe returned nothing (timeout/empty stdout); r2 still works and
    // finds a code xref. The handler must NOT short-circuit to data_only ("not an
    // executable, no code references") on a file whose type was never determined.
    mockConn(deps, { fileType: "", pass2Out: pass2(CODE_XREF) });
    const env = parseEnvelope(await handleVerifyStringUsage(deps, { file: "x.exe", query: "secret-marker" }));
    expect(env.data.matches[0].xref_status).not.toBe("data_only");
    expect(env.data.matches[0].xref_status).toBe("referenced_from_code");
  });

  it("match_count 0 when the query is not present", async () => {
    const deps = createMockDeps();
    mockConn(deps, { izjOut: "[]" });
    const env = parseEnvelope(await handleVerifyStringUsage(deps, { file: "x.exe", query: "absent" }));
    expect(env.data.match_count).toBe(0);
  });

  it("errors when query is missing", async () => {
    const deps = createMockDeps();
    mockConn(deps, {});
    const env = parseEnvelope(await handleVerifyStringUsage(deps, { file: "x.exe", query: "" }));
    expect(env.success).toBe(false);
  });
});
