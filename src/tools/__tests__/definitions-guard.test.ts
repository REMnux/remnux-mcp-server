import { describe, it, expect } from "vitest";
import { TOOL_DEFINITIONS } from "../definitions.js";
import { buildInvocationTemplate } from "../invoker.js";

/**
 * Guards that lock the two bug classes shut so they can't silently regress:
 *  - Issue #2: no tool definition may embed a hardcoded /tmp path.
 *  - Issue #1: the model-facing invocation must surface the real command,
 *    never the internal registry name.
 */
describe("tool definition guards", () => {
  it("no definition embeds a hardcoded /tmp path (use the %OUTPUT% sentinel)", () => {
    for (const def of TOOL_DEFINITIONS) {
      for (const arg of [...(def.fixedArgs ?? []), ...(def.suffixArgs ?? [])]) {
        expect(arg, `${def.name} arg "${arg}"`).not.toContain("/tmp");
      }
    }
  });

  it("surfaced invocation starts with the real command, never the registry name", () => {
    for (const def of TOOL_DEFINITIONS) {
      const firstToken = buildInvocationTemplate(def).split(" ")[0];
      expect(firstToken, `invocation for ${def.name}`).toBe(def.command);
      if (def.name !== def.command) {
        expect(firstToken).not.toBe(def.name);
      }
    }
  });

  it("invocation templates never contain /tmp, and reference output only via %OUTPUT%", () => {
    for (const def of TOOL_DEFINITIONS) {
      const inv = buildInvocationTemplate(def);
      expect(inv, `invocation for ${def.name}`).not.toContain("/tmp");
      if (inv.includes("OUTPUT")) {
        expect(inv).toContain("%OUTPUT%/");
      }
    }
  });
});
