import { describe, it, expect } from "vitest";
import { readFileSync } from "node:fs";
import { fileURLToPath } from "node:url";
import { dirname, join } from "node:path";
import { sanitizeToolOutputForIOCScan } from "../metadata-filter.js";
import { extractIOCs } from "../../ioc/extractor.js";

const fixturesDir = join(dirname(fileURLToPath(import.meta.url)), "../../__tests__/fixtures");
const capaJson = readFileSync(join(fixturesDir, "capa-output.json"), "utf8");
const capaVv = readFileSync(join(fixturesDir, "capa-vv-output.txt"), "utf8");

const scan = (text: string) => sanitizeToolOutputForIOCScan("capa", text);
const iocsOf = (text: string, type: string) =>
  extractIOCs(sanitizeToolOutputForIOCScan("capa", text))
    .iocs.filter((i) => i.type === type)
    .map((i) => i.value);

/**
 * Regression suite for the 0.1.71 defect: capa rule metadata (author emails, reference-sample
 * hashes in `examples`) was reported by analyze_file as indicators extracted from the sample.
 *
 * The root cause was structural: capa runs with `-j` at `standard` depth and emits its entire
 * result as ONE line of JSON, so the line-based metadata filter could not remove anything.
 */
describe("capa metadata is not mistaken for sample-derived IOCs", () => {
  it("the fixture really is single-line JSON (the condition that defeated the line filter)", () => {
    expect(capaJson.split("\n")).toHaveLength(1);
    expect(() => JSON.parse(capaJson)).not.toThrow();
  });

  describe("capa -j output", () => {
    const filtered = scan(capaJson);

    it("removes rule author emails", () => {
      expect(filtered).not.toContain("mehunhoff@google.com");
      expect(filtered).not.toContain("0x534a@mailbox.org");
      expect(filtered).not.toContain("joakim@intezer.com");
    });

    it("removes rule reference-sample hashes from `examples`", () => {
      expect(filtered).not.toContain("9324D1A8AE37A36AE560C37448C9705A");
      expect(filtered).not.toContain("B5F85C26D7AA5A1FB4AF5821B6B5AB9B");
      expect(filtered).not.toContain("563653399B82CD443F120ECEFF836EA3678D4CF11D9B351BB737573C2D856299");
    });

    it("removes rule `references` URLs", () => {
      expect(filtered).not.toContain("docs.microsoft.com");
      expect(filtered).not.toContain("LordNoteworthy");
    });

    it("removes the rule YAML capa embeds in `source`", () => {
      // A second, independent copy of the same provenance: the rule's own text.
      expect(capaJson).toContain('"source":"rule:');
      expect(filtered).not.toContain("rule:");
    });

    it("removes capa's own run metadata (argv, sample path, timestamp)", () => {
      expect(filtered).not.toContain("/home/remnux/files/samples/cherome.exe");
      expect(filtered).not.toContain("803217cb97dc6d38c339bc53650f2c90");
    });

    it("drops a rule cross-reference entirely, hash and all", () => {
      // capa writes a `match` feature as "<rule name>/<rule content hash>". Both halves are rule
      // identity, and the hash was being reported as an MD5 found in the sample.
      expect(capaJson).toContain("allocate or change RWX memory/5de1e2419d9a4fdb987c3f14a689a26b");
      expect(filtered).not.toContain("5de1e2419d9a4fdb987c3f14a689a26b");
      expect(filtered).not.toContain("allocate or change RWX memory");
    });

    it("drops the rule-authored `regex` pattern but keeps what it captured", () => {
      // A pattern like `good\.com|bad\.com` names both candidates; only the captured text was
      // actually in the sample.
      const doc = JSON.stringify({
        meta: {}, rules: { r: { meta: {}, matches: [[{ type: "absolute", value: 1 }, {
          success: true,
          node: { type: "feature", feature: { type: "regex", regex: "/decoy-host\\.net|real-c2\\.net/" } },
          children: [], locations: [], captures: { "real-c2.net/gate.php": [] },
        }]] } },
      });
      const out = scan(doc);
      expect(out).not.toContain("decoy-host.net");
      expect(out).toContain("real-c2.net/gate.php");
    });

    it("drops the rule-authored `description` annotation on a feature", () => {
      const doc = JSON.stringify({
        meta: {}, rules: { r: { meta: {}, matches: [[{ type: "absolute", value: 1 }, {
          success: true,
          node: { type: "feature", feature: { type: "api", api: "Sleep", description: "see notes at rule-author.example.net" } },
          children: [], locations: [], captures: {},
        }]] } },
      });
      const out = scan(doc);
      expect(out).toContain("Sleep");
      expect(out).not.toContain("rule-author.example.net");
    });

    it("keeps matched-feature content, which is sample-derived", () => {
      expect(filtered).toContain("GetProcAddress");
      expect(filtered).toContain("http://sample-c2.example-evil.net/gate.php");
      expect(filtered).toContain("d1b2c3d4e5f60718293a4b5c6d7e8f90");
    });

    it("produces zero email IOCs", () => {
      expect(iocsOf(capaJson, "email")).toEqual([]);
    });

    it("produces no hash IOC that came from a rule `examples` field", () => {
      const hashes = [
        ...iocsOf(capaJson, "md5"),
        ...iocsOf(capaJson, "sha1"),
        ...iocsOf(capaJson, "sha256"),
      ].map((h) => h.toLowerCase());
      expect(hashes).not.toContain("9324d1a8ae37a36ae560c37448c9705a");
      expect(hashes).not.toContain("b5f85c26d7aa5a1fb4af5821b6b5ab9b");
      expect(hashes).not.toContain("cee25a2e7d3f455d8b9d79de2fe5bc74");
      expect(hashes).not.toContain(
        "563653399b82cd443f120eceff836ea3678d4cf11d9b351bb737573c2d856299",
      );
    });

    it("produces no domain IOC derived from a rule author's email domain", () => {
      const domains = iocsOf(capaJson, "domain");
      expect(domains).not.toContain("mailbox.org");
      expect(domains).not.toContain("mandiant.com");
      expect(domains).not.toContain("intezer.com");
    });

    // Anti-vacuity control: the assertions above would also pass if extraction found nothing
    // at all. This proves the extractor still sees the sample-derived side of the same document.
    it("still extracts the sample-derived URL and hash from matched features", () => {
      expect(iocsOf(capaJson, "url")).toContain("http://sample-c2.example-evil.net/gate.php");
      expect(iocsOf(capaJson, "md5")).toContain("d1b2c3d4e5f60718293a4b5c6d7e8f90");
    });
  });

  describe("unmatched capa branches are not evidence", () => {
    // capa emits its whole feature tree, including the alternatives it looked for and did NOT
    // find. On the real cherome.exe run this listed supportxmr.com and dwarfpool.com for a
    // sample containing neither string — the strongest false positive of the whole defect,
    // because it inverts the meaning of capa's own result.
    const withUnmatched = JSON.stringify({
      meta: { version: "9.3.1" },
      rules: {
        "reference cryptocurrency strings": {
          meta: { name: "reference cryptocurrency strings", authors: ["moritz.raabe@mandiant.com"] },
          matches: [[
            { type: "absolute", value: 4198400 },
            {
              success: true,
              node: { type: "statement", statement: { type: "or" } },
              children: [
                {
                  success: false,
                  node: { type: "feature", feature: { type: "string", string: "supportxmr.com:" } },
                  children: [], locations: [], captures: {},
                },
                {
                  success: false,
                  node: { type: "feature", feature: { type: "string", string: "dwarfpool.com:" } },
                  children: [], locations: [], captures: {},
                },
                {
                  success: true,
                  node: { type: "feature", feature: { type: "string", string: "xmr." } },
                  children: [], locations: [{ type: "absolute", value: 4198410 }], captures: {},
                },
              ],
            },
          ]],
        },
      },
    });

    it("drops strings from branches capa recorded as not matching", () => {
      const filtered = scan(withUnmatched);
      expect(filtered).not.toContain("supportxmr.com");
      expect(filtered).not.toContain("dwarfpool.com");
    });

    it("keeps the string from the branch that did match", () => {
      expect(scan(withUnmatched)).toContain("xmr.");
    });

    it("keeps a matched feature nested under a branch that failed overall", () => {
      // capa serializes every child regardless of the parent's result, so a failed `and` can
      // still hold a feature that was genuinely found in the sample.
      const doc = JSON.stringify({
        meta: {}, rules: { r: { meta: {}, matches: [[{ type: "absolute", value: 1 }, {
          success: false,
          node: { type: "statement", statement: { type: "and" } },
          children: [
            { success: true, node: { type: "feature", feature: { type: "string", string: "found-host.example.net" } }, children: [], locations: [{ type: "absolute", value: 2 }], captures: {} },
            { success: false, node: { type: "feature", feature: { type: "string", string: "absent-host.example.net" } }, children: [], locations: [], captures: {} },
          ],
        }]] } },
      });
      const out = scan(doc);
      expect(out).toContain("found-host.example.net");
      expect(out).not.toContain("absent-host.example.net");
    });

    it("keeps a counted feature, which hangs off a range statement rather than a feature node", () => {
      const doc = JSON.stringify({
        meta: {}, rules: { r: { meta: {}, matches: [[{ type: "absolute", value: 1 }, {
          success: true,
          node: { type: "statement", statement: { type: "range", child: { type: "string", string: "counted-c2.example.net" } } },
          children: [], locations: [{ type: "absolute", value: 2 }], captures: {},
        }]] } },
      });
      expect(scan(doc)).toContain("counted-c2.example.net");
    });

    it("drops a counted feature whose successful count was zero", () => {
      const doc = JSON.stringify({
        meta: {}, rules: { r: { meta: {}, matches: [[{ type: "absolute", value: 1 }, {
          success: true,
          node: { type: "statement", statement: { type: "range", child: { type: "string", string: "never-seen.example.net" } } },
          children: [], locations: [], captures: {},
        }]] } },
      });
      expect(scan(doc)).not.toContain("never-seen.example.net");
    });

    it("reports no domain IOC for a pool the sample never referenced", () => {
      expect(iocsOf(withUnmatched, "domain")).toEqual([]);
    });
  });

  describe("capa -vv text output (column-aligned metadata, no separator)", () => {
    const filtered = scan(capaVv);

    it("removes `author  <email>` lines that use column alignment rather than a colon", () => {
      expect(capaVv).toContain("author      michael.hunhoff@mandiant.com");
      expect(filtered).not.toContain("michael.hunhoff@mandiant.com");
      expect(filtered).not.toContain("0x534a@mailbox.org");
      expect(filtered).not.toContain("moritz.raabe@mandiant.com");
    });

    it("removes wrapped `references` continuation lines", () => {
      expect(filtered).not.toContain("docs.microsoft.com");
      expect(filtered).not.toContain("github.com/LordNoteworthy");
    });

    it("keeps the capability evidence tree", () => {
      expect(filtered).toContain("api: VirtualProtect");
      expect(filtered).toContain("characteristic: loop");
    });

    it("produces zero email IOCs from capa -vv output", () => {
      expect(iocsOf(capaVv, "email")).toEqual([]);
    });
  });

  describe("robustness", () => {
    it("sanitizes a capa document larger than the per-tool IOC scan cap", () => {
      // analyze_file caps each tool's output at 512KB for IOC scanning. capa emits ONE JSON
      // document, so truncating before sanitizing would leave unparseable JSON and the
      // provenance would flow straight through. Sanitization must therefore run on the whole
      // document first — this asserts the property that ordering exists to protect.
      const rules: Record<string, unknown> = {};
      for (let i = 0; i < 4000; i++) {
        rules[`padding rule ${i}`] = {
          meta: { name: `padding rule ${i}`, authors: ["leak@rule-author.example.net"] },
          source: "rule:\n  meta:\n    authors:\n      - leak@rule-author.example.net\n",
          matches: [[
            { type: "absolute", value: 4096 + i },
            {
              success: true,
              node: { type: "feature", feature: { type: "api", api: "GetProcAddress" } },
              children: [], locations: [], captures: {},
            },
          ]],
        };
      }
      const big = JSON.stringify({ meta: { version: "9.3.1" }, rules });
      expect(big.length).toBeGreaterThan(512 * 1024);

      const sanitized = sanitizeToolOutputForIOCScan("capa", big);
      expect(sanitized).not.toContain("leak@rule-author.example.net");
      expect(sanitized).toContain("GetProcAddress");
      expect(extractIOCs(sanitized).iocs.filter((i) => i.type === "email")).toEqual([]);
    });


    it("does not throw or overflow the stack on deeply nested JSON", () => {
      const deep = `{"meta":{},"rules":{"r":{"matches":${"[".repeat(20000)}${"]".repeat(20000)}}}}`;
      expect(() => sanitizeToolOutputForIOCScan("capa", deep)).not.toThrow();
    });

    it("yields nothing rather than raw JSON when capa output is truncated mid-document", () => {
      // capa's -j output is one line starting with "{", so the line filter cannot remove a field
      // from it. Falling back to raw text would hand the whole provenance-laden document to the
      // extractor, which is the original defect.
      const cut = capaJson.slice(0, Math.floor(capaJson.length / 2));
      const out = sanitizeToolOutputForIOCScan("capa", cut);
      expect(out).not.toContain("mehunhoff@google.com");
      expect(out).not.toContain("9324D1A8AE37A36AE560C37448C9705A");
      expect(extractIOCs(out).iocs).toEqual([]);
    });

    it("handles a capa run that matched nothing", () => {
      const empty = JSON.stringify({ meta: { version: "9.3.1" }, rules: {} });
      expect(sanitizeToolOutputForIOCScan("capa", empty)).toBe("");
    });

    it("does not corrupt output when a rule is named __proto__", () => {
      const hostile = JSON.stringify({
        meta: {},
        rules: { __proto__: { meta: {}, matches: [] }, real: { meta: {}, matches: [] } },
      });
      expect(() => sanitizeToolOutputForIOCScan("capa", hostile)).not.toThrow();
      expect(Object.prototype).not.toHaveProperty("matches");
    });

    it("leaves a non-capa tool's JSON alone rather than pruning semantic keys", () => {
      // A malware config carrying an operator contact is sample evidence, not tool provenance.
      const config = '{"contact":"operator@evil-host.net","c2":"http://evil-host.net/gate"}';
      const out = sanitizeToolOutputForIOCScan("diec", config);
      expect(out).toContain("operator@evil-host.net");
      expect(extractIOCs(out).iocs.map((i) => i.value)).toContain("operator@evil-host.net");
    });

    it("leaves a non-capa tool's column-aligned text alone", () => {
      // "source  203.0.113.27" in some other tool is a row of data, not a metadata field.
      const table = "source  203.0.113.27\ndest  198.51.100.9";
      const out = sanitizeToolOutputForIOCScan("tshark", table);
      expect(out).toContain("203.0.113.27");
    });
  });
});
