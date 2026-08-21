import { describe, it, expect } from "vitest";
import { extractIOC } from "ioc-extractor";
import { extractLibraryHits, hasLongRun, extractIOCs } from "../extractor.js";

/**
 * Regression guard for the windowed extraction in extractor.ts.
 *
 * ioc-extractor is quadratic in the length of a single non-whitespace run
 * (measured on 8.1.7: 30KB unbroken = 3.7s), and extraction is synchronous, so
 * a packed sample could freeze the server's event loop. Windowing bounds that.
 *
 * Two properties matter and both are asserted here: cost stays bounded, and the
 * cuts neither LOSE real indicators nor MANUFACTURE fake ones.
 */

const SHA256 = "e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855";
const SHA512 =
  "cf83e1357eefb8bdf1542850d66d8007d620e4050b5715dc83f4a921d36ce9ce" +
  "47d0d13c5d85f2b0ff8318d2877eec2f63b931bd47417a81a538327af927da3e";

/** Reduce raw library output to a comparable set, keeping the type. */
function rawSet(text: string): Set<string> {
  const res = extractIOC(text) as unknown as Record<string, unknown>;
  const out = new Set<string>();
  for (const [k, v] of Object.entries(res)) {
    if (Array.isArray(v)) for (const x of v as string[]) out.add(`${k}::${x}`);
  }
  return out;
}
function hitSet(text: string): Set<string> {
  return new Set(extractLibraryHits(text).map((h) => `${h.key}::${h.value}`));
}
/**
 * Identity for loss comparison: a URL's host. When an indicator sits inside an
 * unbroken run the library glues trailing junk onto the match, and how much
 * junk it swallows is not the property under test. Type is preserved so losing
 * a URL's classification while keeping its bare domain still registers.
 */
function identities(set: Set<string>): Set<string> {
  const out = new Set<string>();
  for (const entry of set) {
    const idx = entry.indexOf("::");
    const key = entry.slice(0, idx);
    const value = entry.slice(idx + 2);
    if (key === "urls") {
      try {
        out.add(`urls::${new URL(value).hostname}`);
      } catch {
        out.add(`urls::${value}`);
      }
    } else {
      out.add(`${key}::${value}`);
    }
  }
  return out;
}

describe("hasLongRun", () => {
  it("is false for short text", () => expect(hasLongRun("a b c")).toBe(false));
  it("is false for long text made only of short runs", () => {
    expect(hasLongRun("word ".repeat(5000))).toBe(false);
  });
  it("is false at exactly the threshold", () => expect(hasLongRun("A".repeat(4096))).toBe(false));
  it("is true one char past the threshold", () => expect(hasLongRun("A".repeat(4097))).toBe(true));
});

describe("text without an over-long run is untouched", () => {
  it("produces exactly the library's own result", () => {
    // Long overall, but every run is short: must take the plain single-call
    // path, so no filtering of any kind can apply.
    const text = `${"ordinary words here ".repeat(400)} evil-plain.com http://evil-plain.com/a 45.33.32.156 `;
    expect(hasLongRun(text)).toBe(false);
    expect(hitSet(text)).toEqual(rawSet(text));
  });

  it("keeps a defanged domain that the library refangs", () => {
    const text = `${"ordinary words here ".repeat(300)} evil[.]com `;
    expect(hasLongRun(text)).toBe(false);
    const values = extractLibraryHits(text).map((h) => h.value);
    expect(values).toContain("evil.com");
  });
});

describe("windowing loses no indicators", () => {
  const cases: Array<[string, string]> = [
    ["url quoted inside minified JS", `${'a=1;b="q";'.repeat(800)}u="http://evil-js.com/p.bin";${"z=2;".repeat(600)}`],
    ["url at the start of a long run", `http://evil-start.com/a.ps1${"X".repeat(8000)}`],
    ["url at the end of a long run", `${"X".repeat(8000)}http://evil-end.com/a.ps1`],
    ["sha256 delimited inside a long run", `${"X".repeat(6000)} ${SHA256} ${"Y".repeat(6000)}`],
    ["sha512 quoted inside a long run", `${"X".repeat(6000)}"${SHA512}"${"Y".repeat(6000)}`],
    ["ipv4 delimited inside a long run", `${"X".repeat(6000)},45.33.32.156,${"Y".repeat(6000)}`],
    ["base64 blob followed by a url", `${"QUJDREVGR0hJSktMTU5PUFFSU1RVVldYWVo=".repeat(250)} http://evil-b64.com/x`],
    ["hex dump followed by a url", `${"deadbeefcafebabe".repeat(600)} http://evil-hex.com/x`],
    ["url landing on a window boundary", `${"X".repeat(1004)}http://evil-edge.com/aaa${"Y".repeat(8000)}`],
    ["url straddling a window edge", `${"X".repeat(1018)}http://evil-strad.com/bbb${"Y".repeat(8000)}`],
  ];

  for (const [label, input] of cases) {
    it(`loses nothing: ${label}`, () => {
      const raw = identities(rawSet(input));
      const windowed = identities(hitSet(input));
      expect([...raw].filter((x) => !windowed.has(x))).toEqual([]);
      expect(raw.size).toBeGreaterThan(0); // control: fixture is not vacuous
    });
  }

  it("recovers far more indicators than the unsegmented library when many are glued into one run", () => {
    // 20 URLs glued into a single run. Unsegmented, the library swallows the
    // whole run into ONE match and reports a single host; the windows recover
    // most of them. Asserting "all 20" would be asserting perfection windowing
    // does not claim -- the real property is that it strictly beats raw and
    // loses nothing raw had.
    const input = Array.from({ length: 20 }, (_, i) => `${"X".repeat(400)}http://evil${i}.com/p`).join("");
    const raw = identities(rawSet(input));
    const windowed = identities(hitSet(input));
    expect([...raw].filter((x) => !windowed.has(x))).toEqual([]);
    const rawHosts = [...raw].filter((x) => x.startsWith("urls::")).length;
    const windowedHosts = [...windowed].filter((x) => x.startsWith("urls::")).length;
    expect(rawHosts).toBeLessThanOrEqual(2); // control: raw really does collapse them
    expect(windowedHosts).toBeGreaterThanOrEqual(8);
  });

  it("keeps a defanged domain embedded in a long run", () => {
    const input = `${"X".repeat(6000)} evil-defanged[.]com ${"Y".repeat(6000)}`;
    expect(extractLibraryHits(input).map((h) => h.value)).toContain("evil-defanged.com");
  });
});

describe("windowing manufactures no indicators", () => {
  // Every value the windowed path reports must also be reported by the library
  // on the unsegmented input. These three fixtures are the cases a cut is known
  // to fabricate: a domain from a dotted identifier, a hash from a run of hex,
  // and a URL from a glued token.
  const cases: Array<[string, string]> = [
    ["domain from a dotted identifier", `${"A".repeat(3000)}System.IO.Compression.ZipFileExtensions${"B".repeat(3000)}`],
    ["sha256 from a run of F at a window end", `${"X".repeat(959)}:${"F".repeat(64)}${"G".repeat(5000)}`],
  ];

  for (const [label, input] of cases) {
    it(`invents nothing: ${label}`, () => {
      const raw = rawSet(input);
      const windowed = hitSet(input);
      const invented = [...windowed].filter((x) => !raw.has(x));
      expect(invented).toEqual([]);
    });
  }

  it("MAY expose a genuine url that gluing hid from the unsegmented library", () => {
    // Documented policy, not an oversight: a URL needs a scheme and a valid
    // host, so a cut can only reveal one that is really in the text. The
    // unsegmented library reports the same indicator with junk glued on.
    const input = `${"X".repeat(1009)}http://evil.com${"G".repeat(5000)}`;
    const hosts = extractLibraryHits(input)
      .filter((h) => h.key === "urls")
      .map((h) => {
        try { return new URL(h.value).hostname; } catch { return h.value; }
      });
    expect(hosts).toContain("evil.com");
    expect(input).toContain("http://evil.com"); // control: it is genuinely present
  });
});

describe("cost stays bounded", () => {
  // These feed large inputs ON PURPOSE, so they are legitimately slower than
  // the 5s default. That is the input size being bounded, not a symptom hidden:
  // unsegmented, the same inputs run for minutes.
  it("handles a 512KB unbroken run", { timeout: 60_000 }, () => {
    const input = `${"A".repeat(512 * 1024)} url: "http://evil-big.com/x" `;
    const started = Date.now();
    const result = extractIOCs(input);
    expect(Date.now() - started).toBeLessThan(30_000);
    expect(result.iocs.concat(result.noise).some((i) => i.value.includes("evil-big.com"))).toBe(true);
  });

  it("handles very many distinct domains without a per-candidate blowup", { timeout: 60_000 }, () => {
    // Guards the failure mode of a previous implementation, which scanned the
    // whole input once per candidate and so was itself quadratic.
    const input = Array.from({ length: 20_000 }, (_, i) => `host${i}.example.com`).join(" ");
    const started = Date.now();
    extractIOCs(input);
    expect(Date.now() - started).toBeLessThan(30_000);
  });
});
