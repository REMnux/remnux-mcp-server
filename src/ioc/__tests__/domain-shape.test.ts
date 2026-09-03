import { describe, it, expect } from "vitest";
import { isNoise } from "../noise.js";

/**
 * Regression suite for the second half of the 0.1.71 defect: 25 of the 102 "domains"
 * analyze_file reported for cherome.exe were high-entropy fragments from binary data
 * ("0dpC.Nf", "A.Ad", "C.MS"), which crowded the one genuine domain out of the per-type cap.
 *
 * These are the exact 25 values from that report, verbatim.
 */
const REPORTED_JUNK = [
  "0.cl", "0dpC.Nf", "1.Bb", "1.ga", "2.Ne", "2Y5.mY", "3.NZ", "5.NO", "5fif.SY",
  "6.Za", "7-M.gi", "7.CZ", "8.tK", "91.UA", "A.Ad", "A.Fo", "A.GM", "A.zW",
  "ANA.Bg", "Ac.MH", "B.bg", "B.ms", "C.AM", "C.MS", "Cr.nr",
];

/**
 * Positive control. Domain rules that reject junk are worthless if they also reject real
 * indicators, and analyze_file does not surface the noise bucket — a demotion here is a
 * silent drop. Every value below must survive.
 */
const MUST_SURVIVE = [
  "createinstall.com",
  "www.createinstall.com",
  // short but real, including the ones a naive "label must be >= 3 chars" rule would kill
  "t.co", "x.com", "vk.com", "qq.com", "is.gd", "bit.ly", "goo.gl", "discord.gg",
  "cdn.discordapp.com",
  // title case with a label of three or more characters, the natural way a human writes
  // a short domain in prose
  "Bit.ly", "Goo.gl",
  // numeric second-level labels of two or three digits are real registrations
  "163.com", "126.com", "58.com", "22.cn", "51.la", "1337.example.net",
  // an uppercase-only config string, which malware really does embed
  "EVIL.COM", "C2.EXAMPLE.ORG",
  // ordinary mixed-case host references with a lowercase TLD
  "MyDomain.com", "CDN.evil-host.net",
  // long random-looking but structurally plausible DGA output
  "kqxwlnvbtrspd.info", "a1b2c3d4e5f6.biz",
  // multi-label hostnames are never subject to the short-label rules, whatever their casing
  "CDN.example.co.uk", "cdn.example.co.UK", "a.b.evil-host.net",
];

/**
 * Accepted losses, recorded rather than hidden. Each is a real domain the rules reject; each is
 * rejected only in a casing that does not occur in binary output (the lowercase form is kept
 * above), and a domain referenced by a URL is extracted as a `url` and never reaches this check.
 */
const ACCEPTED_LOSSES = [
  // Two-label names in a casing binaries do not use; the lowercase form is kept above.
  "T.co", "X.com", "VK.com", "QQ.com", "Is.gd", "Go.co", "discord.GG", "example.COM",
  // Two-label names with a single-digit label, overwhelmingly binary noise.
  "1.fm", "8.co",
];

describe("domain shape validation", () => {
  it.each(REPORTED_JUNK)("classifies %s as noise", (value) => {
    expect(isNoise(value, "domain")).toBe(true);
  });

  it.each(MUST_SURVIVE)("keeps %s", (value) => {
    expect(isNoise(value, "domain")).toBe(false);
  });

  it("rejects all 25 reported junk domains and keeps every control value", () => {
    // Stated as counts too, so a rule that silently stops matching shows up as a number.
    expect(REPORTED_JUNK.filter((d) => isNoise(d, "domain"))).toHaveLength(25);
    expect(MUST_SURVIVE.filter((d) => !isNoise(d, "domain"))).toHaveLength(MUST_SURVIVE.length);
  });

  // Representative of the categories these rules reject, not an exhaustive enumeration of them:
  // the rules reject shapes, so other values of the same shape are rejected too. If one of these
  // starts passing, the rules were loosened and the junk list above should be re-measured.
  it.each(ACCEPTED_LOSSES)("rejects %s — an accepted loss in a casing binaries do not use", (value) => {
    expect(isNoise(value, "domain")).toBe(true);
  });

  it("never rejects a domain that reaches extraction as a URL", () => {
    // The url type does not go through the domain rules, so a shortener referenced properly
    // survives regardless of casing.
    expect(isNoise("https://T.co/abc123", "url")).toBe(false);
    expect(isNoise("https://discord.GG/invite", "url")).toBe(false);
  });
});
