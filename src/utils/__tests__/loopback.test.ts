import { describe, it, expect } from "vitest";
import { isLoopbackHost, httpBindRequiresToken, loopbackAllowedHosts } from "../loopback.js";

describe("loopbackAllowedHosts", () => {
  const SDK_DEFAULTS = ["localhost", "127.0.0.1", "[::1]"];

  it("matches the SDK's own list for the three hosts the SDK protects", () => {
    for (const h of ["127.0.0.1", "localhost", "::1", undefined, ""]) {
      expect(loopbackAllowedHosts(h)).toEqual(SDK_DEFAULTS);
    }
  });

  it("adds the configured host in the form a Host header parses to", () => {
    expect(loopbackAllowedHosts("LOCALHOST")).toEqual(SDK_DEFAULTS);
    expect(loopbackAllowedHosts("[::1]")).toEqual(SDK_DEFAULTS);
    expect(loopbackAllowedHosts("127.0.0.2")).toEqual([...SDK_DEFAULTS, "127.0.0.2"]);
    expect(loopbackAllowedHosts("::ffff:127.0.0.1")).toEqual([...SDK_DEFAULTS, "[::ffff:7f00:1]"]);
    expect(loopbackAllowedHosts("  127.0.0.3  ")).toEqual([...SDK_DEFAULTS, "127.0.0.3"]);
  });

  it("never allows a foreign hostname", () => {
    for (const h of ["LOCALHOST", "127.0.0.2", "::ffff:127.0.0.1"]) {
      expect(loopbackAllowedHosts(h)).not.toContain("attacker.example");
    }
  });

  it("returns undefined for a non-loopback bind", () => {
    for (const h of ["0.0.0.0", "::", "192.168.1.10", "example.com"]) {
      expect(loopbackAllowedHosts(h)).toBeUndefined();
    }
  });
});

describe("isLoopbackHost", () => {
  it("treats loopback addresses, localhost, and the default as loopback", () => {
    for (const h of [
      "127.0.0.1",
      "127.0.0.2",
      "127.255.255.254",
      "localhost",
      "LOCALHOST",
      "::1",
      "[::1]",
      "::ffff:127.0.0.1",
      "  127.0.0.1  ",
      "",
      undefined,
    ]) {
      expect(isLoopbackHost(h)).toBe(true);
    }
  });

  it("treats network-reachable addresses as non-loopback", () => {
    for (const h of ["0.0.0.0", "::", "192.168.1.10", "10.0.0.5", "example.com", "0"]) {
      expect(isLoopbackHost(h)).toBe(false);
    }
  });
});

describe("httpBindRequiresToken", () => {
  it("requires a token for a non-loopback bind with no token and no override", () => {
    expect(httpBindRequiresToken("0.0.0.0", undefined, false)).toBe(true);
    expect(httpBindRequiresToken("192.168.1.10", undefined, undefined)).toBe(true);
  });

  it("does not require a token when one is set, when overridden, or when loopback", () => {
    expect(httpBindRequiresToken("0.0.0.0", "tok", false)).toBe(false); // token present
    expect(httpBindRequiresToken("0.0.0.0", undefined, true)).toBe(false); // explicit override
    expect(httpBindRequiresToken("127.0.0.1", undefined, false)).toBe(false); // loopback
    expect(httpBindRequiresToken(undefined, undefined, false)).toBe(false); // default bind
  });
});
