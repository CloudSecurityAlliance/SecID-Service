import { describe, it, expect } from "vitest";
import { parseSecID } from "../src/parser";
import { REGISTRY } from "../src/registry";

describe("parseSecID", () => {
  describe("full SecID strings", () => {
    it("parses a complete CVE SecID", () => {
      const r = parseSecID("secid:advisory/mitre.org/cve#CVE-2024-1234", REGISTRY);
      expect(r.prefix).toBe(true);
      expect(r.type).toBe("advisory");
      expect(r.namespace).toBe("mitre.org");
      expect(r.name).toBe("cve");
      expect(r.subpath).toBe("CVE-2024-1234");
      expect(r.version).toBeNull();
      expect(r.itemVersion).toBeNull();
    });

    it("parses RHSA with colon in subpath", () => {
      const r = parseSecID("secid:advisory/redhat.com/errata#RHSA-2024:1234", REGISTRY);
      expect(r.type).toBe("advisory");
      expect(r.namespace).toBe("redhat.com");
      expect(r.name).toBe("errata");
      expect(r.subpath).toBe("RHSA-2024:1234");
    });

    it("parses ATT&CK technique with dot in subpath", () => {
      const r = parseSecID("secid:ttp/mitre.org/attack#T1059.003", REGISTRY);
      expect(r.type).toBe("ttp");
      expect(r.namespace).toBe("mitre.org");
      expect(r.name).toBe("attack");
      expect(r.subpath).toBe("T1059.003");
    });
  });

  describe("progressive depth", () => {
    it("parses type-only", () => {
      const r = parseSecID("secid:advisory", REGISTRY);
      expect(r.prefix).toBe(true);
      expect(r.type).toBe("advisory");
      expect(r.namespace).toBeNull();
      expect(r.name).toBeNull();
      expect(r.subpath).toBeNull();
    });

    it("parses type + namespace", () => {
      const r = parseSecID("secid:advisory/mitre.org", REGISTRY);
      expect(r.type).toBe("advisory");
      expect(r.namespace).toBe("mitre.org");
      expect(r.name).toBeNull();
    });

    it("parses type + namespace + name", () => {
      const r = parseSecID("secid:advisory/mitre.org/cve", REGISTRY);
      expect(r.type).toBe("advisory");
      expect(r.namespace).toBe("mitre.org");
      expect(r.name).toBe("cve");
      expect(r.subpath).toBeNull();
    });
  });

  describe("version extraction", () => {
    it("extracts @version from name", () => {
      const r = parseSecID("secid:weakness/owasp.org/top10@2021#A01", REGISTRY);
      expect(r.type).toBe("weakness");
      expect(r.namespace).toBe("owasp.org");
      expect(r.name).toBe("top10");
      expect(r.version).toBe("2021");
      expect(r.subpath).toBe("A01");
    });

    it("extracts @version without subpath", () => {
      const r = parseSecID("secid:control/cloudsecurityalliance.org/ccm@4.0", REGISTRY);
      expect(r.type).toBe("control");
      expect(r.namespace).toBe("cloudsecurityalliance.org");
      expect(r.name).toBe("ccm");
      expect(r.version).toBe("4.0");
      expect(r.subpath).toBeNull();
    });
  });

  describe("missing prefix", () => {
    it("parses without secid: prefix", () => {
      const r = parseSecID("advisory/mitre.org/cve#CVE-2024-1234", REGISTRY);
      expect(r.prefix).toBe(false);
      expect(r.type).toBe("advisory");
      expect(r.namespace).toBe("mitre.org");
      expect(r.name).toBe("cve");
      expect(r.subpath).toBe("CVE-2024-1234");
    });
  });

  describe("cross-source patterns", () => {
    it("handles identifier without namespace (no domain)", () => {
      const r = parseSecID("secid:advisory/CVE-2024-1234", REGISTRY);
      expect(r.type).toBe("advisory");
      expect(r.namespace).toBeNull();
      expect(r.name).toBe("CVE-2024-1234");
    });

    it("handles unregistered domain-like namespace", () => {
      const r = parseSecID("secid:advisory/unknown.org/something", REGISTRY);
      expect(r.type).toBe("advisory");
      expect(r.namespace).toBe("unknown.org");
      expect(r.name).toBe("something");
    });
  });

  describe("edge cases", () => {
    it("returns null type for empty string", () => {
      const r = parseSecID("", REGISTRY);
      expect(r.type).toBeNull();
    });

    it("returns null type for invalid type", () => {
      const r = parseSecID("secid:frobnicate/mitre.org/cve", REGISTRY);
      expect(r.type).toBeNull();
    });

    it("handles secid: prefix only", () => {
      const r = parseSecID("secid:", REGISTRY);
      expect(r.prefix).toBe(true);
      expect(r.type).toBeNull();
    });

    it("handles case-insensitive prefix", () => {
      const r = parseSecID("SECID:advisory/mitre.org", REGISTRY);
      expect(r.prefix).toBe(true);
      expect(r.type).toBe("advisory");
    });

    it("preserves raw input", () => {
      const input = "secid:advisory/mitre.org/cve#CVE-2024-1234";
      const r = parseSecID(input, REGISTRY);
      expect(r.raw).toBe(input);
    });
  });
});
