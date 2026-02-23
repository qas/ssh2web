/**
 * Unit tests for certificate parsing.
 */

import { parseCertBase64 } from "./certparser";

describe("Cert Parser", () => {
  it("should parse key type and cert blob from two-part string", () => {
    const b64 = btoa(String.fromCharCode(...new Uint8Array([1, 2, 3, 4, 5])));
    const cert = `ssh-ed25519 ${b64}`;
    const result = parseCertBase64(cert);
    expect(result.keyType).toBe("ssh-ed25519");
    expect(result.certBlob.length).toBe(5);
    expect(Array.from(result.certBlob)).toEqual([1, 2, 3, 4, 5]);
  });
  it("should trim and collapse whitespace", () => {
    const b64 = btoa("a");
    const result = parseCertBase64("  ssh-ed25519   " + b64 + "  ");
    expect(result.keyType).toBe("ssh-ed25519");
  });
  it("should throw for invalid format (single part)", () => {
    expect(() => parseCertBase64("only-one-part")).toThrow("Invalid certificate format");
  });
  it("should throw for empty", () => {
    expect(() => parseCertBase64("")).toThrow("Invalid certificate format");
  });
});
