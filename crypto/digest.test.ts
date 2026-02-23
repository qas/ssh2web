/**
 * Unit tests for SHA256 digest.
 */

import { computeSHA256 } from "./digest";

describe("Digest", () => {
  it("should produce 32-byte hash", async () => {
    const data = new Uint8Array([1, 2, 3]);
    const hash = await computeSHA256(data);
    expect(hash.length).toBe(32);
  });
  it("should be deterministic", async () => {
    const data = new Uint8Array([1, 2, 3]);
    const a = await computeSHA256(data);
    const b = await computeSHA256(data);
    expect(a).toEqual(b);
  });
  it("should differ for different input", async () => {
    const h1 = await computeSHA256(new Uint8Array([1, 2, 3]));
    const h2 = await computeSHA256(new Uint8Array([1, 2, 4]));
    expect(h1).not.toEqual(h2);
  });
  it("should handle empty input", async () => {
    const hash = await computeSHA256(new Uint8Array(0));
    expect(hash.length).toBe(32);
  });
});
