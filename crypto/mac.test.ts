/**
 * Unit tests for HMAC-SHA256 and constant-time compare.
 */

import { computeHMACSHA256, constantTimeEqual } from "./mac";

describe("MAC", () => {
  describe("computeHMACSHA256", () => {
    it("should produce 32-byte MAC", async () => {
      const key = new Uint8Array(32).fill(1);
      const data = new Uint8Array([1, 2, 3]);
      const mac = await computeHMACSHA256(key, data);
      expect(mac.length).toBe(32);
    });
    it("should be deterministic", async () => {
      const key = new Uint8Array(32).fill(1);
      const data = new Uint8Array([1, 2, 3]);
      const a = await computeHMACSHA256(key, data);
      const b = await computeHMACSHA256(key, data);
      expect(a).toEqual(b);
    });
    it("should differ for different key", async () => {
      const data = new Uint8Array([1, 2, 3]);
      const a = await computeHMACSHA256(new Uint8Array(32).fill(1), data);
      const b = await computeHMACSHA256(new Uint8Array(32).fill(2), data);
      expect(a).not.toEqual(b);
    });
  });
  describe("constantTimeEqual", () => {
    it("should return true for equal buffers", () => {
      const a = new Uint8Array([1, 2, 3]);
      expect(constantTimeEqual(a, new Uint8Array([1, 2, 3]))).toBe(true);
    });
    it("should return false for different length", () => {
      expect(constantTimeEqual(new Uint8Array(3), new Uint8Array(4))).toBe(false);
    });
    it("should return false for same length different content", () => {
      expect(constantTimeEqual(new Uint8Array([1, 2, 3]), new Uint8Array([1, 2, 4]))).toBe(false);
    });
  });
});
