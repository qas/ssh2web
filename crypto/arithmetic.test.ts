/**
 * Unit tests for crypto arithmetic operations.
 * Tests cryptographic utilities in isolation.
 */

import { modPow, bigintToBytes, bytesToBigint } from "./arithmetic";

describe("Arithmetic Operations", () => {
  describe("modPow", () => {
    it("should compute modular exponentiation", () => {
      const result = modPow(2n, 10n, 1000n);
      expect(result).toBe(24n);
    });

    it("should handle large numbers", () => {
      const p = BigInt("0xFFFFFFFFFFFFFFFFC90FDAA22168C234");
      const result = modPow(2n, 100n, p);
      expect(result > 0n).toBe(true);
      expect(result < p).toBe(true);
    });

    it("should handle exp = 0", () => {
      const result = modPow(5n, 0n, 7n);
      expect(result).toBe(1n);
    });
  });

  describe("bigintToBytes", () => {
    it("should convert small bigint to bytes", () => {
      const bytes = bigintToBytes(256n);
      expect(bytes.length).toBe(2);
      expect(bytes[0]).toBe(1);
      expect(bytes[1]).toBe(0);
    });

    it("should convert zero", () => {
      const bytes = bigintToBytes(0n);
      expect(bytes).toEqual(new Uint8Array([0]));
    });

    it("should handle odd-length hex", () => {
      const bytes = bigintToBytes(15n);
      expect(bytes).toEqual(new Uint8Array([0x0f]));
    });
  });

  describe("bytesToBigint", () => {
    it("should convert bytes back to bigint", () => {
      const bytes = new Uint8Array([0x01, 0x00]);
      const result = bytesToBigint(bytes);
      expect(result).toBe(256n);
    });

    it("should handle single byte", () => {
      const bytes = new Uint8Array([0xff]);
      const result = bytesToBigint(bytes);
      expect(result < 0n).toBe(true);
    });
  });
});
