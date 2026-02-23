/**
 * Unit tests for deserialization layer.
 */

import { readString, readBytes, readMpint } from "./deserialization";
import { writeString, writeBytes, writeBigintMpint } from "./serialization";

describe("Deserialization Layer", () => {
  describe("readString", () => {
    it("should decode string from offset", () => {
      const encoded = writeString("test");
      const result = readString(encoded, 0);
      expect(result).not.toBeNull();
      expect(result?.value).toBe("test");
      expect(result?.consumed).toBe(4 + 4);
    });

    it("should return null for insufficient data", () => {
      const data = new Uint8Array([0, 0, 0]);
      const result = readString(data, 0);
      expect(result).toBeNull();
    });

    it("should handle offset", () => {
      const encoded = concat(new Uint8Array([0, 0, 0, 0]), writeString("data"));
      const result = readString(encoded, 4);
      expect(result?.value).toBe("data");
    });
  });

  describe("readBytes", () => {
    it("should decode bytes from offset", () => {
      const original = new Uint8Array([1, 2, 3]);
      const encoded = writeBytes(original);
      const result = readBytes(encoded, 0);
      expect(result?.value).toEqual(original);
      expect(result?.consumed).toBe(4 + 3);
    });

    it("should return null for insufficient data", () => {
      const data = new Uint8Array([0, 0, 0]);
      const result = readBytes(data, 0);
      expect(result).toBeNull();
    });
  });

  describe("readMpint", () => {
    it("should decode mpint bigint", () => {
      const encoded = writeBigintMpint(256n);
      const result = readMpint(encoded, 0);
      expect(result?.value).toBe(256n);
    });

    it("should return null for insufficient data", () => {
      const data = new Uint8Array([0, 0, 0]);
      const result = readMpint(data, 0);
      expect(result).toBeNull();
    });
  });
});

function concat(...arr: Uint8Array[]): Uint8Array {
  const len = arr.reduce((a, b) => a + b.length, 0);
  const out = new Uint8Array(len);
  let off = 0;
  for (const a of arr) {
    out.set(a, off);
    off += a.length;
  }
  return out;
}
