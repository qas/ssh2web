/**
 * Unit tests for serialization layer.
 * Tests codec without dependencies on transport or crypto.
 */

import { writeString, writeBytes, writeUint32, concat } from "./serialization";
import { readString, readBytes } from "./deserialization";

describe("Serialization Layer", () => {
  describe("writeString", () => {
    it("should encode string with length prefix", () => {
      const result = writeString("hello");
      expect(result.length).toBe(4 + 5);
      const len = new DataView(result.buffer).getUint32(0, false);
      expect(len).toBe(5);
      expect(new TextDecoder().decode(result.subarray(4))).toBe("hello");
    });

    it("should handle empty string", () => {
      const result = writeString("");
      expect(result.length).toBe(4);
      const len = new DataView(result.buffer).getUint32(0, false);
      expect(len).toBe(0);
    });
  });

  describe("writeBytes", () => {
    it("should encode bytes with length prefix", () => {
      const data = new Uint8Array([1, 2, 3, 4, 5]);
      const result = writeBytes(data);
      expect(result.length).toBe(4 + 5);
      const len = new DataView(result.buffer).getUint32(0, false);
      expect(len).toBe(5);
      expect(result.subarray(4)).toEqual(data);
    });
  });

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
  });

  describe("concat", () => {
    it("should concatenate multiple Uint8Arrays", () => {
      const a = new Uint8Array([1, 2]);
      const b = new Uint8Array([3, 4]);
      const c = new Uint8Array([5, 6]);
      const result = concat(a, b, c);
      expect(result).toEqual(new Uint8Array([1, 2, 3, 4, 5, 6]));
    });

    it("should handle empty arrays", () => {
      const a = new Uint8Array([1]);
      const b = new Uint8Array([]);
      const result = concat(a, b);
      expect(result).toEqual(new Uint8Array([1]));
    });
  });
});
