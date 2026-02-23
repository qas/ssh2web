/**
 * Unit tests for packet codec (buildPacket / parsePacket).
 */

import { buildPacket, parsePacket } from "./codec";

describe("Packet Codec", () => {
  describe("buildPacket", () => {
    it("should produce at least 4 + 1 + payload + padding bytes", () => {
      const payload = new Uint8Array([20, 1, 2, 3]);
      const out = buildPacket(payload);
      expect(out.length).toBeGreaterThanOrEqual(4 + 1 + payload.length + 4);
      const plen = new DataView(out.buffer, out.byteOffset, 4).getUint32(0, false);
      expect(plen).toBe(1 + payload.length + out[4]);
    });
    it("should encode padLen at offset 4", () => {
      const payload = new Uint8Array(5);
      const out = buildPacket(payload);
      expect(out[4]).toBeGreaterThanOrEqual(4);
      expect(out[4]).toBeLessThanOrEqual(255);
    });
  });
  describe("parsePacket", () => {
    it("should return null for data shorter than 5 bytes", () => {
      expect(parsePacket(new Uint8Array(0))).toBeNull();
      expect(parsePacket(new Uint8Array(4))).toBeNull();
    });
    it("should return null when not enough data for full packet", () => {
      const header = new Uint8Array(5);
      new DataView(header.buffer).setUint32(0, 100, false);
      header[4] = 10;
      expect(parsePacket(header)).toBeNull();
    });
    it("should round-trip with buildPacket", () => {
      const payload = new Uint8Array([21]);
      const raw = buildPacket(payload);
      const result = parsePacket(raw);
      expect(result).not.toBeNull();
      expect(result!.consumed).toBe(raw.length);
      expect(result!.payload.length).toBe(1);
      expect(result!.payload[0]).toBe(21);
    });
    it("should parse multi-byte payload", () => {
      const payload = new Uint8Array([50, 1, 2, 3, 4, 5]);
      const raw = buildPacket(payload);
      const result = parsePacket(raw);
      expect(result).not.toBeNull();
      expect(result!.payload.length).toBe(6);
      expect(Array.from(result!.payload)).toEqual([50, 1, 2, 3, 4, 5]);
    });
  });
});
