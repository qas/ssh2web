/**
 * Unit tests for key derivation.
 */

import { deriveKeys } from "./keys";

describe("Key Derivation", () => {
  it("should return ivC, keyC, macC, ivS, keyS, macS of correct lengths", async () => {
    const sharedSecret = new Uint8Array(32).fill(1);
    const exchangeHash = new Uint8Array(32).fill(2);
    const sessionId = new Uint8Array(32).fill(3);
    const out = await deriveKeys(sharedSecret, exchangeHash, sessionId);
    expect(out.ivC.length).toBe(16);
    expect(out.keyC.length).toBe(16);
    expect(out.macC.length).toBe(32);
    expect(out.ivS.length).toBe(16);
    expect(out.keyS.length).toBe(16);
    expect(out.macS.length).toBe(32);
  });
  it("should be deterministic for same inputs", async () => {
    const sharedSecret = new Uint8Array(32).fill(1);
    const exchangeHash = new Uint8Array(32).fill(2);
    const sessionId = new Uint8Array(32).fill(3);
    const a = await deriveKeys(sharedSecret, exchangeHash, sessionId);
    const b = await deriveKeys(sharedSecret, exchangeHash, sessionId);
    expect(a.ivC).toEqual(b.ivC);
    expect(a.keyC).toEqual(b.keyC);
    expect(a.macC).toEqual(b.macC);
    expect(a.ivS).toEqual(b.ivS);
    expect(a.keyS).toEqual(b.keyS);
    expect(a.macS).toEqual(b.macS);
  });
  it("should differ for different sessionId", async () => {
    const sharedSecret = new Uint8Array(32).fill(1);
    const exchangeHash = new Uint8Array(32).fill(2);
    const out1 = await deriveKeys(sharedSecret, exchangeHash, new Uint8Array(32).fill(3));
    const out2 = await deriveKeys(sharedSecret, exchangeHash, new Uint8Array(32).fill(4));
    expect(out1.keyC).not.toEqual(out2.keyC);
  });
});
