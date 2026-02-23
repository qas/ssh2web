/**
 * Unit tests for AES-128-CTR cipher.
 */

import { encryptAES128CTR, decryptAES128CTR } from "./cipher";

describe("AES-128-CTR", () => {
  it("should round-trip encrypt and decrypt", async () => {
    const key = await crypto.subtle.importKey("raw", new Uint8Array(16).fill(1), { name: "AES-CTR" }, false, ["encrypt", "decrypt"]);
    const iv = new Uint8Array(16).fill(0);
    const plaintext = new TextEncoder().encode("hello world");
    const { ciphertext, nextIv } = await encryptAES128CTR(key, iv, plaintext);
    expect(ciphertext.length).toBe(plaintext.length);
    const { plaintext: dec, nextIv: _ } = await decryptAES128CTR(key, iv, ciphertext);
    expect(new TextDecoder().decode(dec)).toBe("hello world");
  });
  it("should produce different ciphertext for different IV", async () => {
    const key = await crypto.subtle.importKey("raw", new Uint8Array(16).fill(1), { name: "AES-CTR" }, false, ["encrypt"]);
    const plain = new Uint8Array([1, 2, 3]);
    const a = await encryptAES128CTR(key, new Uint8Array(16).fill(0), plain);
    const b = await encryptAES128CTR(key, new Uint8Array(16).fill(1), plain);
    expect(a.ciphertext).not.toEqual(b.ciphertext);
  });
});
