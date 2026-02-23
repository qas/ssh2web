/**
 * Unit tests for PEM and Ed25519 signing.
 */

import { parsePemPrivateKey, ed25519Sign } from "./keys";

function pemFromKey(key: CryptoKey): Promise<string> {
  return crypto.subtle.exportKey("pkcs8", key).then((buf) => {
    const b64 = btoa(String.fromCharCode(...new Uint8Array(buf)));
    return `-----BEGIN PRIVATE KEY-----\n${b64}\n-----END PRIVATE KEY-----`;
  });
}

describe("Auth Keys", () => {
  describe("parsePemPrivateKey", () => {
    it("should parse PEM and return CryptoKey usable for sign", async () => {
      const keyPair = await crypto.subtle.generateKey({ name: "Ed25519" }, true, ["sign"]) as CryptoKeyPair;
      const pem = await pemFromKey(keyPair.privateKey);
      const imported = await parsePemPrivateKey(pem);
      expect(imported).toBeDefined();
      const data = new Uint8Array([1, 2, 3]);
      const sig = await ed25519Sign(imported, data);
      expect(sig.length).toBeGreaterThan(0);
    });
    it("should throw for invalid PEM", async () => {
      await expect(parsePemPrivateKey("not a pem")).rejects.toThrow("Invalid PEM format");
    });
  });
  describe("ed25519Sign", () => {
    it("should produce deterministic signature for same key and data", async () => {
      const keyPair = await crypto.subtle.generateKey({ name: "Ed25519" }, true, ["sign"]) as CryptoKeyPair;
      const data = new Uint8Array([1, 2, 3]);
      const a = await ed25519Sign(keyPair.privateKey, data);
      const b = await ed25519Sign(keyPair.privateKey, data);
      expect(a).toEqual(b);
    });
  });
});
