/**
 * Unit tests for key exchange (DH and X25519).
 */

import { generateDHPrivate, computeDHSharedSecret, generateX25519KeyPair, computeX25519SharedSecret } from "./keyexchange";
import { DH_PRIME } from "../domain/constants";

describe("Key Exchange", () => {
  describe("DH", () => {
    it("should generate x and e with e in valid range", async () => {
      const { x, e } = await generateDHPrivate();
      expect(e > 1n).toBe(true);
      expect(e < DH_PRIME - 1n).toBe(true);
    });
    it("should produce same shared secret from both sides", async () => {
      const { x: x1, e: e1 } = await generateDHPrivate();
      const { x: x2, e: e2 } = await generateDHPrivate();
      const k1 = computeDHSharedSecret(e2, x1);
      const k2 = computeDHSharedSecret(e1, x2);
      expect(k1).toBe(k2);
    });
  });
  describe("X25519", () => {
    it("should produce same shared secret from both sides", async () => {
      const alice = await generateX25519KeyPair();
      const bob = await generateX25519KeyPair();
      const kAlice = await computeX25519SharedSecret(alice.privateKey, bob.publicKey);
      const kBob = await computeX25519SharedSecret(bob.privateKey, alice.publicKey);
      expect(kAlice).toEqual(kBob);
    });
    it("should produce 32-byte shared secret", async () => {
      const alice = await generateX25519KeyPair();
      const bob = await generateX25519KeyPair();
      const k = await computeX25519SharedSecret(alice.privateKey, bob.publicKey);
      expect(k.length).toBe(32);
    });
  });
});
