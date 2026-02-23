/**
 * Unit tests for domain layer state machines.
 * Tests state transitions without protocol dependencies.
 */

import { createKexState, negotiateAlgorithms, selectAlgorithm } from "./kexstate";

describe("KEX State Machine", () => {
  it("should initialize with correct defaults", () => {
    const state = createKexState();
    expect(state.phase).toBe("init");
    expect(state.negotiated).toBeNull();
  });

  describe("selectAlgorithm", () => {
    it("should select first matching algorithm", () => {
      const ours = ["alg-a", "alg-b", "alg-c"];
      const server = ["alg-b", "alg-x"];
      const result = selectAlgorithm(ours, server);
      expect(result).toBe("alg-b");
    });

    it("should return null when no match", () => {
      const ours = ["alg-a", "alg-b"];
      const server = ["alg-x", "alg-y"];
      const result = selectAlgorithm(ours, server);
      expect(result).toBeNull();
    });
  });

  describe("negotiateAlgorithms", () => {
    it("should negotiate all three algorithm types", () => {
      const result = negotiateAlgorithms(
        ["curve25519-sha256"],
        ["aes128-ctr"],
        ["hmac-sha2-256"],
        ["curve25519-sha256"],
        ["aes128-ctr"],
        ["hmac-sha2-256"]
      );
      expect(result).not.toBeNull();
      expect(result?.kex).toBe("curve25519-sha256");
      expect(result?.cipher).toBe("aes128-ctr");
      expect(result?.mac).toBe("hmac-sha2-256");
    });

    it("should return null if any negotiation fails", () => {
      const result = negotiateAlgorithms(
        ["curve25519-sha256"],
        ["aes128-ctr"],
        ["hmac-sha2-256"],
        ["diffie-hellman"],
        ["aes128-ctr"],
        ["hmac-sha2-256"]
      );
      expect(result).toBeNull();
    });
  });
});
