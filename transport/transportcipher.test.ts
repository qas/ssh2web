/**
 * Unit tests for transport cipher.
 */

import { createTransportCipher } from "./transportcipher";
import { deriveKeys } from "../crypto/keys";
import { MacVerificationError } from "../domain/errors";

describe("TransportCipher", () => {
  async function createPair() {
    const sharedSecret = new Uint8Array(32).fill(1);
    const exchangeHash = new Uint8Array(32).fill(2);
    const sessionId = new Uint8Array(32).fill(3);
    const { ivC, keyC, macC, ivS, keyS, macS } = await deriveKeys(sharedSecret, exchangeHash, sessionId);
    const client = await createTransportCipher(ivC, keyC, macC, ivS, keyS, macS, 0, 0, false);
    const server = await createTransportCipher(ivS, keyS, macS, ivC, keyC, macC, 0, 0, false);
    return { client, server };
  }

  it("should round-trip encrypt and decrypt", async () => {
    const { client, server } = await createPair();
    const payload = new Uint8Array([21]);
    const { ciphertext } = await client.encrypt(payload);
    const result = await server.decrypt(ciphertext);
    expect(result).not.toBeNull();
    expect(result!.payload).toEqual(payload);
    expect(result!.consumed).toBe(ciphertext.length);
  });

  it("should throw MacVerificationError when MAC is tampered", async () => {
    const { client, server } = await createPair();
    const { ciphertext } = await client.encrypt(new Uint8Array([21]));
    ciphertext[ciphertext.length - 1] ^= 0xff;
    await expect(server.decrypt(ciphertext)).rejects.toThrow(MacVerificationError);
  });

  it("should return null when not enough data", async () => {
    const { server } = await createPair();
    const result = await server.decrypt(new Uint8Array(10));
    expect(result).toBeNull();
  });

  it("should round-trip with EtM mode", async () => {
    const sharedSecret = new Uint8Array(32).fill(5);
    const exchangeHash = new Uint8Array(32).fill(6);
    const sessionId = new Uint8Array(32).fill(7);
    const { ivC, keyC, macC, ivS, keyS, macS } = await deriveKeys(sharedSecret, exchangeHash, sessionId);
    const client = await createTransportCipher(ivC, keyC, macC, ivS, keyS, macS, 0, 0, true);
    const server = await createTransportCipher(ivS, keyS, macS, ivC, keyC, macC, 0, 0, true);
    const payload = new Uint8Array([50, 1, 2, 3]);
    const { ciphertext } = await client.encrypt(payload);
    const result = await server.decrypt(ciphertext);
    expect(result).not.toBeNull();
    expect(result!.payload).toEqual(payload);
  });
});
