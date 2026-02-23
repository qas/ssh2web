/**
 * Diffie-Hellman key exchange operations.
 * Single responsibility: DH parameter generation and shared secret computation.
 */
import { modPow } from "./arithmetic";
import { DH_GENERATOR, DH_PRIME } from "../domain/constants";

export async function generateDHPrivate(): Promise<{ x: bigint; e: bigint }> {
  let x: bigint;
  let e: bigint;
  do {
    const xBytes = crypto.getRandomValues(new Uint8Array(32));
    x = 0n;
    for (let i = 0; i < xBytes.length; i++) x = (x << 8n) | BigInt(xBytes[i]);
    x = x % (DH_PRIME - 2n) + 2n;
    e = modPow(DH_GENERATOR, x, DH_PRIME);
  } while (e <= 1n || e >= DH_PRIME - 1n);
  return { x, e };
}

export function computeDHSharedSecret(f: bigint, x: bigint): bigint {
  return modPow(f, x, DH_PRIME);
}

export async function generateX25519KeyPair(): Promise<{ publicKey: Uint8Array; privateKey: CryptoKey }> {
  const keyPair = (await crypto.subtle.generateKey(
    { name: "X25519" },
    true,
    ["deriveBits"]
  )) as CryptoKeyPair;
  const pub = await crypto.subtle.exportKey("raw", keyPair.publicKey);
  return { publicKey: new Uint8Array(pub), privateKey: keyPair.privateKey };
}

export async function computeX25519SharedSecret(privateKey: CryptoKey, publicKey: Uint8Array): Promise<Uint8Array> {
  const buffer = publicKey.byteOffset === 0 && publicKey.byteLength === publicKey.buffer.byteLength
    ? publicKey.buffer
    : publicKey.slice().buffer;
  const pub = await crypto.subtle.importKey("raw", buffer as ArrayBuffer, { name: "X25519" }, false, []);
  const bits = await crypto.subtle.deriveBits({ name: "X25519", public: pub }, privateKey, 256);
  return new Uint8Array(bits);
}
