/**
 * Key derivation from shared secret to session keys.
 * RFC 4253: derives IVs, encryption keys, and MAC keys.
 */
import { computeSHA256 } from "./digest";

interface DerivedKeys {
  ivC: Uint8Array;
  keyC: Uint8Array;
  macC: Uint8Array;
  ivS: Uint8Array;
  keyS: Uint8Array;
  macS: Uint8Array;
}

export async function deriveKeys(
  sharedSecret: Uint8Array,
  exchangeHash: Uint8Array,
  sessionId: Uint8Array
): Promise<DerivedKeys> {
  const deriveKey = async (id: number): Promise<Uint8Array> => {
    return computeSHA256(concat(sharedSecret, exchangeHash, new Uint8Array([id]), sessionId));
  };
  const ivC = (await deriveKey(0x41)).subarray(0, 16);
  const ivS = (await deriveKey(0x42)).subarray(0, 16);
  const keyC = (await deriveKey(0x43)).subarray(0, 16);
  const keyS = (await deriveKey(0x44)).subarray(0, 16);
  const macC = (await deriveKey(0x45)).subarray(0, 32);
  const macS = (await deriveKey(0x46)).subarray(0, 32);
  return { ivC, keyC, macC, ivS, keyS, macS };
}

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
