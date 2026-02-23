/**
 * SSH protocol serialization (writing data types to packets).
 * Single responsibility: Encoding strings, bytes, and integers.
 */

export function writeString(s: string): Uint8Array {
  const enc = new TextEncoder().encode(s);
  const out = new Uint8Array(4 + enc.length);
  new DataView(out.buffer).setUint32(0, enc.length, false);
  out.set(enc, 4);
  return out;
}

export function writeBytes(b: Uint8Array): Uint8Array {
  const out = new Uint8Array(4 + b.length);
  new DataView(out.buffer).setUint32(0, b.length, false);
  out.set(b, 4);
  return out;
}

export function writeUint32(n: number): Uint8Array {
  const out = new Uint8Array(4);
  new DataView(out.buffer).setUint32(0, n, false);
  return out;
}

export function writeBigintMpint(n: bigint): Uint8Array {
  if (n === 0n) return writeBytes(new Uint8Array(0));
  const neg = n < 0n;
  if (neg) n = -n;
  let bytes = bigintToBytes(n);
  if (bytes[0] & 0x80) {
    const tmp = new Uint8Array(bytes.length + 1);
    tmp[0] = 0;
    tmp.set(bytes, 1);
    bytes = tmp;
  }
  return writeBytes(bytes);
}

export function writeByteMpint(k: Uint8Array): Uint8Array {
  let kk = k;
  if (kk.length > 0 && (kk[0] & 0x80) !== 0) {
    const tmp = new Uint8Array(kk.length + 1);
    tmp[0] = 0;
    tmp.set(kk, 1);
    kk = tmp;
  }
  return writeBytes(kk);
}

export function concat(...arr: Uint8Array[]): Uint8Array {
  const len = arr.reduce((a, b) => a + b.length, 0);
  const out = new Uint8Array(len);
  let off = 0;
  for (const a of arr) {
    out.set(a, off);
    off += a.length;
  }
  return out;
}

function bigintToBytes(n: bigint): Uint8Array {
  if (n === 0n) return new Uint8Array([0]);
  let hex = n.toString(16);
  if (hex.length % 2) hex = "0" + hex;
  const bytes = new Uint8Array(hex.length / 2);
  for (let i = 0; i < bytes.length; i++) {
    bytes[i] = parseInt(hex.slice(i * 2, i * 2 + 2), 16);
  }
  return bytes;
}
