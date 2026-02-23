/**
 * SSH protocol deserialization (reading data types from packets).
 * Single responsibility: Decoding strings, bytes, and integers.
 */
import { ParseError } from "../domain/errors";

export interface StringValue {
  value: string;
  consumed: number;
}

export interface BytesValue {
  value: Uint8Array;
  consumed: number;
}

export interface BigintValue {
  value: bigint;
  consumed: number;
}

export function readString(data: Uint8Array, offset: number): StringValue | null {
  if (offset + 4 > data.length) return null;
  const len = new DataView(data.buffer, data.byteOffset + offset, 4).getUint32(0, false);
  if (offset + 4 + len > data.length) return null;
  const value = new TextDecoder().decode(data.subarray(offset + 4, offset + 4 + len));
  return { value, consumed: 4 + len };
}

export function readBytes(data: Uint8Array, offset: number): BytesValue | null {
  if (offset + 4 > data.length) return null;
  const len = new DataView(data.buffer, data.byteOffset + offset, 4).getUint32(0, false);
  if (offset + 4 + len > data.length) return null;
  const value = data.slice(offset + 4, offset + 4 + len);
  return { value, consumed: 4 + len };
}

export function readMpint(data: Uint8Array, offset: number): BigintValue | null {
  const rb = readBytes(data, offset);
  if (!rb) return null;
  const b = rb.value;
  let n = 0n;
  for (let i = 0; i < b.length; i++) n = (n << 8n) | BigInt(b[i]);
  if (b.length > 0 && (b[0] & 0x80)) n -= 1n << BigInt(b.length * 8);
  return { value: n, consumed: rb.consumed };
}

export function readStringThrows(data: Uint8Array, offset: number): StringValue {
  const result = readString(data, offset);
  if (!result) throw new ParseError(`Failed to read string at offset ${offset}`);
  return result;
}

export function readBytesThrows(data: Uint8Array, offset: number): BytesValue {
  const result = readBytes(data, offset);
  if (!result) throw new ParseError(`Failed to read bytes at offset ${offset}`);
  return result;
}

export function readMpintThrows(data: Uint8Array, offset: number): BigintValue {
  const result = readMpint(data, offset);
  if (!result) throw new ParseError(`Failed to read mpint at offset ${offset}`);
  return result;
}
