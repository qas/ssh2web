/**
 * RFC 4253 SSH binary packet format.
 * Single responsibility: Packet structure encoding/decoding without encryption.
 */
import { AES_BLOCK_SIZE, MIN_PADDING } from "../domain/constants";
import { writeUint32, concat } from "./serialization";

export interface ParsedPacket {
  payload: Uint8Array;
  consumed: number;
}

export function buildPacket(payload: Uint8Array, etm = false): Uint8Array {
  const padLen = calculatePadding(payload.length, etm);
  const plen = 1 + payload.length + padLen;
  const out = new Uint8Array(4 + plen);
  const view = new DataView(out.buffer);
  view.setUint32(0, plen, false);
  out[4] = padLen;
  out.set(payload, 5);
  crypto.getRandomValues(out.subarray(5 + payload.length, 5 + payload.length + padLen));
  return out;
}

export function parsePacket(data: Uint8Array): ParsedPacket | null {
  if (data.length < 5) return null;
  const plen = new DataView(data.buffer, data.byteOffset, 4).getUint32(0, false);
  const total = 4 + plen;
  if (data.length < total) return null;
  const padLen = data[4];
  const payloadLen = plen - 1 - padLen;
  const payload = data.slice(5, 5 + payloadLen);
  return { payload, consumed: total };
}

function calculatePadding(payloadLen: number, etm: boolean): number {
  if (etm) {
    const innerLen = 1 + payloadLen;
    return MIN_PADDING + (AES_BLOCK_SIZE - ((innerLen + MIN_PADDING) % AES_BLOCK_SIZE)) % AES_BLOCK_SIZE;
  }
  return MIN_PADDING + (AES_BLOCK_SIZE - ((5 + payloadLen + MIN_PADDING) % AES_BLOCK_SIZE)) % AES_BLOCK_SIZE;
}
