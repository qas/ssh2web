/**
 * AES-128-CTR encryption and decryption.
 * Single responsibility: AES-CTR mode operations.
 */
import { AES_BLOCK_SIZE } from "../domain/constants";

function incrementCounter(iv: Uint8Array, count = 1): Uint8Array {
  const result = new Uint8Array(iv);
  let carry = count;
  for (let i = 15; i >= 0 && carry > 0; i--) {
    const sum = result[i] + carry;
    result[i] = sum & 0xff;
    carry = sum >> 8;
  }
  return result;
}

export async function encryptAES128CTR(
  key: CryptoKey,
  iv: Uint8Array,
  plaintext: Uint8Array
): Promise<{ ciphertext: Uint8Array; nextIv: Uint8Array }> {
  const ciphertext: Uint8Array = new Uint8Array(plaintext.length);
  const blocks = Math.ceil(plaintext.length / AES_BLOCK_SIZE);
  let offset = 0;
  let ivCopy: Uint8Array = new Uint8Array(iv);
  for (let i = 0; i < blocks; i++) {
    const blockLen = Math.min(AES_BLOCK_SIZE, plaintext.length - offset);
    const enc = await crypto.subtle.encrypt(
      { name: "AES-CTR", counter: ivCopy as BufferSource, length: 128 },
      key,
      plaintext.subarray(offset, offset + blockLen) as BufferSource
    );
    ciphertext.set(new Uint8Array(enc as ArrayBuffer) as unknown as Uint8Array<ArrayBuffer>, offset);
    offset += blockLen;
    ivCopy = incrementCounter(ivCopy, 1);
  }
  return { ciphertext, nextIv: ivCopy };
}

export async function decryptAES128CTR(
  key: CryptoKey,
  iv: Uint8Array,
  ciphertext: Uint8Array
): Promise<{ plaintext: Uint8Array; nextIv: Uint8Array }> {
  const plaintext: Uint8Array = new Uint8Array(ciphertext.length);
  const blocks = Math.ceil(ciphertext.length / AES_BLOCK_SIZE);
  let offset = 0;
  let ivCopy: Uint8Array = new Uint8Array(iv);
  for (let i = 0; i < blocks; i++) {
    const blockLen = Math.min(AES_BLOCK_SIZE, ciphertext.length - offset);
    const dec = await crypto.subtle.decrypt(
      { name: "AES-CTR", counter: ivCopy as BufferSource, length: 128 },
      key,
      ciphertext.subarray(offset, offset + blockLen) as BufferSource
    );
    plaintext.set(new Uint8Array(dec as ArrayBuffer) as unknown as Uint8Array<ArrayBuffer>, offset);
    offset += blockLen;
    ivCopy = incrementCounter(ivCopy, 1);
  }
  return { plaintext, nextIv: ivCopy };
}
