/**
 * Cryptographic hashing operations.
 * Single responsibility: SHA256 hashing via Web Crypto API.
 */

export async function computeSHA256(data: Uint8Array): Promise<Uint8Array> {
  const buffer = data.byteOffset === 0 && data.byteLength === data.buffer.byteLength
    ? data.buffer
    : data.slice().buffer;
  return new Uint8Array(await crypto.subtle.digest("SHA-256", buffer as ArrayBuffer));
}
