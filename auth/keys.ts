/**
 * Certificate and private key parsing.
 * Extracts key material from PEM and base64-encoded SSH certs.
 */

export async function parsePemPrivateKey(pem: string): Promise<CryptoKey> {
  const m = pem.match(/-----BEGIN PRIVATE KEY-----([\s\S]*?)-----END PRIVATE KEY-----/);
  if (!m) throw new Error("Invalid PEM format");
  const b64 = m[1].replace(/\s/g, "");
  const der = Uint8Array.from(atob(b64), (c) => c.charCodeAt(0));
  return crypto.subtle.importKey("pkcs8", der as BufferSource, { name: "Ed25519" }, false, ["sign"]);
}

export async function ed25519Sign(privateKey: CryptoKey, data: Uint8Array): Promise<Uint8Array> {
  const buffer = data.byteOffset === 0 && data.byteLength === data.buffer.byteLength
    ? data.buffer
    : data.slice().buffer;
  return new Uint8Array(await crypto.subtle.sign({ name: "Ed25519" }, privateKey, buffer as ArrayBuffer));
}
