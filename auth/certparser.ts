/**
 * SSH certificate parsing.
 * Extracts key type and certificate blob from base64-encoded format.
 */

export function parseCertBase64(cert: string): { keyType: string; certBlob: Uint8Array } {
  const parts = cert.trim().replace(/\s+/g, " ").split(" ");
  if (parts.length < 2) throw new Error("Invalid certificate format");
  const keyType = parts[0];
  const b64 = parts[1].replace(/\s/g, "");
  const certBlob = Uint8Array.from(atob(b64), (c) => c.charCodeAt(0));
  return { keyType, certBlob };
}
