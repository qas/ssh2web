/**
 * Builds KEXINIT payload for client key exchange.
 */
import { writeString, writeUint32, concat } from "../protocol/serialization";
import { SSH_MSG_KEXINIT, PREFERRED_KEX, PREFERRED_CIPHER, PREFERRED_MAC } from "../domain/constants";

export function buildKexInit(): Uint8Array {
  const cookie = crypto.getRandomValues(new Uint8Array(16));
  const macList = PREFERRED_MAC.split(",").map((s) => s.trim()).filter(Boolean);
  const lists = [
    PREFERRED_KEX,
    "ssh-ed25519",
    PREFERRED_CIPHER,
    PREFERRED_CIPHER,
    macList.join(","),
    macList.join(","),
    "none",
    "none",
    "",
    "",
  ];
  return concat(
    new Uint8Array([SSH_MSG_KEXINIT]),
    cookie,
    ...lists.map(writeString),
    new Uint8Array([0]),
    writeUint32(0)
  );
}
