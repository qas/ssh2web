/**
 * SSH message type utilities and debug information.
 */

const MESSAGE_NAMES: Record<number, string> = {
  1: "DISCONNECT",
  3: "UNIMPLEMENTED",
  4: "DEBUG",
  5: "SERVICE_REQUEST",
  6: "SERVICE_ACCEPT",
  7: "EXT_INFO",
  20: "KEXINIT",
  21: "NEWKEYS",
  30: "KEX_DH_INIT",
  31: "KEX_DH_REPLY",
  50: "USERAUTH_REQUEST",
  51: "USERAUTH_FAILURE",
  52: "USERAUTH_SUCCESS",
  60: "USERAUTH_PK_OK",
  80: "GLOBAL_REQUEST",
  81: "REQUEST_SUCCESS",
  82: "REQUEST_FAILURE",
  90: "CHANNEL_OPEN",
  91: "CHANNEL_OPEN_CONFIRMATION",
  93: "CHANNEL_WINDOW_ADJUST",
  94: "CHANNEL_DATA",
  95: "CHANNEL_EXTENDED_DATA",
  98: "CHANNEL_REQUEST",
  99: "CHANNEL_SUCCESS",
  100: "CHANNEL_FAILURE",
};

export function getMessageName(msgType: number): string {
  return MESSAGE_NAMES[msgType] ?? `msg${msgType}`;
}
