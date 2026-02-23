/**
 * Debug logging utility.
 * Controlled by localStorage.ssh_debug flag.
 */

const DEBUG = typeof window === "undefined" || localStorage.getItem("ssh_debug") !== "0";

export function log(...args: unknown[]): void {
  if (DEBUG) console.log("[SSH]", ...args);
}

export function logDebug(...args: unknown[]): void {
  if (DEBUG) console.log("[SSH_DEBUG]", ...args);
}

export function logError(...args: unknown[]): void {
  console.error("[SSH_ERROR]", ...args);
}

export function logWarn(...args: unknown[]): void {
  console.warn("[SSH_WARN]", ...args);
}
