/**
 * Public API types for SSH connection.
 */

import type { Credentials, TerminalConfig } from "../domain/models";

export type { Credentials as SSHCredentials };

export interface SSHConnection {
  write: (data: string | Uint8Array) => void;
  onData: (cb: (data: string) => void) => void;
  resize: (cols: number, rows: number) => void;
  close: () => void;
}

export interface ConnectSSHOptions {
  cols?: number;
  rows?: number;
  onPtyDenied?: () => void;
}
