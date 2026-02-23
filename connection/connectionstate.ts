/**
 * Overall connection state machine.
 * Tracks: version exchange → kex → auth → channel open → data.
 */
import { KexState } from "../kex/kexstate";
import { AuthState } from "../auth/authstate";
import { ChannelState } from "../channel/channelstate";
import { TransportCipher } from "../transport/transportcipher";

export type ConnectionPhase = "ident_exchange" | "kex" | "auth" | "channel_open" | "active" | "closed" | "error";

export interface ConnectionState {
  phase: ConnectionPhase;
  serverIdent: string;
  sessionId: Uint8Array | null;
  kex: KexState;
  auth: AuthState;
  channel: ChannelState;
  cipher: TransportCipher | null;
  fatalError: string | null;
}

export function createConnectionState(defaultWindowSize: number): ConnectionState {
  return {
    phase: "ident_exchange",
    serverIdent: "",
    sessionId: null,
    kex: {
      phase: "init",
      serverKexList: [],
      serverHostKeyTypes: [],
      negotiated: null,
      kexInitC: null,
      kexInitS: null,
    },
    auth: {
      phase: "init",
      receivedPKOk: false,
      error: null,
    },
    channel: {
      phase: "init",
      clientChannelId: 0,
      serverChannelId: 0,
      windowSizeLocal: defaultWindowSize,
      windowSizeRemote: defaultWindowSize,
      ptySent: false,
      shellSent: false,
    },
    cipher: null,
    fatalError: null,
  };
}

export function setFatalError(state: ConnectionState, error: string): ConnectionState {
  return { ...state, phase: "error", fatalError: error };
}

export function transitionConnectionPhase(current: ConnectionPhase): ConnectionPhase {
  const transitions: Record<ConnectionPhase, ConnectionPhase> = {
    "ident_exchange": "kex",
    "kex": "auth",
    "auth": "channel_open",
    "channel_open": "active",
    "active": "active",
    "closed": "closed",
    "error": "error",
  };
  return transitions[current];
}
