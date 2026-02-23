/**
 * Channel management state machine.
 * Tracks channel lifecycle: open → pty_request → shell → data_exchange.
 */

export type ChannelPhase = "init" | "opening" | "open" | "pty_requested" | "shell_requested" | "active" | "closed";

export interface ChannelState {
  phase: ChannelPhase;
  clientChannelId: number;
  serverChannelId: number;
  windowSizeLocal: number;
  windowSizeRemote: number;
  ptySent: boolean;
  shellSent: boolean;
}

export function createChannelState(defaultWindowSize: number): ChannelState {
  return {
    phase: "init",
    clientChannelId: 0,
    serverChannelId: 0,
    windowSizeLocal: defaultWindowSize,
    windowSizeRemote: defaultWindowSize,
    ptySent: false,
    shellSent: false,
  };
}

export function transitionChannelPhase(current: ChannelPhase): ChannelPhase {
  const transitions: Record<ChannelPhase, ChannelPhase> = {
    "init": "opening",
    "opening": "open",
    "open": "pty_requested",
    "pty_requested": "shell_requested",
    "shell_requested": "active",
    "active": "active",
    "closed": "closed",
  };
  return transitions[current];
}

export function adjustWindowSize(state: ChannelState, consumed: number): ChannelState {
  return { ...state, windowSizeLocal: state.windowSizeLocal - consumed };
}
