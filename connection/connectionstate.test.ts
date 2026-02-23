/**
 * Unit tests for connection state.
 */

import { createConnectionState, setFatalError, transitionConnectionPhase } from "./connectionstate";
import type { ConnectionPhase } from "./connectionstate";

describe("Connection State", () => {
  describe("createConnectionState", () => {
    it("should initialize with ident_exchange phase", () => {
      const state = createConnectionState(0x8000);
      expect(state.phase).toBe("ident_exchange");
      expect(state.serverIdent).toBe("");
      expect(state.sessionId).toBeNull();
      expect(state.cipher).toBeNull();
      expect(state.fatalError).toBeNull();
    });
    it("should set channel window size from argument", () => {
      const state = createConnectionState(0x4000);
      expect(state.channel.windowSizeLocal).toBe(0x4000);
      expect(state.channel.windowSizeRemote).toBe(0x4000);
    });
  });
  describe("setFatalError", () => {
    it("should set phase to error and store message", () => {
      const state = createConnectionState(0x8000);
      const next = setFatalError(state, "test error");
      expect(next.phase).toBe("error");
      expect(next.fatalError).toBe("test error");
    });
  });
  describe("transitionConnectionPhase", () => {
    it("should transition ident_exchange -> kex -> auth -> channel_open -> active", () => {
      expect(transitionConnectionPhase("ident_exchange")).toBe("kex");
      expect(transitionConnectionPhase("kex")).toBe("auth");
      expect(transitionConnectionPhase("auth")).toBe("channel_open");
      expect(transitionConnectionPhase("channel_open")).toBe("active");
      expect(transitionConnectionPhase("active")).toBe("active");
    });
    it("should keep closed and error unchanged", () => {
      expect(transitionConnectionPhase("closed")).toBe("closed");
      expect(transitionConnectionPhase("error")).toBe("error");
    });
  });
});
