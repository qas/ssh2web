/**
 * Unit tests for auth state machine.
 */

import { createAuthState, setAuthFailed } from "./authstate";

describe("Auth State Machine", () => {
  it("should initialize with correct defaults", () => {
    const state = createAuthState();
    expect(state.phase).toBe("init");
    expect(state.receivedPKOk).toBe(false);
  });

  it("should set failed state", () => {
    const state = createAuthState();
    const failed = setAuthFailed(state, "Auth rejected");
    expect(failed.phase).toBe("failed");
    expect(failed.error).toBe("Auth rejected");
  });
});
