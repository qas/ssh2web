/**
 * Authentication state machine.
 * Manages auth flow: service request → userauth → success/failure.
 */

export type AuthPhase = "init" | "service_requested" | "awaiting_pk_ok" | "signed" | "complete" | "failed";

export interface AuthState {
  phase: AuthPhase;
  receivedPKOk: boolean;
  error: string | null;
}

export function createAuthState(): AuthState {
  return {
    phase: "init",
    receivedPKOk: false,
    error: null,
  };
}

export function transitionAuthPhase(current: AuthPhase): AuthPhase {
  const transitions: Record<AuthPhase, AuthPhase> = {
    "init": "service_requested",
    "service_requested": "awaiting_pk_ok",
    "awaiting_pk_ok": "signed",
    "signed": "complete",
    "complete": "complete",
    "failed": "failed",
  };
  return transitions[current];
}

export function setAuthFailed(state: AuthState, error: string): AuthState {
  return { ...state, phase: "failed", error };
}
