/**
 * Key exchange state machine.
 * Manages KEX negotiation and algorithm selection.
 */
import { KexAlgorithm, CipherAlgorithm, MacAlgorithm, AlgorithmNegotiation } from "../domain/models";
import { KEXError } from "../domain/errors";

export type KexPhase = "init" | "negotiating" | "exchanging" | "complete";

export interface KexState {
  phase: KexPhase;
  serverKexList: string[];
  serverHostKeyTypes: string[];
  negotiated: AlgorithmNegotiation | null;
  kexInitC: Uint8Array | null;
  kexInitS: Uint8Array | null;
}

export function createKexState(): KexState {
  return {
    phase: "init",
    serverKexList: [],
    serverHostKeyTypes: [],
    negotiated: null,
    kexInitC: null,
    kexInitS: null,
  };
}

export function selectAlgorithm(
  ourList: string[],
  serverList: string[]
): string | null {
  return ourList.find((a) => serverList.includes(a)) ?? null;
}

export function negotiateAlgorithms(
  preferredKex: string[],
  preferredCipher: string[],
  preferredMac: string[],
  serverKex: string[],
  serverCipher: string[],
  serverMac: string[]
): AlgorithmNegotiation | null {
  const kex = selectAlgorithm(preferredKex, serverKex) as KexAlgorithm | null;
  const cipher = selectAlgorithm(preferredCipher, serverCipher) as CipherAlgorithm | null;
  const mac = selectAlgorithm(preferredMac, serverMac) as MacAlgorithm | null;
  if (!kex || !cipher || !mac) return null;
  return { kex, cipher, mac };
}

export function isValidKex(kex: string): boolean {
  return kex === "curve25519-sha256" ||
    kex === "curve25519-sha256@libssh.org" ||
    kex === "diffie-hellman-group14-sha256";
}

export function transitionKexPhase(current: KexPhase): KexPhase {
  const transitions: Record<KexPhase, KexPhase> = {
    "init": "negotiating",
    "negotiating": "exchanging",
    "exchanging": "complete",
    "complete": "complete",
  };
  return transitions[current];
}
