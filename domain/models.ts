/**
 * Domain model value objects and entities.
 * These represent core SSH protocol concepts.
 */

export interface Credentials {
  username: string;
  certificate: string;
  privateKey: string;
}

export interface TerminalConfig {
  cols: number;
  rows: number;
  termType: string;
}

export interface SessionId extends Readonly<{ readonly __brand: unique symbol }> {
  readonly value: Uint8Array;
}

export interface ChannelId extends Readonly<{ readonly __brand: unique symbol }> {
  readonly value: number;
}

export interface SequenceNumber extends Readonly<{ readonly __brand: unique symbol }> {
  readonly value: number;
}

export interface EncryptionKey extends Readonly<{ readonly __brand: unique symbol }> {
  readonly key: CryptoKey;
}

export interface MacKey extends Readonly<{ readonly __brand: unique symbol }> {
  readonly key: Uint8Array;
}

export interface InitializationVector extends Readonly<{ readonly __brand: unique symbol }> {
  readonly value: Uint8Array;
}

export type KexAlgorithm = "curve25519-sha256" | "curve25519-sha256@libssh.org" | "diffie-hellman-group14-sha256";
export type CipherAlgorithm = "aes128-ctr";
export type MacAlgorithm = "hmac-sha2-256" | "hmac-sha2-256-etm@openssh.com";

export interface AlgorithmNegotiation {
  kex: KexAlgorithm;
  cipher: CipherAlgorithm;
  mac: MacAlgorithm;
}

export type SSHMessageType = number;

export const createSessionId = (data: Uint8Array): SessionId => ({ value: data }) as SessionId;
export const createChannelId = (value: number): ChannelId => ({ value }) as ChannelId;
export const createSequenceNumber = (value: number): SequenceNumber => ({ value }) as SequenceNumber;
export const createEncryptionKey = (key: CryptoKey): EncryptionKey => ({ key }) as EncryptionKey;
export const createMacKey = (key: Uint8Array): MacKey => ({ key }) as MacKey;
export const createInitializationVector = (value: Uint8Array): InitializationVector => ({ value }) as InitializationVector;
