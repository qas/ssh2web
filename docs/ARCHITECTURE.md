## SSH Client - Architecture

This library is structured with DDD (Domain-Driven Design): strict layer separation, strong cohesion, and test-friendly boundaries.

### Directory Structure

```
sshClient/
├── domain/                    # Core domain models & constants (no dependencies)
│   ├── models.ts             # Value objects & entities (SessionId, ChannelId, etc.)
│   ├── errors.ts             # Domain-specific exceptions
│   └── constants.ts          # SSH protocol constants
│
├── crypto/                   # Cryptographic operations (isolated)
│   ├── digest.ts             # SHA256 hashing
│   ├── cipher.ts             # AES-128-CTR encryption/decryption
│   ├── mac.ts                # HMAC-SHA256 & constant-time comparison
│   ├── arithmetic.ts         # BigInt utilities & modular exponentiation
│   ├── keyexchange.ts        # DH & ECDH key pair generation
│   ├── keys.ts               # Key derivation from shared secret
│   └── *.test.ts             # Unit tests (colocated)
│
├── protocol/                 # SSH packet codec (no crypto, no transport)
│   ├── serialization.ts      # Write strings, bytes, integers
│   ├── deserialization.ts    # Read strings, bytes, integers
│   ├── codec.ts              # RFC 4253 packet format encoding/decoding
│   ├── messages.ts           # SSH message type utilities
│   └── *.test.ts             # Unit tests (colocated)
│
├── transport/                # Transport layer encryption/decryption
│   ├── transportcipher.ts    # Combined AES-CTR + HMAC state machine
│   └── *.test.ts             # Unit tests (colocated)
│
├── kex/                      # Key exchange state & negotiation
│   ├── kexstate.ts           # KEX state machine & algorithm selection
│   ├── builder.ts            # KEXINIT payload builder
│   └── *.test.ts             # Unit tests (colocated)
│
├── auth/                     # Authentication state & key management
│   ├── authstate.ts          # Auth state machine transitions
│   ├── certparser.ts         # SSH certificate parsing
│   ├── keys.ts               # PEM private key loading & Ed25519 signing
│   └── *.test.ts             # Unit tests (colocated)
│
├── channel/                  # SSH channel state management
│   ├── channelstate.ts       # Channel lifecycle & window management
│   └── *.test.ts             # Unit tests (colocated)
│
├── connection/               # Connection orchestration
│   ├── connectionstate.ts    # Overall connection state machine
│   ├── connectSSH.ts         # Main orchestrator (ties all layers)
│   ├── types.ts              # Public API types
│   └── *.test.ts             # Tests (colocated)
│
├── debug.ts                  # Logging utilities
└── index.ts                  # Public API barrel export
```

### Layer Boundaries & Responsibilities

#### 1. **Domain Layer** (`domain/`)
- Pure domain logic: models, constants, errors
- **Zero external dependencies**
- Single Responsibility: Define domain concepts

```typescript
// No imports from other sshClient modules
export interface SessionId extends Readonly<{ readonly __brand: unique symbol }> {
  readonly value: Uint8Array;
}
```

#### 2. **Crypto Layer** (`crypto/`)
- Cryptographic primitives: hash, cipher, MAC, key exchange
- **Only depends on**: domain layer + Web Crypto API
- Single files per operation:
  - `digest.ts`: SHA256
  - `cipher.ts`: AES-128-CTR
  - `mac.ts`: HMAC-SHA256
  - `keyexchange.ts`: DH & ECDH
  - `keys.ts`: Key derivation
  - `arithmetic.ts`: BigInt utilities

```typescript
// digest.ts - no protocol knowledge
export async function computeSHA256(data: Uint8Array): Promise<Uint8Array> {
  // Pure crypto operation
}
```

#### 3. **Protocol Layer** (`protocol/`)
- SSH packet codec: encode/decode without transport
- **Only depends on**: domain layer
- Separate concerns:
  - `serialization.ts`: Write operations (strings, bytes, integers)
  - `deserialization.ts`: Read operations (strings, bytes, integers)
  - `codec.ts`: RFC 4253 packet format (padding, length calculation)
  - `messages.ts`: Message type utilities

```typescript
// serialization.ts - no encryption, no crypto
export function writeString(s: string): Uint8Array {
  // Plain protocol encoding
}
```

#### 4. **Transport Layer** (`transport/`)
- **Stateful** encryption/decryption with MAC verification
- **Only depends on**: domain, crypto, protocol layers
- Single class: `TransportCipher`

```typescript
// transportcipher.ts - combines crypto + protocol
class TransportCipher {
  async encrypt(payload: Uint8Array): Promise<EncryptResult>
  async decrypt(data: Uint8Array): Promise<DecryptResult | null>
}
```

#### 5. **State Machines** (`kex/`, `auth/`, `channel/`)
- Pure state transitions (no side effects)
- **Only depends on**: domain layer
- Each module handles one state machine:
  - KEX: Algorithm negotiation & key exchange phases
  - Auth: Authentication flow phases
  - Channel: Channel lifecycle phases
  - Connection: Overall connection phases

```typescript
// kexstate.ts - pure state, no IO
export function negotiateAlgorithms(
  preferredKex: string[],
  preferredCipher: string[],
  preferredMac: string[],
  serverKex: string[],
  serverCipher: string[],
  serverMac: string[]
): AlgorithmNegotiation | null
```

#### 6. **Connection Orchestrator** (`connection/connectSSH.ts`)
- **Coordinates all layers**: domain → crypto → protocol → transport → state
- Single entry point: `connectSSH()`
- Handles SSH protocol flow:
  1. Version exchange
  2. KEX negotiation & key derivation
  3. Authentication with Ed25519 certs
  4. Channel open & PTY allocation
  5. Shell setup & data exchange
- Returns public API: `SSHConnection`

### Design Principles

#### Strong Cohesion
- Each module has a single, well-defined responsibility
- No scattered concern logic

#### Weak Coupling
- Layers only know about layers below them
- No circular dependencies
- Tests can mock each layer independently

#### Test-Friendly Architecture
- **Colocated tests**: `*.test.ts` files next to source
- Each layer testable in isolation:
  - Crypto layer: no WebSocket needed
  - Protocol layer: no encryption needed
  - State machines: no async/IO needed
- Example:

```typescript
// protocol/serialization.test.ts
describe("writeString", () => {
  it("should encode with length prefix", () => {
    const result = writeString("hello");
    expect(result.length).toBe(4 + 5);
  });
});
```

#### Public API
- Single entry point: `index.ts` re-exports `connectSSH` and types from `connection/`.
- Consumers import from the package or path:
  ```typescript
  import { connectSSH } from "ssh2webclient"
  ```

### Data Flow

```
Caller / application
    |
connectSSH(ws, creds) <- index.ts (public API)
    |
SSHConnectionOrchestrator.start()
    | (receives SSH version)
    |- negotiateAlgorithms()     [state machines]
    |- generateKeyPair()         [crypto layer]
    |- buildKexInit()            [kex state]
    |- createTransportCipher()   [transport layer]
         |- deriveKeys()          [crypto: key derivation]
         |- encryptAES128CTR()    [crypto: cipher]
         |- computeHMACSHA256()   [crypto: MAC]
    |
    |- sendEncrypted()
    |    - cipher.encrypt()       [transport layer]
    |- receiveEncrypted()
         - cipher.decrypt()      [transport layer]
    |
    onData() callback with server output
```

### Testability Example

```typescript
// Test crypto in isolation (no protocol, no transport, no WebSocket)
describe("Arithmetic", () => {
  it("modPow", () => {
    expect(modPow(2n, 10n, 1000n)).toBe(24n);
  });
});

// Test protocol in isolation (no crypto, no encryption)
describe("Serialization", () => {
  it("writeString", () => {
    expect(writeString("test").length).toBe(4 + 4);
  });
});

// Test state machines (no async, no side effects)
describe("KEX State", () => {
  it("negotiateAlgorithms", () => {
    const result = negotiateAlgorithms(["curve25519-sha256"], ...);
    expect(result?.kex).toBe("curve25519-sha256");
  });
});
```

### Modification Guide

**To add a new crypto algorithm:**
1. Create `crypto/newalgos.ts`
2. Implement crypto operations
3. Add unit tests alongside: `crypto/newalgos.test.ts`
4. Update `transport/transportcipher.ts` to use new layer
5. Update state machines if algorithm selection changes

**To fix a protocol bug:**
1. Locate bug in `protocol/*.ts`
2. Write failing test in `protocol/*.test.ts`
3. Fix implementation
4. Test still passes in isolation (without crypto)

**To add new SSH message handling:**
1. Add message type to `domain/constants.ts`
2. Add handler logic in `connection/connectSSH.ts`
3. Add or extend tests in `connection/` or exercise via integration.
