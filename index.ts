/**
 * Public API barrel export.
 * Architecture: domain, crypto, protocol, transport, state machines (kex/auth/channel/connection), connection orchestrator.
 */

export { connectSSH } from "./connection/connectSSH";
export type { SSHConnection, ConnectSSHOptions, SSHCredentials } from "./connection/types";
export { SSHError, KEXError, AuthenticationError, MacVerificationError, ProtocolError, ChannelError, ParseError } from "./domain/errors";
