/**
 * Domain-specific errors and exception handling.
 */

export class SSHError extends Error {
  constructor(message: string) {
    super(message);
    this.name = "SSHError";
  }
}

export class KEXError extends SSHError {
  constructor(message: string) {
    super(message);
    this.name = "KEXError";
  }
}

export class AuthenticationError extends SSHError {
  constructor(message: string) {
    super(message);
    this.name = "AuthenticationError";
  }
}

export class MacVerificationError extends SSHError {
  constructor(message: string) {
    super(message);
    this.name = "MacVerificationError";
  }
}

export class ProtocolError extends SSHError {
  constructor(message: string) {
    super(message);
    this.name = "ProtocolError";
  }
}

export class ChannelError extends SSHError {
  constructor(message: string) {
    super(message);
    this.name = "ChannelError";
  }
}

export class ParseError extends SSHError {
  constructor(message: string) {
    super(message);
    this.name = "ParseError";
  }
}
