/**
 * Unit tests for domain errors.
 */

import {
  SSHError,
  KEXError,
  AuthenticationError,
  MacVerificationError,
  ProtocolError,
  ChannelError,
  ParseError,
} from "./errors";

describe("Domain Errors", () => {
  it("should set name and message for SSHError", () => {
    const e = new SSHError("test");
    expect(e.name).toBe("SSHError");
    expect(e.message).toBe("test");
    expect(e).toBeInstanceOf(Error);
  });
  it("should set name for KEXError", () => {
    const e = new KEXError("kex failed");
    expect(e.name).toBe("KEXError");
    expect(e).toBeInstanceOf(SSHError);
  });
  it("should set name for MacVerificationError", () => {
    const e = new MacVerificationError("MAC failed");
    expect(e.name).toBe("MacVerificationError");
  });
  it("should set name for ProtocolError", () => {
    const e = new ProtocolError("bad packet");
    expect(e.name).toBe("ProtocolError");
  });
  it("should set name for ParseError", () => {
    const e = new ParseError("parse failed");
    expect(e.name).toBe("ParseError");
  });
});
