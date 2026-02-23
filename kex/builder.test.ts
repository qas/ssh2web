/**
 * Unit tests for KEXINIT builder.
 */

import { buildKexInit } from "./builder";
import { SSH_MSG_KEXINIT } from "../domain/constants";

describe("KEX Builder", () => {
  it("should start with SSH_MSG_KEXINIT byte", () => {
    const payload = buildKexInit();
    expect(payload[0]).toBe(SSH_MSG_KEXINIT);
  });
  it("should include 16-byte cookie after message type", () => {
    const payload = buildKexInit();
    expect(payload.length).toBeGreaterThan(1 + 16);
  });
  it("should produce different cookies on each call", () => {
    const a = buildKexInit();
    const b = buildKexInit();
    const cookieA = a.subarray(1, 17);
    const cookieB = b.subarray(1, 17);
    expect(cookieA).not.toEqual(cookieB);
  });
});
