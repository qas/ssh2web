/**
 * Unit tests for message type names.
 */

import { getMessageName } from "./messages";

describe("Message Names", () => {
  it("should return known names for standard message types", () => {
    expect(getMessageName(1)).toBe("DISCONNECT");
    expect(getMessageName(20)).toBe("KEXINIT");
    expect(getMessageName(21)).toBe("NEWKEYS");
    expect(getMessageName(50)).toBe("USERAUTH_REQUEST");
    expect(getMessageName(52)).toBe("USERAUTH_SUCCESS");
    expect(getMessageName(94)).toBe("CHANNEL_DATA");
    expect(getMessageName(100)).toBe("CHANNEL_FAILURE");
  });
  it("should return msgN for unknown message types", () => {
    expect(getMessageName(0)).toBe("msg0");
    expect(getMessageName(255)).toBe("msg255");
  });
});
