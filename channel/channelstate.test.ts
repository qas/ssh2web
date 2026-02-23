/**
 * Unit tests for channel state machine.
 */

import { createChannelState, adjustWindowSize } from "./channelstate";

describe("Channel State Machine", () => {
  it("should initialize with default window size", () => {
    const state = createChannelState(0x8000);
    expect(state.phase).toBe("init");
    expect(state.windowSizeLocal).toBe(0x8000);
  });

  it("should adjust window size on data consumption", () => {
    const state = createChannelState(0x8000);
    const adjusted = adjustWindowSize(state, 100);
    expect(adjusted.windowSizeLocal).toBe(0x8000 - 100);
  });
});
