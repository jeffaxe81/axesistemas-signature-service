import { describe, expect, it } from "vitest";
import {
  transitionSignatureStatus,
  transitionUniversalSignatureStatus,
} from "./domain.js";

describe("signature lifecycle", () => {
  it("allows draft -> pending -> signed", () => {
    expect(transitionSignatureStatus("draft", "pending")).toBe("pending");
    expect(transitionSignatureStatus("pending", "signed")).toBe("signed");
  });

  it("allows pending -> rejected/expired/failed", () => {
    expect(transitionSignatureStatus("pending", "rejected")).toBe("rejected");
    expect(transitionSignatureStatus("pending", "expired")).toBe("expired");
    expect(transitionSignatureStatus("pending", "failed")).toBe("failed");
  });

  it("rejects terminal-state mutation", () => {
    for (const terminal of ["signed", "rejected", "expired", "failed"] as const) {
      expect(() => transitionSignatureStatus(terminal, "pending")).toThrow(
        "INVALID_SIGNATURE_TRANSITION"
      );
    }
  });

  it("rejects direct draft -> signed", () => {
    expect(() => transitionSignatureStatus("draft", "signed")).toThrow(
      "INVALID_SIGNATURE_TRANSITION"
    );
  });
});

describe("universal signature lifecycle", () => {
  it("allows participant progress through validation to completion", () => {
    expect(transitionUniversalSignatureStatus("draft", "awaiting_participants")).toBe(
      "awaiting_participants"
    );
    expect(
      transitionUniversalSignatureStatus("awaiting_participants", "partially_completed")
    ).toBe("partially_completed");
    expect(transitionUniversalSignatureStatus("partially_completed", "validating")).toBe(
      "validating"
    );
    expect(transitionUniversalSignatureStatus("validating", "completed")).toBe("completed");
  });

  it("rejects mutation after completion", () => {
    expect(() => transitionUniversalSignatureStatus("completed", "validating")).toThrow(
      "INVALID_UNIVERSAL_SIGNATURE_TRANSITION"
    );
  });
});
