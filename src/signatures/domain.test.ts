import { describe, expect, it } from "vitest";
import { transitionSignatureStatus } from "./domain.js";

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
