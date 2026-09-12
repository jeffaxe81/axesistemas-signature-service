import { describe, expect, it } from "vitest";
import { FakeConsentProvider } from "./fakeConsentProvider.js";

const baseInput = {
  tenantId: "tenant-a",
  requestId: "request-1",
  participantId: "participant-1",
  identityEvidenceId: "identity-1",
  documentSha256: "a".repeat(64),
  statementHash: "b".repeat(64),
};

describe("FakeConsentProvider", () => {
  it("records accepted consent with FAKE evidence", async () => {
    const provider = new FakeConsentProvider();
    const result = await provider.record({ ...baseInput, decision: "accepted" });

    expect(result.recorded).toBe(true);
    expect(result.evidence).toEqual({ provider: "fake-consent", decision: "accepted" });
    expect(provider.descriptor.kind).toBe("consent");
    expect(provider.descriptor.trustMode).toBe("fake");
  });

  it("records declined consent with FAKE evidence", async () => {
    const provider = new FakeConsentProvider();
    const result = await provider.record({ ...baseInput, decision: "declined" });

    expect(result.recorded).toBe(true);
    expect(result.evidence).toEqual({ provider: "fake-consent", decision: "declined" });
  });

  it("can simulate provider failure", async () => {
    const provider = new FakeConsentProvider({ fail: true });
    await expect(
      provider.record({ ...baseInput, decision: "accepted" })
    ).rejects.toThrow("IDENTITY_PROVIDER_UNAVAILABLE");
  });
});
