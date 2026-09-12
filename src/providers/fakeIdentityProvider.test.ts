import { describe, expect, it } from "vitest";
import { FakeIdentityProvider } from "./fakeIdentityProvider.js";

const input = {
  tenantId: "tenant-a",
  requestId: "request-1",
  participantId: "participant-1",
  method: "fake" as const,
};

async function begin(provider: FakeIdentityProvider) {
  return provider.beginVerification(input);
}

describe("FakeIdentityProvider", () => {
  it("returns deterministic FAKE verification evidence", async () => {
    const provider = new FakeIdentityProvider({ assurance: "strong" });
    const started = await begin(provider);

    const result = await provider.completeVerification({
      tenantId: input.tenantId,
      requestId: input.requestId,
      participantId: input.participantId,
      providerSessionId: started.providerSessionId,
      challengeId: started.challengeId,
      response: { answer: "FAKE-OK" },
    });

    expect(result.verified).toBe(true);
    expect(result.assurance).toBe("strong");
    expect(result.evidence).toMatchObject({ provider: "fake-identity", outcome: "verified" });
    expect(provider.descriptor.kind).toBe("identity");
    expect(provider.descriptor.trustMode).toBe("fake");
  });

  it("returns denied for FAKE-DENY", async () => {
    const provider = new FakeIdentityProvider({ assurance: "strong" });
    const started = await begin(provider);
    const result = await provider.completeVerification({
      tenantId: input.tenantId,
      requestId: input.requestId,
      participantId: input.participantId,
      providerSessionId: started.providerSessionId,
      challengeId: started.challengeId,
      response: { answer: "FAKE-DENY" },
    });

    expect(result.verified).toBe(false);
    expect(result.denied).toBe(true);
  });

  it("returns unverified for an invalid answer", async () => {
    const provider = new FakeIdentityProvider({ assurance: "strong" });
    const started = await begin(provider);
    const result = await provider.completeVerification({
      tenantId: input.tenantId,
      requestId: input.requestId,
      participantId: input.participantId,
      providerSessionId: started.providerSessionId,
      challengeId: started.challengeId,
      response: { answer: "WRONG" },
    });

    expect(result.verified).toBe(false);
    expect(result.denied).toBeUndefined();
  });

  it("returns the configured assurance without making policy decisions", async () => {
    const provider = new FakeIdentityProvider({ assurance: "basic" });
    const started = await begin(provider);
    const result = await provider.completeVerification({
      tenantId: input.tenantId,
      requestId: input.requestId,
      participantId: input.participantId,
      providerSessionId: started.providerSessionId,
      challengeId: started.challengeId,
      response: { answer: "FAKE-OK" },
    });

    expect(result.verified).toBe(true);
    expect(result.assurance).toBe("basic");
  });

  it("can simulate provider failure", async () => {
    const provider = new FakeIdentityProvider({ assurance: "strong", fail: true });
    const started = await begin(provider);

    await expect(
      provider.completeVerification({
        tenantId: input.tenantId,
        requestId: input.requestId,
        participantId: input.participantId,
        providerSessionId: started.providerSessionId,
        challengeId: started.challengeId,
        response: { answer: "FAKE-OK" },
      })
    ).rejects.toThrow("IDENTITY_PROVIDER_UNAVAILABLE");
  });
});
