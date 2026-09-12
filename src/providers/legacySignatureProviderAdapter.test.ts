import { describe, expect, it } from "vitest";
import { FakeSignatureProvider } from "./fakeSignatureProvider.js";
import { LegacySignatureProviderAdapter } from "./legacySignatureProviderAdapter.js";

describe("LegacySignatureProviderAdapter", () => {
  it("adapta o provider v0.1.0 sem alterar seu contrato", async () => {
    const legacy = new FakeSignatureProvider();
    const adapter = new LegacySignatureProviderAdapter(legacy);

    const result = await adapter.sign({
      requestId: "req-1",
      participantId: "participant-1",
      documentSha256: "abc",
      level: "simple",
      format: "detached",
    });

    expect(result).toEqual({ providerRequestId: "fake:req-1", status: "pending" });
  });
});
