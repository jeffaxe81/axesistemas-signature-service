import { describe, expect, it } from "vitest";
import { FakeSignatureProvider } from "./fakeSignatureProvider.js";

describe("FakeSignatureProvider", () => {
  it("returns a deterministic provider request id without external I/O", async () => {
    const provider = new FakeSignatureProvider();
    await expect(
      provider.createRequest({ requestId: "req-1", documentSha256: "abc" })
    ).resolves.toEqual({ providerRequestId: "fake:req-1" });
  });

  it("accepts cancellation without external I/O", async () => {
    const provider = new FakeSignatureProvider();
    await expect(provider.cancelRequest("fake:req-1")).resolves.toBeUndefined();
  });
});
