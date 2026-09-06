import { describe, expect, it } from "vitest";
import { InMemorySignatureRepository } from "../db/signatureRepository.js";
import type { DocumentStore } from "../documents/documentStore.js";
import { FakeSignatureProvider } from "../providers/fakeSignatureProvider.js";
import { SignatureService } from "./signatureService.js";

class MemoryDocumentStore implements DocumentStore {
  lastPut?: { tenantId: string; requestId: string; bytes: Buffer; contentType?: string };

  async put(input: { tenantId: string; requestId: string; bytes: Buffer; contentType?: string }) {
    this.lastPut = input;
    return { key: `${input.tenantId}/${input.requestId}`, sizeBytes: input.bytes.length, contentType: input.contentType };
  }

  async get(): Promise<Buffer | null> {
    return null;
  }
}

describe("SignatureService", () => {
  it("hashes and stores the closed document before sending it to the provider", async () => {
    const repo = new InMemorySignatureRepository();
    const store = new MemoryDocumentStore();
    const provider = new FakeSignatureProvider();
    const service = new SignatureService({
      repository: repo,
      documentStore: store,
      provider,
      idFactory: () => "req-1",
      now: () => "2026-09-06T17:30:00.000Z",
    });

    const result = await service.createSignatureRequest(
      { tenantId: "tenant-a", subject: "dispatch" },
      { document: Buffer.from("doc"), signer: { name: "Ana" }, contentType: "application/pdf" }
    );

    expect(store.lastPut?.tenantId).toBe("tenant-a");
    expect(store.lastPut?.requestId).toBe("req-1");
    expect(provider.lastCreate?.documentSha256).toBe(result.documentSha256);
    expect(provider.lastCreate?.requestId).toBe("req-1");
    expect(result.status).toBe("pending");
    expect(result.providerRequestId).toBe("fake:req-1");
    await expect(repo.findById("tenant-a", "req-1")).resolves.toEqual(result);
  });
});
