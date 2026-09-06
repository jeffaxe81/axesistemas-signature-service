import { describe, expect, it } from "vitest";
import {
  InMemorySignatureRepository,
  type SignatureEvidence,
} from "../db/signatureRepository.js";
import { ProviderWebhookHandler, InMemoryProviderEventStore } from "./providerWebhookHandler.js";

class CountingRepository extends InMemorySignatureRepository {
  statusUpdateCount = 0;
  evidence: SignatureEvidence[] = [];

  override async updateStatus(tenantId: string, id: string, status: Parameters<InMemorySignatureRepository["updateStatus"]>[2]) {
    const changed = await super.updateStatus(tenantId, id, status);
    if (changed) this.statusUpdateCount += 1;
    return changed;
  }

  override async appendEvidence(tenantId: string, evidence: SignatureEvidence) {
    this.evidence.push(evidence);
    return super.appendEvidence(tenantId, evidence);
  }
}

describe("ProviderWebhookHandler", () => {
  it("ignores an already processed provider event", async () => {
    const repo = new CountingRepository();
    await repo.create("tenant-a", {
      id: "req-1",
      tenantId: "tenant-a",
      status: "pending",
      documentSha256: "abc",
      providerRequestId: "fake:req-1",
      signer: { name: "Ana" },
    });

    const handler = new ProviderWebhookHandler({
      repository: repo,
      eventStore: new InMemoryProviderEventStore(),
      now: () => "2026-09-06T17:40:00.000Z",
    });

    const event = {
      eventId: "evt-1",
      requestId: "req-1",
      providerRequestId: "fake:req-1",
      status: "signed" as const,
    };

    await handler.handle({ tenantId: "tenant-a", subject: "provider-webhook" }, event);
    await handler.handle({ tenantId: "tenant-a", subject: "provider-webhook" }, event);

    expect(repo.statusUpdateCount).toBe(1);
    await expect(repo.findById("tenant-a", "req-1")).resolves.toMatchObject({ status: "signed" });
    expect(repo.evidence).toHaveLength(1);
  });

  it("fails closed when the request belongs to another tenant", async () => {
    const repo = new CountingRepository();
    await repo.create("tenant-a", {
      id: "req-1",
      tenantId: "tenant-a",
      status: "pending",
      documentSha256: "abc",
      providerRequestId: "fake:req-1",
      signer: { name: "Ana" },
    });

    const handler = new ProviderWebhookHandler({
      repository: repo,
      eventStore: new InMemoryProviderEventStore(),
      now: () => "2026-09-06T17:40:00.000Z",
    });

    await expect(
      handler.handle(
        { tenantId: "tenant-b", subject: "provider-webhook" },
        { eventId: "evt-2", requestId: "req-1", providerRequestId: "fake:req-1", status: "signed" }
      )
    ).rejects.toThrow("SIGNATURE_REQUEST_NOT_FOUND");
  });
});
