import { describe, expect, it } from "vitest";
import { InMemorySignatureRepository } from "./signatureRepository.js";

const fixture = {
  id: "req-1",
  tenantId: "tenant-a",
  status: "draft" as const,
  documentSha256: "abc",
  signer: { name: "Ana" },
};

describe("SignatureRepository tenant isolation", () => {
  it("never resolves a request across tenants", async () => {
    const repo = new InMemorySignatureRepository();
    await repo.create("tenant-a", fixture);
    await expect(repo.findById("tenant-b", fixture.id)).resolves.toBeNull();
    await expect(repo.findById("tenant-a", fixture.id)).resolves.toEqual(fixture);
  });

  it("never updates status across tenants", async () => {
    const repo = new InMemorySignatureRepository();
    await repo.create("tenant-a", fixture);
    await expect(repo.updateStatus("tenant-b", fixture.id, "pending")).resolves.toBe(false);
    await expect(repo.findById("tenant-a", fixture.id)).resolves.toEqual(fixture);
  });
});
