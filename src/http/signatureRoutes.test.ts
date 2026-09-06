import { describe, expect, it } from "vitest";
import { buildApp } from "../app.js";
import { InMemorySignatureRepository } from "../db/signatureRepository.js";
import type { DocumentStore } from "../documents/documentStore.js";
import { FakeSignatureProvider } from "../providers/fakeSignatureProvider.js";
import { SignatureService } from "../signatures/signatureService.js";

class MemoryDocumentStore implements DocumentStore {
  async put(input: { tenantId: string; requestId: string; bytes: Buffer; contentType?: string }) {
    return { key: `${input.tenantId}/${input.requestId}`, sizeBytes: input.bytes.length, contentType: input.contentType };
  }
  async get(_input: { tenantId: string; key: string }): Promise<Buffer | null> {
    return null;
  }
}

function makeApp() {
  let sequence = 0;
  const service = new SignatureService({
    repository: new InMemorySignatureRepository(),
    documentStore: new MemoryDocumentStore(),
    provider: new FakeSignatureProvider(),
    idFactory: () => `req-${++sequence}`,
    now: () => "2026-09-06T17:50:00.000Z",
  });

  return buildApp({
    signatureService: service,
    resolveAuthIdentity: authorization =>
      authorization === "Bearer test-tenant-a"
        ? { subject: "dispatch", authorizedTenants: ["tenant-a"] }
        : null,
  });
}

describe("signature HTTP API", () => {
  it("does not authorize tenantId supplied by a caller", async () => {
    const app = makeApp();
    const response = await app.inject({
      method: "POST",
      url: "/v1/signature-requests",
      headers: { authorization: "Bearer test-tenant-a" },
      payload: {
        tenantId: "tenant-b",
        signer: { name: "Ana" },
        documentBase64: Buffer.from("doc").toString("base64"),
        contentType: "application/pdf",
      },
    });

    expect(response.statusCode).toBe(201);
    expect(response.json()).toMatchObject({ id: "req-1", status: "pending" });
    expect(response.json()).not.toHaveProperty("tenantId");
    await app.close();
  });

  it("rejects missing or unknown bearer credentials", async () => {
    const app = makeApp();
    const response = await app.inject({
      method: "POST",
      url: "/v1/signature-requests",
      payload: {
        signer: { name: "Ana" },
        documentBase64: Buffer.from("doc").toString("base64"),
      },
    });
    expect(response.statusCode).toBe(401);
    await app.close();
  });

  it("returns a created request only inside authenticated tenant context", async () => {
    const app = makeApp();
    const create = await app.inject({
      method: "POST",
      url: "/v1/signature-requests",
      headers: { authorization: "Bearer test-tenant-a" },
      payload: {
        signer: { name: "Ana" },
        documentBase64: Buffer.from("doc").toString("base64"),
      },
    });
    const id = create.json().id;
    const get = await app.inject({
      method: "GET",
      url: `/v1/signature-requests/${id}`,
      headers: { authorization: "Bearer test-tenant-a" },
    });
    expect(get.statusCode).toBe(200);
    expect(get.json()).toMatchObject({ id, status: "pending" });
    expect(get.json()).not.toHaveProperty("tenantId");
    await app.close();
  });
});
