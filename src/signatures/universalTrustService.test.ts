import { expect, it } from "vitest";
import { makeFakeUniversalService } from "../fake-pki/testFactory.js";

it("completa somente após assinatura e validação aprovadas", async () => {
  const { service } = makeFakeUniversalService();
  const result = await service.execute({
    tenantId: "tenant-a",
    requestId: "req-1",
    trustProfileId: "fake-dev",
    document: Buffer.from("doc"),
    level: "advanced",
    format: "detached",
    participants: [
      {
        id: "p1",
        role: "signer",
        status: "authenticated",
        identity: { name: "Ana" },
        authenticationMethods: ["fake"],
      },
    ],
  });

  expect(result.status).toBe("completed");
  expect(result.validation).toMatchObject({ valid: true, trustMode: "fake" });
});

it("rejeita provider fake em production-standard antes de assinar", async () => {
  const { service, signingProvider } = makeFakeUniversalService();

  await expect(
    service.execute({
      tenantId: "tenant-a",
      requestId: "req-prod",
      trustProfileId: "production-standard",
      document: Buffer.from("doc"),
      level: "advanced",
      format: "detached",
      participants: [
        {
          id: "p1",
          role: "signer",
          status: "authenticated",
          identity: { name: "Ana" },
          authenticationMethods: ["fake"],
        },
      ],
    })
  ).rejects.toThrow("UNSUPPORTED_CAPABILITY");

  expect(signingProvider.signCalls).toBe(0);
});
