import { createHash } from "node:crypto";
import { expect, it } from "vitest";
import { FakeConsentProvider } from "../providers/fakeConsentProvider.js";
import { FakeIdentityProvider } from "../providers/fakeIdentityProvider.js";
import {
  IdentityConsentService,
  type IdentityAuditSink,
} from "../identity/identityConsentService.js";
import { InMemoryIdentityConsentRepository } from "../identity/identityConsentRepository.js";
import type { IdentityPolicy } from "../identity/identityPolicy.js";
import { makeFakeUniversalService } from "../fake-pki/testFactory.js";
import { UniversalTrustService } from "./universalTrustService.js";

const participant = {
  id: "p1",
  role: "signer" as const,
  status: "pending" as const,
  identity: { name: "Ana" },
  authenticationMethods: ["fake"],
};

const identityPolicy: IdentityPolicy = {
  id: "fake-standard",
  identityRequired: true,
  consentRequired: true,
  allowedMethods: ["fake"],
  minimumAssurance: "strong",
  allowedProviderIds: ["fake-identity", "fake-consent"],
  challengeTtlSeconds: 300,
  maxChallengeAttempts: 3,
};

const statement = "I agree";
const statementHash = createHash("sha256").update(statement, "utf8").digest("hex");

function makeIdentityAwareService() {
  const base = makeFakeUniversalService();
  const identityProvider = new FakeIdentityProvider({ assurance: "strong" });
  const consentProvider = new FakeConsentProvider();
  base.registry.register(identityProvider);
  base.registry.register(consentProvider);

  const repository = new InMemoryIdentityConsentRepository();
  const audit: IdentityAuditSink = { async append() {} };
  let id = 0;
  const identityService = new IdentityConsentService({
    registry: base.registry,
    repository,
    audit,
    now: () => new Date("2026-09-12T18:00:00Z"),
    randomId: () => `identity-${++id}`,
  });

  const service = new UniversalTrustService({
    registry: base.registry,
    identityReadiness: {
      service: identityService,
      resolvePolicy: async () => identityPolicy,
      resolveStatementHash: async () => statementHash,
    },
  });

  return {
    ...base,
    service,
    identityService,
    identityProvider,
    consentProvider,
  };
}

const baseInput = {
  tenantId: "tenant-a",
  requestId: "req-identity",
  trustProfileId: "fake-dev" as const,
  document: Buffer.from("doc"),
  level: "advanced" as const,
  format: "detached" as const,
  participants: [participant],
};

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

it("bloqueia assinatura em awaiting_identity antes de chamar o signing provider", async () => {
  const { service, signingProvider } = makeIdentityAwareService();
  const result = await service.execute(baseInput);

  expect(result.status).toBe("awaiting_identity");
  expect(result.providerRequestIds).toEqual([]);
  expect(signingProvider.signCalls).toBe(0);
});

it("bloqueia em awaiting_consent após autenticação e antes de assinar", async () => {
  const { service, identityService, signingProvider } = makeIdentityAwareService();
  const started = await identityService.startIdentityVerification({
    tenantId: baseInput.tenantId,
    requestId: baseInput.requestId,
    participant,
    trustProfile: (await import("../trust/trustProfile.js")).fakeDevProfile,
    identityPolicy,
    method: "fake",
  });
  await identityService.completeIdentityVerification({
    tenantId: baseInput.tenantId,
    requestId: baseInput.requestId,
    participant,
    trustProfile: (await import("../trust/trustProfile.js")).fakeDevProfile,
    identityPolicy,
    sessionId: started.sessionId,
    response: { answer: "FAKE-OK" },
  });

  const result = await service.execute(baseInput);
  expect(result.status).toBe("awaiting_consent");
  expect(signingProvider.signCalls).toBe(0);
});

it("executa o fluxo completo e invalida consentimento quando o documento muda", async () => {
  const { service, identityService, signingProvider } = makeIdentityAwareService();
  const { fakeDevProfile } = await import("../trust/trustProfile.js");

  const first = await service.execute(baseInput);
  expect(first.status).toBe("awaiting_identity");
  expect(signingProvider.signCalls).toBe(0);

  const started = await identityService.startIdentityVerification({
    tenantId: baseInput.tenantId,
    requestId: baseInput.requestId,
    participant,
    trustProfile: fakeDevProfile,
    identityPolicy,
    method: "fake",
  });
  await identityService.completeIdentityVerification({
    tenantId: baseInput.tenantId,
    requestId: baseInput.requestId,
    participant,
    trustProfile: fakeDevProfile,
    identityPolicy,
    sessionId: started.sessionId,
    response: { answer: "FAKE-OK" },
  });

  const second = await service.execute(baseInput);
  expect(second.status).toBe("awaiting_consent");
  expect(signingProvider.signCalls).toBe(0);

  await identityService.recordConsent({
    tenantId: baseInput.tenantId,
    requestId: baseInput.requestId,
    participant,
    trustProfile: fakeDevProfile,
    identityPolicy,
    documentSha256: createHash("sha256").update(baseInput.document).digest("hex"),
    statement,
    decision: "accepted",
  });

  const third = await service.execute(baseInput);
  expect(third.status).toBe("completed");
  expect(signingProvider.signCalls).toBe(1);

  const changed = await service.execute({ ...baseInput, document: Buffer.from("changed-doc") });
  expect(changed.status).toBe("awaiting_consent");
  expect(signingProvider.signCalls).toBe(1);
});
