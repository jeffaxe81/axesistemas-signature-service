import { expect, it } from "vitest";
import { buildApp } from "../app.js";
import { InMemoryIdentityConsentRepository } from "../identity/identityConsentRepository.js";
import { IdentityConsentService } from "../identity/identityConsentService.js";
import type { IdentityPolicy } from "../identity/identityPolicy.js";
import { FakeIdentityProvider } from "../providers/fakeIdentityProvider.js";
import type { Participant } from "../signatures/participant.js";
import { InMemoryChallengeRateLimiter } from "../security/challengeRateLimiter.js";
import { ProviderRegistry } from "../trust/providerRegistry.js";
import { fakeDevProfile } from "../trust/trustProfile.js";

it("starts identity without requiring consent-only context when consent is disabled", async () => {
  const participant: Participant = {
    id: "p1",
    role: "signer",
    status: "pending",
    identity: { name: "Ana" },
    authenticationMethods: ["fake"],
  };
  const policy: IdentityPolicy = {
    id: "identity-only",
    identityRequired: true,
    consentRequired: false,
    allowedMethods: ["fake"],
    minimumAssurance: "strong",
    allowedProviderIds: ["fake-identity"],
    challengeTtlSeconds: 300,
    maxChallengeAttempts: 3,
  };
  const registry = new ProviderRegistry();
  registry.register(new FakeIdentityProvider({ assurance: "strong" }));
  let sequence = 0;
  const service = new IdentityConsentService({
    registry,
    repository: new InMemoryIdentityConsentRepository(),
    audit: { async append() {} },
    now: () => new Date("2026-09-12T18:00:00Z"),
    randomId: () => `identity-only-${++sequence}`,
  });
  const app = buildApp({
    identityConsentRoutes: {
      service,
      resolveAuthIdentity: authorization =>
        authorization === "Bearer tenant-a"
          ? { subject: "tester", authorizedTenants: ["tenant-a"] }
          : null,
      resolveParticipant: async ({ tenantId, requestId, participantId }) =>
        tenantId === "tenant-a" && requestId === "req-1" && participantId === "p1"
          ? participant
          : undefined,
      resolveTrustProfile: async ({ tenantId, requestId }) =>
        tenantId === "tenant-a" && requestId === "req-1" ? fakeDevProfile : undefined,
      resolveIdentityPolicy: async ({ tenantId, requestId, participantId }) =>
        tenantId === "tenant-a" && requestId === "req-1" && participantId === "p1"
          ? policy
          : undefined,
      resolveDocumentSha256: async () => undefined,
      resolveConsentStatement: async () => undefined,
      rateLimiter: new InMemoryChallengeRateLimiter({ limit: 5, windowSeconds: 60 }),
      now: () => new Date("2026-09-12T18:00:00Z"),
    },
  });

  const response = await app.inject({
    method: "POST",
    url: "/v1/signature-requests/req-1/participants/p1/identity-sessions",
    headers: { authorization: "Bearer tenant-a" },
    payload: { method: "fake" },
  });

  expect(response.statusCode).toBe(201);
  expect(response.json()).toMatchObject({
    sessionId: expect.any(String),
    challengeId: expect.any(String),
  });
  await app.close();
});
