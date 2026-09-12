import { createHash } from "node:crypto";
import { describe, expect, it } from "vitest";
import { buildApp } from "../app.js";
import { InMemoryIdentityConsentRepository } from "../identity/identityConsentRepository.js";
import { IdentityConsentService } from "../identity/identityConsentService.js";
import type { IdentityPolicy } from "../identity/identityPolicy.js";
import { FakeConsentProvider } from "../providers/fakeConsentProvider.js";
import { FakeIdentityProvider } from "../providers/fakeIdentityProvider.js";
import type { Participant } from "../signatures/participant.js";
import { InMemoryChallengeRateLimiter } from "../security/challengeRateLimiter.js";
import { ProviderRegistry } from "../trust/providerRegistry.js";
import { fakeDevProfile } from "../trust/trustProfile.js";

const participant: Participant = {
  id: "participant-1",
  role: "signer",
  status: "pending",
  identity: { name: "Ana", email: "ana@example.com" },
  authenticationMethods: ["fake"],
};

const policy: IdentityPolicy = {
  id: "fake-standard",
  identityRequired: true,
  consentRequired: true,
  allowedMethods: ["fake"],
  minimumAssurance: "strong",
  allowedProviderIds: ["fake-identity", "fake-consent"],
  challengeTtlSeconds: 300,
  maxChallengeAttempts: 3,
};

const documentSha256 = createHash("sha256").update("doc").digest("hex");

function makeApp(limit = 20) {
  const registry = new ProviderRegistry();
  registry.register(new FakeIdentityProvider({ assurance: "strong" }));
  registry.register(new FakeConsentProvider());
  let id = 0;
  const service = new IdentityConsentService({
    registry,
    repository: new InMemoryIdentityConsentRepository(),
    audit: { async append() {} },
    now: () => new Date("2026-09-12T18:00:00Z"),
    randomId: () => `http-${++id}`,
  });

  return buildApp({
    identityConsentRoutes: {
      service,
      resolveAuthIdentity: authorization => {
        if (authorization === "Bearer tenant-a") {
          return { subject: "tester-a", authorizedTenants: ["tenant-a"] };
        }
        if (authorization === "Bearer tenant-b") {
          return { subject: "tester-b", authorizedTenants: ["tenant-b"] };
        }
        if (authorization === "Bearer multi") {
          return { subject: "tester", authorizedTenants: ["tenant-a", "tenant-b"] };
        }
        return null;
      },
      resolveParticipant: async ({ tenantId, requestId, participantId }) =>
        tenantId === "tenant-a" && requestId === "request-1" && participantId === participant.id
          ? participant
          : undefined,
      resolveTrustProfile: async ({ tenantId, requestId }) =>
        tenantId === "tenant-a" && requestId === "request-1" ? fakeDevProfile : undefined,
      resolveIdentityPolicy: async ({ tenantId, requestId, participantId }) =>
        tenantId === "tenant-a" && requestId === "request-1" && participantId === participant.id
          ? policy
          : undefined,
      resolveDocumentSha256: async ({ tenantId, requestId }) =>
        tenantId === "tenant-a" && requestId === "request-1" ? documentSha256 : undefined,
      resolveConsentStatement: async ({ tenantId, requestId, participantId }) =>
        tenantId === "tenant-a" && requestId === "request-1" && participantId === participant.id
          ? "I agree"
          : undefined,
      rateLimiter: new InMemoryChallengeRateLimiter({ limit, windowSeconds: 60 }),
      now: () => new Date("2026-09-12T18:00:00Z"),
    },
  });
}

const startUrl =
  "/v1/signature-requests/request-1/participants/participant-1/identity-sessions";

describe("D-009C HTTP API", () => {
  it("uses the same 401/403 tenant-context boundary as the legacy API", async () => {
    const app = makeApp();
    const missing = await app.inject({ method: "POST", url: startUrl, payload: { method: "fake" } });
    expect(missing.statusCode).toBe(401);

    const unresolved = await app.inject({
      method: "POST",
      url: startUrl,
      headers: { authorization: "Bearer multi" },
      payload: { method: "fake" },
    });
    expect(unresolved.statusCode).toBe(403);
    await app.close();
  });

  it("rejects caller-supplied tenantId and returns only safe challenge continuation fields", async () => {
    const app = makeApp();
    const injectedTenant = await app.inject({
      method: "POST",
      url: startUrl,
      headers: { authorization: "Bearer tenant-a" },
      payload: { method: "fake", tenantId: "tenant-b" },
    });
    expect(injectedTenant.statusCode).toBe(400);

    const started = await app.inject({
      method: "POST",
      url: startUrl,
      headers: { authorization: "Bearer tenant-a" },
      payload: { method: "fake" },
    });
    expect(started.statusCode).toBe(201);
    expect(started.json()).toMatchObject({
      sessionId: expect.any(String),
      challengeId: expect.any(String),
      clientData: expect.any(Object),
    });
    expect(started.json()).not.toHaveProperty("providerSessionId");
    expect(started.json()).not.toHaveProperty("evidence");
    await app.close();
  });

  it("rate limits challenge creation per tenant/request/participant/operation", async () => {
    const app = makeApp(1);
    const first = await app.inject({
      method: "POST",
      url: startUrl,
      headers: { authorization: "Bearer tenant-a" },
      payload: { method: "fake" },
    });
    expect(first.statusCode).toBe(201);

    const second = await app.inject({
      method: "POST",
      url: startUrl,
      headers: { authorization: "Bearer tenant-a" },
      payload: { method: "fake" },
    });
    expect(second.statusCode).toBe(429);
    expect(second.json()).toMatchObject({ error: "RATE_LIMITED", retryAfterSeconds: 60 });
    await app.close();
  });

  it("completes identity, records canonical consent and returns ready_to_sign without raw provider evidence", async () => {
    const app = makeApp();
    const started = await app.inject({
      method: "POST",
      url: startUrl,
      headers: { authorization: "Bearer tenant-a" },
      payload: { method: "fake" },
    });
    const sessionId = started.json().sessionId as string;

    const completed = await app.inject({
      method: "POST",
      url: `${startUrl}/${sessionId}/complete`,
      headers: { authorization: "Bearer tenant-a" },
      payload: { response: { answer: "FAKE-OK" } },
    });
    expect(completed.statusCode).toBe(200);
    expect(completed.json()).toMatchObject({
      status: "authenticated",
      identityEvidenceId: expect.any(String),
      assurance: "strong",
    });
    expect(completed.json()).not.toHaveProperty("providerEvidence");
    expect(completed.json()).not.toHaveProperty("externalSubjectHash");

    const injectedHash = await app.inject({
      method: "POST",
      url: "/v1/signature-requests/request-1/participants/participant-1/consents",
      headers: { authorization: "Bearer tenant-a" },
      payload: { statement: "I agree", decision: "accepted", documentSha256: "attacker" },
    });
    expect(injectedHash.statusCode).toBe(400);

    const wrongStatement = await app.inject({
      method: "POST",
      url: "/v1/signature-requests/request-1/participants/participant-1/consents",
      headers: { authorization: "Bearer tenant-a" },
      payload: { statement: "Different text", decision: "accepted" },
    });
    expect(wrongStatement.statusCode).toBe(400);
    expect(wrongStatement.json()).toEqual({ error: "INVALID_CONSENT_REQUEST" });

    const consent = await app.inject({
      method: "POST",
      url: "/v1/signature-requests/request-1/participants/participant-1/consents",
      headers: { authorization: "Bearer tenant-a" },
      payload: { statement: "I agree", decision: "accepted" },
    });
    expect(consent.statusCode).toBe(201);
    expect(consent.json()).toMatchObject({
      status: "accepted",
      consentId: expect.any(String),
      statementHash: expect.any(String),
    });
    expect(consent.json()).not.toHaveProperty("providerEvidence");

    const readiness = await app.inject({
      method: "GET",
      url: "/v1/signature-requests/request-1/participants/participant-1/readiness",
      headers: { authorization: "Bearer tenant-a" },
    });
    expect(readiness.statusCode).toBe(200);
    expect(readiness.json()).toEqual({ readiness: "ready_to_sign" });
    await app.close();
  });

  it("normalizes replay errors and hides cross-tenant resource existence", async () => {
    const app = makeApp();
    const started = await app.inject({
      method: "POST",
      url: startUrl,
      headers: { authorization: "Bearer tenant-a" },
      payload: { method: "fake" },
    });
    const sessionId = started.json().sessionId as string;
    const completeUrl = `${startUrl}/${sessionId}/complete`;
    const payload = { response: { answer: "FAKE-OK" } };

    expect(
      (await app.inject({ method: "POST", url: completeUrl, headers: { authorization: "Bearer tenant-a" }, payload })).statusCode
    ).toBe(200);
    const replay = await app.inject({
      method: "POST",
      url: completeUrl,
      headers: { authorization: "Bearer tenant-a" },
      payload,
    });
    expect(replay.statusCode).toBe(409);
    expect(replay.json()).toEqual({ error: "IDENTITY_REPLAY_DETECTED" });

    const foreign = await app.inject({
      method: "GET",
      url: "/v1/signature-requests/request-1/participants/participant-1/readiness",
      headers: { authorization: "Bearer tenant-b" },
    });
    expect(foreign.statusCode).toBe(404);
    expect(foreign.json()).toEqual({ error: "PARTICIPANT_NOT_FOUND" });
    await app.close();
  });
});
