import { createHash } from "node:crypto";
import { beforeEach, describe, expect, it } from "vitest";
import { FakeConsentProvider } from "../providers/fakeConsentProvider.js";
import { FakeIdentityProvider } from "../providers/fakeIdentityProvider.js";
import type { IdentityEvidence } from "./identityEvidence.js";
import type { IdentityPolicy } from "./identityPolicy.js";
import { InMemoryIdentityConsentRepository } from "./identityConsentRepository.js";
import {
  IdentityConsentService,
  type IdentityAuditSink,
} from "./identityConsentService.js";
import type { Participant } from "../signatures/participant.js";
import { ProviderRegistry } from "../trust/providerRegistry.js";
import {
  fakeDevProfile,
  productionStandardProfile,
} from "../trust/trustProfile.js";

const participant: Participant = {
  id: "participant-1",
  role: "signer",
  status: "pending",
  identity: { name: "Test Signer", email: "test@example.com" },
  authenticationMethods: ["fake"],
};

const policy: IdentityPolicy = {
  id: "fake-standard",
  identityRequired: true,
  consentRequired: true,
  allowedMethods: ["fake"],
  minimumAssurance: "strong",
  allowedProviderIds: ["fake-identity", "fake-consent"],
  challengeTtlSeconds: 60,
  maxChallengeAttempts: 2,
};

type AuditEvent = Parameters<IdentityAuditSink["append"]>[0];

function testContext(options: { assurance?: "basic" | "strong" | "high" } = {}) {
  const identityProvider = new FakeIdentityProvider({
    assurance: options.assurance ?? "strong",
  });
  const consentProvider = new FakeConsentProvider();
  const registry = new ProviderRegistry();
  registry.register(identityProvider);
  registry.register(consentProvider);
  const repository = new InMemoryIdentityConsentRepository();
  const events: AuditEvent[] = [];
  const audit: IdentityAuditSink = {
    async append(event) {
      events.push(event);
    },
  };
  let clock = new Date("2026-09-12T18:00:00Z");
  let id = 0;
  const service = new IdentityConsentService({
    registry,
    repository,
    audit,
    now: () => new Date(clock),
    randomId: () => `id-${++id}`,
  });

  return {
    service,
    repository,
    identityProvider,
    consentProvider,
    events,
    setNow(value: string) {
      clock = new Date(value);
    },
  };
}

async function start(context: ReturnType<typeof testContext>, identityPolicy = policy) {
  return context.service.startIdentityVerification({
    tenantId: "tenant-a",
    requestId: "request-1",
    participant,
    trustProfile: fakeDevProfile,
    identityPolicy,
    method: "fake",
  });
}

async function complete(
  context: ReturnType<typeof testContext>,
  sessionId: string,
  answer = "FAKE-OK",
  identityPolicy = policy
) {
  return context.service.completeIdentityVerification({
    tenantId: "tenant-a",
    requestId: "request-1",
    participant,
    trustProfile: fakeDevProfile,
    identityPolicy,
    sessionId,
    response: { answer },
  });
}

describe("IdentityConsentService - start identity verification", () => {
  it("rejects a FAKE identity provider under a production trust profile", async () => {
    const context = testContext();
    await expect(
      context.service.startIdentityVerification({
        tenantId: "tenant-a",
        requestId: "request-1",
        participant,
        trustProfile: productionStandardProfile,
        identityPolicy: policy,
        method: "fake",
      })
    ).rejects.toThrow("UNSUPPORTED_CAPABILITY");
  });

  it("rejects a provider not allowed by IdentityPolicy", async () => {
    const context = testContext();
    await expect(
      start(context, { ...policy, allowedProviderIds: ["other-provider"] })
    ).rejects.toThrow("TRUST_POLICY_VIOLATION");
  });

  it("stores a challenge_pending session with policy TTL and only a digest of continuation data", async () => {
    const context = testContext();
    const result = await start(context);
    const session = await context.repository.getSession("tenant-a", result.sessionId);

    expect(session).toMatchObject({
      tenantId: "tenant-a",
      requestId: "request-1",
      participantId: "participant-1",
      providerId: "fake-identity",
      status: "challenge_pending",
      attemptCount: 0,
      maxAttempts: 2,
    });
    expect(session?.providerSessionId).toBeTruthy();
    expect(session?.expiresAt.toISOString()).toBe("2026-09-12T18:01:00.000Z");
    expect(session?.challengeDigest).toMatch(/^[a-f0-9]{64}$/);
    expect(JSON.stringify(session)).not.toContain("FAKE-OK");
    expect(context.events.at(-1)?.type).toBe("identity.challenge.created");
  });
});

describe("IdentityConsentService - complete identity verification", () => {
  it("creates immutable evidence, verifies the session and emits an audit event", async () => {
    const context = testContext();
    const started = await start(context);
    const evidence = await complete(context, started.sessionId);
    const session = await context.repository.getSession("tenant-a", started.sessionId);

    expect(Object.isFrozen(evidence)).toBe(true);
    expect(evidence.assurance).toBe("strong");
    expect(evidence.externalSubjectHash).toMatch(/^[a-f0-9]{64}$/);
    expect(evidence.externalSubjectHash).not.toContain("fake:participant-1");
    expect(JSON.stringify(evidence)).not.toContain("fake:participant-1");
    expect(session?.status).toBe("verified");
    expect(context.events.at(-1)?.type).toBe("identity.verified");
  });

  it("increments attempts and emits failure evidence for an invalid response", async () => {
    const context = testContext();
    const started = await start(context);

    await expect(complete(context, started.sessionId, "WRONG")).rejects.toThrow(
      "IDENTITY_CHALLENGE_INVALID"
    );
    const session = await context.repository.getSession("tenant-a", started.sessionId);
    expect(session?.attemptCount).toBe(1);
    expect(context.events.at(-1)?.type).toBe("identity.challenge.failed");
  });

  it("rejects expiration before calling provider completion", async () => {
    const context = testContext();
    const started = await start(context);
    context.setNow("2026-09-12T18:01:01Z");

    await expect(complete(context, started.sessionId)).rejects.toThrow(
      "IDENTITY_CHALLENGE_EXPIRED"
    );
    expect(context.identityProvider.completeCalls).toBe(0);
  });

  it("rejects replay before calling provider completion again", async () => {
    const context = testContext();
    const started = await start(context);
    await complete(context, started.sessionId);

    await expect(complete(context, started.sessionId)).rejects.toThrow(
      "IDENTITY_REPLAY_DETECTED"
    );
    expect(context.identityProvider.completeCalls).toBe(1);
  });

  it("rejects exhausted attempts before an additional provider call", async () => {
    const context = testContext();
    const started = await start(context);
    await expect(complete(context, started.sessionId, "WRONG")).rejects.toThrow();
    await expect(complete(context, started.sessionId, "WRONG")).rejects.toThrow();
    await expect(complete(context, started.sessionId, "FAKE-OK")).rejects.toThrow(
      "IDENTITY_CHALLENGE_INVALID"
    );
    expect(context.identityProvider.completeCalls).toBe(2);
  });

  it("rejects insufficient assurance without persisting identity evidence", async () => {
    const context = testContext({ assurance: "basic" });
    const started = await start(context);

    await expect(complete(context, started.sessionId)).rejects.toThrow(
      "IDENTITY_ASSURANCE_INSUFFICIENT"
    );
    expect(
      await context.repository.getLatestIdentityEvidence(
        "tenant-a",
        "request-1",
        "participant-1"
      )
    ).toBeUndefined();
  });

  it("does not resolve a session from another tenant", async () => {
    const context = testContext();
    const started = await start(context);

    await expect(
      context.service.completeIdentityVerification({
        tenantId: "tenant-b",
        requestId: "request-1",
        participant,
        trustProfile: fakeDevProfile,
        identityPolicy: policy,
        sessionId: started.sessionId,
        response: { answer: "FAKE-OK" },
      })
    ).rejects.toThrow("IDENTITY_CHALLENGE_INVALID");
    expect(context.identityProvider.completeCalls).toBe(0);
  });
});

describe("IdentityConsentService - consent and readiness", () => {
  it("requires identity evidence before consent", async () => {
    const context = testContext();
    await expect(
      context.service.recordConsent({
        tenantId: "tenant-a",
        requestId: "request-1",
        participant,
        trustProfile: fakeDevProfile,
        identityPolicy: policy,
        documentSha256: "a".repeat(64),
        statement: "I agree",
        decision: "accepted",
      })
    ).rejects.toThrow("IDENTITY_REQUIRED");
  });

  it("creates accepted consent bound to normalized statement and emits audit evidence", async () => {
    const context = testContext();
    const started = await start(context);
    await complete(context, started.sessionId);
    const consent = await context.service.recordConsent({
      tenantId: "tenant-a",
      requestId: "request-1",
      participant,
      trustProfile: fakeDevProfile,
      identityPolicy: policy,
      documentSha256: "a".repeat(64),
      statement: "  I agree\r\nLine 2  ",
      decision: "accepted",
    });

    expect(Object.isFrozen(consent)).toBe(true);
    expect(consent.statementHash).toBe(
      createHash("sha256").update("I agree\nLine 2", "utf8").digest("hex")
    );
    expect(context.events.at(-1)?.type).toBe("consent.accepted");
  });

  it("keeps declined consent non-signable", async () => {
    const context = testContext();
    const started = await start(context);
    const evidence = await complete(context, started.sessionId);
    const consent = await context.service.recordConsent({
      tenantId: "tenant-a",
      requestId: "request-1",
      participant,
      trustProfile: fakeDevProfile,
      identityPolicy: policy,
      documentSha256: "a".repeat(64),
      statement: "I agree",
      decision: "declined",
    });
    const readiness = await context.service.evaluateParticipantReadiness({
      tenantId: "tenant-a",
      requestId: "request-1",
      participant,
      identityPolicy: policy,
      documentSha256: "a".repeat(64),
      statementHash: consent.statementHash,
    });

    expect(evidence.id).toBe(consent.identityEvidenceId);
    expect(readiness).toBe("awaiting_consent");
    expect(context.events.at(-1)?.type).toBe("consent.declined");
  });

  it("derives readiness from current document and does not reuse old consent", async () => {
    const context = testContext();
    const started = await start(context);
    await complete(context, started.sessionId);
    const consent = await context.service.recordConsent({
      tenantId: "tenant-a",
      requestId: "request-1",
      participant,
      trustProfile: fakeDevProfile,
      identityPolicy: policy,
      documentSha256: "a".repeat(64),
      statement: "I agree",
      decision: "accepted",
    });

    expect(
      await context.service.evaluateParticipantReadiness({
        tenantId: "tenant-a",
        requestId: "request-1",
        participant,
        identityPolicy: policy,
        documentSha256: "a".repeat(64),
        statementHash: consent.statementHash,
      })
    ).toBe("ready_to_sign");

    expect(
      await context.service.evaluateParticipantReadiness({
        tenantId: "tenant-a",
        requestId: "request-1",
        participant,
        identityPolicy: policy,
        documentSha256: "changed-document",
        statementHash: consent.statementHash,
      })
    ).toBe("awaiting_consent");
  });

  it("rejects mismatched identity evidence returned by a corrupt repository", async () => {
    const context = testContext();
    const corruptEvidence: IdentityEvidence = Object.freeze({
      tenantId: "tenant-a",
      id: "bad-evidence",
      requestId: "other-request",
      participantId: "other-participant",
      identitySessionId: "session-x",
      providerId: "fake-identity",
      method: "fake",
      assurance: "strong",
      verifiedAt: new Date("2026-09-12T18:00:00Z"),
      providerEvidence: {},
      createdAt: new Date("2026-09-12T18:00:00Z"),
    });
    context.repository.getLatestIdentityEvidence = async () => corruptEvidence;

    await expect(
      context.service.recordConsent({
        tenantId: "tenant-a",
        requestId: "request-1",
        participant,
        trustProfile: fakeDevProfile,
        identityPolicy: policy,
        documentSha256: "a".repeat(64),
        statement: "I agree",
        decision: "accepted",
      })
    ).rejects.toThrow("CONSENT_IDENTITY_MISMATCH");
  });
});
