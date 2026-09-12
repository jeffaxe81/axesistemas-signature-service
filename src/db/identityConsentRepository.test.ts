import { readFileSync } from "node:fs";
import { describe, expect, it } from "vitest";
import { createConsentRecord } from "../consent/consentRecord.js";
import { createIdentityEvidence } from "../identity/identityEvidence.js";
import { InMemoryIdentityConsentRepository } from "../identity/identityConsentRepository.js";
import { createIdentitySession } from "../identity/identitySession.js";
import { DrizzleIdentityConsentRepository } from "./identityConsentRepository.js";

const now = new Date("2026-09-12T18:00:00Z");

describe("D-009C persistence isolation", () => {
  it("keeps sessions isolated when tenants reuse the same id", async () => {
    const repository = new InMemoryIdentityConsentRepository();
    for (const tenantId of ["tenant-a", "tenant-b"]) {
      await repository.saveSession(
        createIdentitySession({
          tenantId,
          id: "session-1",
          requestId: "request-1",
          participantId: "participant-1",
          providerId: "fake-identity",
          providerSessionId: `provider-${tenantId}`,
          method: "fake",
          challengeId: `challenge-${tenantId}`,
          challengeDigest: tenantId === "tenant-a" ? "a".repeat(64) : "b".repeat(64),
          now,
          ttlSeconds: 60,
          maxAttempts: 3,
        })
      );
    }

    await expect(repository.getSession("tenant-a", "session-1")).resolves.toMatchObject({
      tenantId: "tenant-a",
      providerSessionId: "provider-tenant-a",
    });
    await expect(repository.getSession("tenant-b", "session-1")).resolves.toMatchObject({
      tenantId: "tenant-b",
      providerSessionId: "provider-tenant-b",
    });
  });

  it("filters latest evidence and consent by tenant, request and participant together", async () => {
    const repository = new InMemoryIdentityConsentRepository();
    const contexts = [
      ["tenant-a", "request-1", "participant-1", "one"],
      ["tenant-a", "request-2", "participant-1", "two"],
      ["tenant-b", "request-1", "participant-1", "three"],
      ["tenant-a", "request-1", "participant-2", "four"],
    ] as const;

    for (const [tenantId, requestId, participantId, suffix] of contexts) {
      const evidence = createIdentityEvidence({
        tenantId,
        id: `evidence-${suffix}`,
        requestId,
        participantId,
        identitySessionId: `session-${suffix}`,
        providerId: "fake-identity",
        method: "fake",
        assurance: "strong",
        verifiedAt: now,
        providerEvidence: { outcome: "verified" },
        createdAt: now,
      });
      await repository.saveIdentityEvidence(evidence);
      await repository.saveConsent(
        createConsentRecord({
          tenantId,
          id: `consent-${suffix}`,
          requestId,
          participantId,
          identityEvidenceId: evidence.id,
          documentSha256: "d".repeat(64),
          statementHash: "s".repeat(64),
          decision: "accepted",
          providerId: "fake-consent",
          providerEvidence: { decision: "accepted" },
          now,
        })
      );
    }

    await expect(
      repository.getLatestIdentityEvidence("tenant-a", "request-1", "participant-1")
    ).resolves.toMatchObject({ id: "evidence-one" });
    await expect(
      repository.getLatestConsent("tenant-a", "request-1", "participant-1")
    ).resolves.toMatchObject({ id: "consent-one" });
  });

  it("exports a Drizzle adapter whose read filters explicitly include tenant id", () => {
    expect(DrizzleIdentityConsentRepository).toBeDefined();
    const source = readFileSync(new URL("./identityConsentRepository.ts", import.meta.url), "utf8");

    expect(source).toContain("eq(identitySessions.tenantId, tenantId)");
    expect(source).toContain("eq(identityEvidences.tenantId, tenantId)");
    expect(source).toContain("eq(consentRecords.tenantId, tenantId)");
    expect(source).not.toContain("externalSubject:");
    expect(source).not.toContain("challengeResponse");
  });
});
