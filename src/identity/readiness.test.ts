import { describe, expect, it } from "vitest";
import { createConsentRecord } from "../consent/consentRecord.js";
import { createIdentityEvidence } from "./identityEvidence.js";
import type { IdentityPolicy } from "./identityPolicy.js";
import { evaluateReadiness } from "./readiness.js";
import type { Participant } from "../signatures/participant.js";

const now = new Date("2026-09-12T18:00:00Z");
const documentSha256 = "a".repeat(64);
const statementHash = "b".repeat(64);

const policy: IdentityPolicy = {
  id: "fake-standard",
  identityRequired: true,
  consentRequired: true,
  allowedMethods: ["fake"],
  minimumAssurance: "strong",
  allowedProviderIds: "*",
  challengeTtlSeconds: 300,
  maxChallengeAttempts: 3,
};

const participant: Participant = {
  id: "participant-1",
  role: "signer",
  status: "pending",
  identity: { name: "Test Signer", email: "test@example.com" },
  authenticationMethods: ["fake"],
};

const identityEvidence = createIdentityEvidence({
  tenantId: "tenant-a",
  id: "evidence-1",
  requestId: "request-1",
  participantId: "participant-1",
  identitySessionId: "session-1",
  providerId: "fake-identity",
  method: "fake",
  assurance: "strong",
  verifiedAt: now,
  providerEvidence: {},
  createdAt: now,
});

const consent = createConsentRecord({
  tenantId: "tenant-a",
  id: "consent-1",
  requestId: "request-1",
  participantId: "participant-1",
  identityEvidenceId: identityEvidence.id,
  documentSha256,
  statementHash,
  decision: "accepted",
  providerId: "fake-consent",
  providerEvidence: {},
  now,
});

const base = {
  tenantId: "tenant-a",
  requestId: "request-1",
  policy,
  participant,
  documentSha256,
  statementHash,
  now,
};

describe("participant readiness", () => {
  it("returns awaiting_identity when policy requires identity and none exists", () => {
    expect(
      evaluateReadiness({
        ...base,
        identityEvidence: undefined,
        consent: undefined,
      })
    ).toBe("awaiting_identity");
  });

  it("returns awaiting_consent after valid identity when consent is required", () => {
    expect(evaluateReadiness({ ...base, identityEvidence, consent: undefined })).toBe(
      "awaiting_consent"
    );
  });

  it("returns ready_to_sign only when identity and consent match current document", () => {
    expect(evaluateReadiness({ ...base, identityEvidence, consent })).toBe(
      "ready_to_sign"
    );
  });

  it("returns awaiting_identity when identity evidence exceeds max age", () => {
    const agingPolicy: IdentityPolicy = {
      ...policy,
      identityEvidenceMaxAgeSeconds: 60,
    };
    const oldEvidence = createIdentityEvidence({
      ...identityEvidence,
      id: "old-evidence",
      verifiedAt: new Date("2026-09-12T17:58:59Z"),
      createdAt: new Date("2026-09-12T17:58:59Z"),
    });

    expect(
      evaluateReadiness({
        ...base,
        policy: agingPolicy,
        identityEvidence: oldEvidence,
        consent: undefined,
      })
    ).toBe("awaiting_identity");
  });

  it("returns awaiting_consent when accepted consent exceeds max age", () => {
    const agingPolicy: IdentityPolicy = { ...policy, consentMaxAgeSeconds: 60 };
    const oldConsent = createConsentRecord({
      tenantId: "tenant-a",
      id: "old-consent",
      requestId: "request-1",
      participantId: "participant-1",
      identityEvidenceId: identityEvidence.id,
      documentSha256,
      statementHash,
      decision: "accepted",
      providerId: "fake-consent",
      providerEvidence: {},
      now: new Date("2026-09-12T17:58:59Z"),
    });

    expect(
      evaluateReadiness({
        ...base,
        policy: agingPolicy,
        identityEvidence,
        consent: oldConsent,
      })
    ).toBe("awaiting_consent");
  });

  it("returns ready_to_sign without evidence when neither identity nor consent is required", () => {
    expect(
      evaluateReadiness({
        ...base,
        policy: { ...policy, identityRequired: false, consentRequired: false },
        identityEvidence: undefined,
        consent: undefined,
      })
    ).toBe("ready_to_sign");
  });

  it("still requires identity when consent is required", () => {
    expect(
      evaluateReadiness({
        ...base,
        policy: { ...policy, identityRequired: false, consentRequired: true },
        identityEvidence: undefined,
        consent: undefined,
      })
    ).toBe("awaiting_identity");
  });
});
