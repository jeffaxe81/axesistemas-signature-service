import { describe, expect, it } from "vitest";
import {
  assertConsentMatches,
  createConsentRecord,
  transitionConsentStatus,
} from "./consentRecord.js";

const now = new Date("2026-09-12T18:00:00Z");

function acceptedConsent(expiresAt?: Date) {
  return createConsentRecord({
    tenantId: "tenant-a",
    id: "consent-1",
    requestId: "request-1",
    participantId: "participant-1",
    identityEvidenceId: "evidence-1",
    documentSha256: "a".repeat(64),
    statementHash: "b".repeat(64),
    decision: "accepted",
    providerId: "fake-consent",
    providerEvidence: { provider: "fake-consent" },
    now,
    expiresAt,
  });
}

describe("ConsentRecord", () => {
  it("rejects consent bound to another document", () => {
    const consent = acceptedConsent();
    expect(() =>
      assertConsentMatches({
        consent,
        tenantId: "tenant-a",
        requestId: "request-1",
        participantId: "participant-1",
        identityEvidenceId: "evidence-1",
        documentSha256: "changed-hash",
        statementHash: consent.statementHash,
        now,
      })
    ).toThrowError("CONSENT_DOCUMENT_MISMATCH");
  });

  it("rejects consent bound to another identity evidence", () => {
    const consent = acceptedConsent();
    expect(() =>
      assertConsentMatches({
        consent,
        tenantId: "tenant-a",
        requestId: "request-1",
        participantId: "participant-1",
        identityEvidenceId: "evidence-2",
        documentSha256: consent.documentSha256,
        statementHash: consent.statementHash,
        now,
      })
    ).toThrowError("CONSENT_IDENTITY_MISMATCH");
  });

  it("rejects cross-tenant consent", () => {
    const consent = acceptedConsent();
    expect(() =>
      assertConsentMatches({
        consent,
        tenantId: "tenant-b",
        requestId: "request-1",
        participantId: "participant-1",
        identityEvidenceId: "evidence-1",
        documentSha256: consent.documentSha256,
        statementHash: consent.statementHash,
        now,
      })
    ).toThrowError("CROSS_TENANT_ACCESS_DENIED");
  });

  it("rejects same-tenant consent from another request or participant", () => {
    const consent = acceptedConsent();
    for (const context of [
      { requestId: "request-2", participantId: "participant-1" },
      { requestId: "request-1", participantId: "participant-2" },
    ]) {
      expect(() =>
        assertConsentMatches({
          consent,
          tenantId: "tenant-a",
          ...context,
          identityEvidenceId: "evidence-1",
          documentSha256: consent.documentSha256,
          statementHash: consent.statementHash,
          now,
        })
      ).toThrowError("CONSENT_IDENTITY_MISMATCH");
    }
  });

  it("rejects consent when the statement changes", () => {
    const consent = acceptedConsent();
    expect(() =>
      assertConsentMatches({
        consent,
        tenantId: "tenant-a",
        requestId: "request-1",
        participantId: "participant-1",
        identityEvidenceId: "evidence-1",
        documentSha256: consent.documentSha256,
        statementHash: "changed-statement",
        now,
      })
    ).toThrowError("CONSENT_DOCUMENT_MISMATCH");
  });

  it("rejects expired accepted consent", () => {
    const consent = acceptedConsent(new Date("2026-09-12T17:59:59Z"));
    expect(() =>
      assertConsentMatches({
        consent,
        tenantId: "tenant-a",
        requestId: "request-1",
        participantId: "participant-1",
        identityEvidenceId: "evidence-1",
        documentSha256: consent.documentSha256,
        statementHash: consent.statementHash,
        now,
      })
    ).toThrowError("CONSENT_REQUIRED");
  });

  it("does not allow accepted or declined consent to be finalized again", () => {
    const accepted = acceptedConsent();
    expect(() => transitionConsentStatus(accepted, "declined", now)).toThrowError(
      "CONSENT_ALREADY_FINALIZED"
    );

    const declined = createConsentRecord({
      tenantId: "tenant-a",
      id: "consent-2",
      requestId: "request-1",
      participantId: "participant-1",
      identityEvidenceId: "evidence-1",
      documentSha256: "a".repeat(64),
      statementHash: "b".repeat(64),
      decision: "declined",
      providerId: "fake-consent",
      providerEvidence: {},
      now,
    });
    expect(() => transitionConsentStatus(declined, "accepted", now)).toThrowError(
      "CONSENT_ALREADY_FINALIZED"
    );
  });
});
