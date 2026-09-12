export type ConsentDecision = "accepted" | "declined";
export type ConsentStatus = "pending" | "accepted" | "declined" | "expired";

export type ConsentRecord = Readonly<{
  tenantId: string;
  id: string;
  requestId: string;
  participantId: string;
  identityEvidenceId: string;
  documentSha256: string;
  statementHash: string;
  decision: ConsentDecision;
  status: ConsentStatus;
  providerId: string;
  acceptedAt?: Date;
  declinedAt?: Date;
  expiresAt?: Date;
  providerEvidence: Record<string, unknown>;
  createdAt: Date;
}>;

export type CreateConsentRecordInput = {
  tenantId: string;
  id: string;
  requestId: string;
  participantId: string;
  identityEvidenceId: string;
  documentSha256: string;
  statementHash: string;
  decision: ConsentDecision;
  providerId: string;
  providerEvidence: Record<string, unknown>;
  now: Date;
  expiresAt?: Date;
};

export function createConsentRecord(input: CreateConsentRecordInput): ConsentRecord {
  const record: ConsentRecord = {
    tenantId: input.tenantId,
    id: input.id,
    requestId: input.requestId,
    participantId: input.participantId,
    identityEvidenceId: input.identityEvidenceId,
    documentSha256: input.documentSha256,
    statementHash: input.statementHash,
    decision: input.decision,
    status: input.decision,
    providerId: input.providerId,
    ...(input.decision === "accepted" ? { acceptedAt: new Date(input.now) } : {}),
    ...(input.decision === "declined" ? { declinedAt: new Date(input.now) } : {}),
    ...(input.expiresAt ? { expiresAt: new Date(input.expiresAt) } : {}),
    providerEvidence: input.providerEvidence,
    createdAt: new Date(input.now),
  };

  return Object.freeze(record);
}

export function assertConsentMatches(input: {
  consent: ConsentRecord;
  tenantId: string;
  requestId: string;
  participantId: string;
  identityEvidenceId: string;
  documentSha256: string;
  statementHash: string;
  now: Date;
}): void {
  const { consent } = input;

  if (consent.tenantId !== input.tenantId) {
    throw new Error("CROSS_TENANT_ACCESS_DENIED");
  }

  if (
    consent.requestId !== input.requestId ||
    consent.participantId !== input.participantId ||
    consent.identityEvidenceId !== input.identityEvidenceId
  ) {
    throw new Error("CONSENT_IDENTITY_MISMATCH");
  }

  if (
    consent.documentSha256 !== input.documentSha256 ||
    consent.statementHash !== input.statementHash
  ) {
    throw new Error("CONSENT_DOCUMENT_MISMATCH");
  }

  if (consent.status !== "accepted") {
    throw new Error("CONSENT_REQUIRED");
  }

  if (consent.expiresAt && input.now.getTime() > consent.expiresAt.getTime()) {
    throw new Error("CONSENT_REQUIRED");
  }
}

export function transitionConsentStatus(
  consent: ConsentRecord,
  next: ConsentStatus,
  now: Date
): ConsentRecord {
  if (["accepted", "declined", "expired"].includes(consent.status)) {
    throw new Error("CONSENT_ALREADY_FINALIZED");
  }

  if (consent.status !== "pending" || !["accepted", "declined", "expired"].includes(next)) {
    throw new Error("INVALID_CONSENT_TRANSITION");
  }

  const updated: ConsentRecord = {
    ...consent,
    status: next,
    ...(next === "accepted" ? { acceptedAt: new Date(now) } : {}),
    ...(next === "declined" ? { declinedAt: new Date(now) } : {}),
  };
  return Object.freeze(updated);
}
