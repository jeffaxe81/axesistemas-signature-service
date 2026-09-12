import type { ConsentRecord } from "../consent/consentRecord.js";
import { assertConsentMatches } from "../consent/consentRecord.js";
import type { Participant } from "../signatures/participant.js";
import type { IdentityEvidence } from "./identityEvidence.js";
import {
  assertAssuranceSatisfied,
  type IdentityPolicy,
} from "./identityPolicy.js";

export type ParticipantReadiness =
  | "awaiting_identity"
  | "awaiting_consent"
  | "ready_to_sign";

export function evaluateReadiness(input: {
  tenantId: string;
  requestId: string;
  policy: IdentityPolicy;
  participant: Participant;
  documentSha256: string;
  statementHash: string;
  identityEvidence?: IdentityEvidence;
  consent?: ConsentRecord;
  now: Date;
}): ParticipantReadiness {
  const needsIdentity = input.policy.identityRequired || input.policy.consentRequired;

  if (!needsIdentity && !input.policy.consentRequired) {
    return "ready_to_sign";
  }

  const evidence = input.identityEvidence;
  if (!evidence) {
    return "awaiting_identity";
  }

  if (evidence.tenantId !== input.tenantId) {
    throw new Error("CROSS_TENANT_ACCESS_DENIED");
  }

  if (
    evidence.requestId !== input.requestId ||
    evidence.participantId !== input.participant.id
  ) {
    return "awaiting_identity";
  }

  assertAssuranceSatisfied(input.policy, evidence.assurance);

  if (
    input.policy.identityEvidenceMaxAgeSeconds !== undefined &&
    input.now.getTime() - evidence.verifiedAt.getTime() >
      input.policy.identityEvidenceMaxAgeSeconds * 1000
  ) {
    return "awaiting_identity";
  }

  if (!input.policy.consentRequired) {
    return "ready_to_sign";
  }

  const consent = input.consent;
  if (!consent) {
    return "awaiting_consent";
  }

  try {
    assertConsentMatches({
      consent,
      tenantId: input.tenantId,
      requestId: input.requestId,
      participantId: input.participant.id,
      identityEvidenceId: evidence.id,
      documentSha256: input.documentSha256,
      statementHash: input.statementHash,
      now: input.now,
    });
  } catch (error) {
    if (error instanceof Error && error.message === "CROSS_TENANT_ACCESS_DENIED") {
      throw error;
    }
    return "awaiting_consent";
  }

  if (
    input.policy.consentMaxAgeSeconds !== undefined &&
    consent.acceptedAt &&
    input.now.getTime() - consent.acceptedAt.getTime() >
      input.policy.consentMaxAgeSeconds * 1000
  ) {
    return "awaiting_consent";
  }

  return "ready_to_sign";
}
