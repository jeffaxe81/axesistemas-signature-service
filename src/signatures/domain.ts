import type { SignatureFormat, SignatureLevel } from "../trust/capabilities.js";
import type { Participant } from "./participant.js";

export type SignatureStatus =
  | "draft"
  | "pending"
  | "signed"
  | "rejected"
  | "expired"
  | "failed";

export type SignatureRequest = {
  id: string;
  tenantId: string;
  status: SignatureStatus;
  documentSha256: string;
  providerRequestId?: string;
  signer: {
    name: string;
    document?: string;
    email?: string;
  };
};

const allowedTransitions: Record<SignatureStatus, readonly SignatureStatus[]> = {
  draft: ["pending", "failed"],
  pending: ["signed", "rejected", "expired", "failed"],
  signed: [],
  rejected: [],
  expired: [],
  failed: [],
};

export function transitionSignatureStatus(
  current: SignatureStatus,
  next: SignatureStatus
): SignatureStatus {
  if (!allowedTransitions[current].includes(next)) {
    throw new Error("INVALID_SIGNATURE_TRANSITION");
  }

  return next;
}

export type UniversalSignatureStatus =
  | "draft"
  | "awaiting_participants"
  | "partially_completed"
  | "validating"
  | "completed"
  | "rejected"
  | "expired"
  | "cancelled"
  | "failed";

export type UniversalSignatureRequest = {
  id: string;
  tenantId: string;
  status: UniversalSignatureStatus;
  documentSha256: string;
  trustProfileId: string;
  signatureLevel: SignatureLevel;
  signatureFormat: SignatureFormat;
  signingMode: "parallel" | "sequential";
  participants: Participant[];
};

const allowedUniversalTransitions: Record<
  UniversalSignatureStatus,
  readonly UniversalSignatureStatus[]
> = {
  draft: ["awaiting_participants", "cancelled", "failed"],
  awaiting_participants: [
    "partially_completed",
    "validating",
    "rejected",
    "expired",
    "cancelled",
    "failed",
  ],
  partially_completed: [
    "validating",
    "rejected",
    "expired",
    "cancelled",
    "failed",
  ],
  validating: ["completed", "failed"],
  completed: [],
  rejected: [],
  expired: [],
  cancelled: [],
  failed: [],
};

export function transitionUniversalSignatureStatus(
  current: UniversalSignatureStatus,
  next: UniversalSignatureStatus
): UniversalSignatureStatus {
  if (!allowedUniversalTransitions[current].includes(next)) {
    throw new Error("INVALID_UNIVERSAL_SIGNATURE_TRANSITION");
  }

  return next;
}
