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
