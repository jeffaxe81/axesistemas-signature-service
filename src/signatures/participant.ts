export type ParticipantRole = "signer" | "approver" | "witness" | "seal";

export type ParticipantStatus =
  | "invited"
  | "pending"
  | "authenticated"
  | "consented"
  | "signed"
  | "rejected"
  | "expired"
  | "failed";

export type Participant = {
  id: string;
  role: ParticipantRole;
  order?: number;
  status: ParticipantStatus;
  identity: {
    name: string;
    document?: string;
    email?: string;
  };
  authenticationMethods: string[];
};

const allowedTransitions: Record<
  ParticipantStatus,
  readonly ParticipantStatus[]
> = {
  invited: ["pending", "authenticated", "rejected", "expired", "failed"],
  pending: ["authenticated", "rejected", "expired", "failed"],
  authenticated: ["consented", "signed", "rejected", "expired", "failed"],
  consented: ["signed", "rejected", "expired", "failed"],
  signed: [],
  rejected: [],
  expired: [],
  failed: [],
};

export function transitionParticipantStatus(
  current: ParticipantStatus,
  next: ParticipantStatus
): ParticipantStatus {
  if (!allowedTransitions[current].includes(next)) {
    throw new Error("INVALID_PARTICIPANT_TRANSITION");
  }

  return next;
}
