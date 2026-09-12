import type { AuthenticationMethod } from "./identityPolicy.js";

export type IdentitySessionStatus =
  | "created"
  | "challenge_pending"
  | "verified"
  | "denied"
  | "expired"
  | "failed";

export type IdentitySession = {
  tenantId: string;
  id: string;
  requestId: string;
  participantId: string;
  providerId: string;
  method: AuthenticationMethod;
  purpose: "document-signing";
  status: IdentitySessionStatus;
  challengeId: string;
  challengeDigest: string;
  expiresAt: Date;
  attemptCount: number;
  maxAttempts: number;
  createdAt: Date;
  updatedAt: Date;
  completedAt?: Date;
};

export type CreateIdentitySessionInput = {
  tenantId: string;
  id: string;
  requestId: string;
  participantId: string;
  providerId: string;
  method: AuthenticationMethod;
  challengeId: string;
  challengeDigest: string;
  now: Date;
  ttlSeconds: number;
  maxAttempts: number;
};

const allowedTransitions: Record<
  IdentitySessionStatus,
  readonly IdentitySessionStatus[]
> = {
  created: ["challenge_pending", "failed"],
  challenge_pending: ["verified", "denied", "expired", "failed"],
  verified: [],
  denied: [],
  expired: [],
  failed: [],
};

const terminal: IdentitySessionStatus[] = ["verified", "denied", "expired", "failed"];

export function createIdentitySession(input: CreateIdentitySessionInput): IdentitySession {
  return {
    tenantId: input.tenantId,
    id: input.id,
    requestId: input.requestId,
    participantId: input.participantId,
    providerId: input.providerId,
    method: input.method,
    purpose: "document-signing",
    status: "challenge_pending",
    challengeId: input.challengeId,
    challengeDigest: input.challengeDigest,
    expiresAt: new Date(input.now.getTime() + input.ttlSeconds * 1000),
    attemptCount: 0,
    maxAttempts: input.maxAttempts,
    createdAt: new Date(input.now),
    updatedAt: new Date(input.now),
  };
}

export function incrementIdentityAttempt(
  session: IdentitySession,
  now: Date
): IdentitySession {
  return {
    ...session,
    attemptCount: session.attemptCount + 1,
    updatedAt: new Date(now),
  };
}

export function assertSessionUsable(session: IdentitySession, now: Date): void {
  if (session.status === "verified") {
    throw new Error("IDENTITY_REPLAY_DETECTED");
  }

  if (terminal.includes(session.status)) {
    throw new Error("IDENTITY_CHALLENGE_INVALID");
  }

  if (now.getTime() > session.expiresAt.getTime()) {
    throw new Error("IDENTITY_CHALLENGE_EXPIRED");
  }

  if (session.attemptCount >= session.maxAttempts) {
    throw new Error("IDENTITY_CHALLENGE_INVALID");
  }
}

export function transitionIdentitySession(
  session: IdentitySession,
  next: IdentitySessionStatus,
  now: Date
): IdentitySession {
  if (!allowedTransitions[session.status].includes(next)) {
    throw new Error("INVALID_IDENTITY_SESSION_TRANSITION");
  }

  const isTerminal = terminal.includes(next);
  return {
    ...session,
    status: next,
    updatedAt: new Date(now),
    ...(isTerminal ? { completedAt: new Date(now) } : {}),
  };
}
