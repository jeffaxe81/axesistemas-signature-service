import type { AuthenticationMethod, IdentityAssurance } from "./identityPolicy.js";

export type IdentityEvidence = Readonly<{
  tenantId: string;
  id: string;
  requestId: string;
  participantId: string;
  identitySessionId: string;
  providerId: string;
  method: AuthenticationMethod;
  assurance: IdentityAssurance;
  acr?: string;
  amr?: string[];
  externalSubjectHash?: string;
  verifiedAt: Date;
  providerEvidence: Record<string, unknown>;
  createdAt: Date;
}>;

export function createIdentityEvidence(input: IdentityEvidence): IdentityEvidence {
  return Object.freeze({ ...input });
}
