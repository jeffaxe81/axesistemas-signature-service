import type { ProviderDescriptor } from "../trust/capabilities.js";

export type AuthenticationMethod =
  | "fake"
  | "email_otp"
  | "sms_otp"
  | "totp"
  | "oidc"
  | "webauthn"
  | "biometric"
  | "govbr";

export type IdentityAssurance = "basic" | "strong" | "high";

export type IdentityPolicy = {
  id: string;
  identityRequired: boolean;
  consentRequired: boolean;
  allowedMethods: AuthenticationMethod[];
  minimumAssurance: IdentityAssurance;
  allowedProviderIds: string[] | "*";
  challengeTtlSeconds: number;
  maxChallengeAttempts: number;
  identityEvidenceMaxAgeSeconds?: number;
  consentMaxAgeSeconds?: number;
};

const assuranceRank: Record<IdentityAssurance, number> = {
  basic: 1,
  strong: 2,
  high: 3,
};

export function assertAssuranceSatisfied(
  policy: IdentityPolicy,
  achieved: IdentityAssurance
): void {
  if (assuranceRank[achieved] < assuranceRank[policy.minimumAssurance]) {
    throw new Error("IDENTITY_ASSURANCE_INSUFFICIENT");
  }
}

export function assertIdentityProviderAllowed(
  policy: IdentityPolicy,
  provider: ProviderDescriptor,
  method: AuthenticationMethod
): void {
  if (provider.kind !== "identity") {
    throw new Error("TRUST_POLICY_VIOLATION");
  }

  if (!policy.allowedMethods.includes(method)) {
    throw new Error("TRUST_POLICY_VIOLATION");
  }

  if (
    policy.allowedProviderIds !== "*" &&
    !policy.allowedProviderIds.includes(provider.id)
  ) {
    throw new Error("TRUST_POLICY_VIOLATION");
  }
}
