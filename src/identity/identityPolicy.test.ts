import { describe, expect, it } from "vitest";
import {
  assertAssuranceSatisfied,
  assertIdentityProviderAllowed,
  type IdentityPolicy,
} from "./identityPolicy.js";

const policy: IdentityPolicy = {
  id: "fake-standard",
  identityRequired: true,
  consentRequired: true,
  allowedMethods: ["fake"],
  minimumAssurance: "strong",
  allowedProviderIds: ["fake-identity"],
  challengeTtlSeconds: 300,
  maxChallengeAttempts: 3,
};

describe("IdentityPolicy", () => {
  it("accepts assurance at or above the configured minimum", () => {
    expect(() => assertAssuranceSatisfied(policy, "strong")).not.toThrow();
    expect(() => assertAssuranceSatisfied(policy, "high")).not.toThrow();
  });

  it("rejects an assurance downgrade", () => {
    expect(() => assertAssuranceSatisfied(policy, "basic")).toThrowError(
      "IDENTITY_ASSURANCE_INSUFFICIENT"
    );
  });

  it("rejects an identity method not allowed by policy", () => {
    expect(() =>
      assertIdentityProviderAllowed(
        policy,
        {
          id: "fake-identity",
          version: "0.1.0",
          kind: "identity",
          trustMode: "fake",
          levels: ["simple"],
          formats: ["detached"],
        },
        "oidc"
      )
    ).toThrowError("TRUST_POLICY_VIOLATION");
  });

  it("rejects an identity provider not allowed by policy", () => {
    expect(() =>
      assertIdentityProviderAllowed(
        policy,
        {
          id: "other-provider",
          version: "0.1.0",
          kind: "identity",
          trustMode: "fake",
          levels: ["simple"],
          formats: ["detached"],
        },
        "fake"
      )
    ).toThrowError("TRUST_POLICY_VIOLATION");
  });

  it("rejects a non-identity provider", () => {
    expect(() =>
      assertIdentityProviderAllowed(
        policy,
        {
          id: "fake-signing",
          version: "0.1.0",
          kind: "signing",
          trustMode: "fake",
          levels: ["simple"],
          formats: ["detached"],
        },
        "fake"
      )
    ).toThrowError("TRUST_POLICY_VIOLATION");
  });
});
