import { describe, expect, it } from "vitest";
import {
  assertProviderAllowed,
  fakeDevProfile,
  productionStandardProfile,
} from "./trustProfile.js";
import type { ProviderDescriptor } from "./capabilities.js";

const fakeProvider: ProviderDescriptor = {
  id: "fake-signing",
  version: "1.0.0",
  kind: "signing",
  trustMode: "fake",
  signatureLevels: ["simple", "advanced"],
  signatureFormats: ["detached"],
};

describe("TrustProfile", () => {
  it("permite provider fake somente no profile fake-dev", () => {
    expect(() => assertProviderAllowed(fakeDevProfile, fakeProvider)).not.toThrow();
  });

  it("rejeita provider fake no profile production-standard", () => {
    expect(() => assertProviderAllowed(productionStandardProfile, fakeProvider)).toThrow(
      "TRUST_POLICY_VIOLATION"
    );
  });
});
