import { expect, it } from "vitest";
import type { ProviderDescriptor } from "./capabilities.js";
import { ProviderRegistry } from "./providerRegistry.js";
import {
  assertProviderAllowed,
  fakeDevProfile,
  type TrustProfile,
} from "./trustProfile.js";

const sandboxProvider: ProviderDescriptor = {
  id: "sandbox-sign",
  version: "1",
  kind: "signing",
  trustMode: "sandbox",
  signatureLevels: ["advanced"],
  signatureFormats: ["detached"],
};

it("fake-dev aceita exclusivamente providers fake", () => {
  expect(() => assertProviderAllowed(fakeDevProfile, sandboxProvider)).toThrow(
    "TRUST_POLICY_VIOLATION"
  );
});

it("registry respeita níveis e formatos permitidos pelo trust profile", () => {
  const restrictedProfile: TrustProfile = {
    id: "fake-dev",
    trustMode: "fake",
    allowedProviderIds: "*",
    allowedLevels: ["simple"],
    allowedFormats: ["detached"],
    timestampRequired: false,
  };
  const provider = {
    descriptor: {
      ...sandboxProvider,
      id: "fake-advanced",
      trustMode: "fake" as const,
    },
  };
  const registry = new ProviderRegistry();
  registry.register(provider);

  expect(() =>
    registry.resolve("signing", restrictedProfile, {
      level: "advanced",
      format: "detached",
    })
  ).toThrow("UNSUPPORTED_CAPABILITY");
});
