import { expect, it } from "vitest";
import { ProviderRegistry } from "./providerRegistry.js";
import {
  fakeDevProfile,
  productionStandardProfile,
} from "./trustProfile.js";

const fake = {
  descriptor: {
    id: "fake-sign",
    version: "1",
    kind: "signing" as const,
    trustMode: "fake" as const,
    signatureLevels: ["advanced" as const],
    signatureFormats: ["detached" as const],
  },
};

it("resolve provider compatível com capacidade e profile", () => {
  const registry = new ProviderRegistry();
  registry.register(fake);
  expect(
    registry.resolve("signing", fakeDevProfile, {
      level: "advanced",
      format: "detached",
    }).descriptor.id
  ).toBe("fake-sign");
});

it("não faz fallback fake em produção", () => {
  const registry = new ProviderRegistry();
  registry.register(fake);
  expect(() =>
    registry.resolve("signing", productionStandardProfile, {
      level: "advanced",
      format: "detached",
    })
  ).toThrow("UNSUPPORTED_CAPABILITY");
});
