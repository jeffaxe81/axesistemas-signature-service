import { FakeCertificateAuthority } from "./fakeCertificateAuthority.js";
import { FakeSigningProvider } from "./fakeSigningProvider.js";
import { FakeTimestampProvider } from "./fakeTimestampProvider.js";
import { FakeValidationProvider } from "./fakeValidationProvider.js";
import { ProviderRegistry } from "../trust/providerRegistry.js";
import { UniversalTrustService } from "../signatures/universalTrustService.js";

export function makeFakeUniversalService() {
  const ca = new FakeCertificateAuthority({
    now: () => new Date("2026-09-12T12:00:00.000Z"),
  });
  const certificate = ca.issue({
    subject: "AXESISTEMAS FAKE DEV SIGNER",
    validForSeconds: 3600,
  });
  const signingProvider = new FakeSigningProvider(ca, certificate.serial);
  const validationProvider = new FakeValidationProvider(ca);
  const timestampProvider = new FakeTimestampProvider({
    now: () => new Date("2026-09-12T12:00:00.000Z"),
  });
  const registry = new ProviderRegistry();
  registry.register(signingProvider);
  registry.register(validationProvider);
  registry.register(timestampProvider);

  return {
    service: new UniversalTrustService({ registry }),
    ca,
    signingProvider,
    validationProvider,
    timestampProvider,
    registry,
  };
}
