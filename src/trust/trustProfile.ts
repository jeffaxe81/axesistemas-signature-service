import type {
  ProviderDescriptor,
  SignatureFormat,
  SignatureLevel,
  TrustMode,
} from "./capabilities.js";

export type TrustProfile = {
  id: "fake-dev" | "sandbox" | "production-standard";
  trustMode: TrustMode;
  allowedProviderIds: string[] | "*";
  allowedLevels: SignatureLevel[];
  allowedFormats: SignatureFormat[];
  timestampRequired: boolean;
};

const allLevels: SignatureLevel[] = ["simple", "advanced", "qualified"];
const allFormats: SignatureFormat[] = [
  "pades",
  "cades",
  "xades",
  "xmldsig",
  "detached",
  "asic",
  "jades",
  "proprietary",
];

export const fakeDevProfile: TrustProfile = {
  id: "fake-dev",
  trustMode: "fake",
  allowedProviderIds: "*",
  allowedLevels: [...allLevels],
  allowedFormats: [...allFormats],
  timestampRequired: false,
};

export const sandboxProfile: TrustProfile = {
  id: "sandbox",
  trustMode: "sandbox",
  allowedProviderIds: [],
  allowedLevels: [...allLevels],
  allowedFormats: [...allFormats],
  timestampRequired: false,
};

export const productionStandardProfile: TrustProfile = {
  id: "production-standard",
  trustMode: "production",
  allowedProviderIds: [],
  allowedLevels: [...allLevels],
  allowedFormats: [...allFormats],
  timestampRequired: false,
};

export function assertProviderAllowed(
  profile: TrustProfile,
  provider: ProviderDescriptor
): void {
  if (profile.trustMode === "production" && provider.trustMode === "fake") {
    throw new Error("TRUST_POLICY_VIOLATION");
  }

  if (
    profile.allowedProviderIds !== "*" &&
    !profile.allowedProviderIds.includes(provider.id)
  ) {
    throw new Error("TRUST_POLICY_VIOLATION");
  }
}
