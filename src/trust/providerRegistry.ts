import type {
  ProviderDescriptor,
  ProviderKind,
  SignatureFormat,
  SignatureLevel,
} from "./capabilities.js";
import {
  assertProviderAllowed,
  type TrustProfile,
} from "./trustProfile.js";

export type RegisteredProvider = {
  descriptor: ProviderDescriptor;
};

export class ProviderRegistry {
  private readonly providers: RegisteredProvider[] = [];

  register(provider: RegisteredProvider): void {
    this.providers.push(provider);
  }

  resolve(
    kind: ProviderKind,
    profile: TrustProfile,
    requirements: {
      level: SignatureLevel;
      format: SignatureFormat;
    }
  ): RegisteredProvider {
    if (
      !profile.allowedLevels.includes(requirements.level) ||
      !profile.allowedFormats.includes(requirements.format)
    ) {
      throw new Error("UNSUPPORTED_CAPABILITY");
    }

    const candidate = this.providers.find(provider => {
      if (provider.descriptor.kind !== kind) return false;

      try {
        assertProviderAllowed(profile, provider.descriptor);
      } catch {
        return false;
      }

      return (
        provider.descriptor.signatureLevels.includes(requirements.level) &&
        provider.descriptor.signatureFormats.includes(requirements.format)
      );
    });

    if (!candidate) {
      throw new Error("UNSUPPORTED_CAPABILITY");
    }

    return candidate;
  }
}
