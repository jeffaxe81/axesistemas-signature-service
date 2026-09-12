import type { ProviderDescriptor } from "../trust/capabilities.js";
import type {
  ConsentProvider,
  RecordConsentInput,
} from "./providerContracts.js";

export type FakeConsentProviderOptions = {
  fail?: boolean;
};

export class FakeConsentProvider implements ConsentProvider {
  readonly descriptor: ProviderDescriptor = {
    id: "fake-consent",
    version: "0.1.0",
    kind: "consent",
    trustMode: "fake",
    signatureLevels: ["simple"],
    signatureFormats: ["detached"],
  };

  constructor(private readonly options: FakeConsentProviderOptions = {}) {}

  async record(input: RecordConsentInput): Promise<{
    recorded: boolean;
    evidence: Record<string, unknown>;
  }> {
    if (this.options.fail) {
      throw new Error("IDENTITY_PROVIDER_UNAVAILABLE");
    }

    return {
      recorded: true,
      evidence: {
        provider: "fake-consent",
        decision: input.decision,
      },
    };
  }
}
