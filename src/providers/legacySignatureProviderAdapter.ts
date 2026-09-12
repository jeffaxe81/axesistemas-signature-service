import type { ProviderDescriptor } from "../trust/capabilities.js";
import type {
  SigningInput,
  SigningProvider,
  SigningResult,
} from "./providerContracts.js";
import type { SignatureProvider } from "./signatureProvider.js";

export class LegacySignatureProviderAdapter implements SigningProvider {
  readonly descriptor: ProviderDescriptor = {
    id: "legacy-signature-provider",
    version: "0.1.0",
    kind: "signing",
    trustMode: "fake",
    signatureLevels: ["simple"],
    signatureFormats: ["detached"],
  };

  constructor(private readonly legacy: SignatureProvider) {}

  async sign(input: SigningInput): Promise<SigningResult> {
    const result = await this.legacy.createRequest({
      requestId: input.requestId,
      documentSha256: input.documentSha256,
    });

    return {
      providerRequestId: result.providerRequestId,
      status: "pending",
    };
  }

  async cancel(providerRequestId: string): Promise<void> {
    await this.legacy.cancelRequest(providerRequestId);
  }
}
