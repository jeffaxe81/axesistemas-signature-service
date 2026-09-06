import type {
  CreateSignatureProviderRequest,
  CreateSignatureProviderResult,
  SignatureProvider,
} from "./signatureProvider.js";

export class FakeSignatureProvider implements SignatureProvider {
  async createRequest(
    input: CreateSignatureProviderRequest
  ): Promise<CreateSignatureProviderResult> {
    return { providerRequestId: `fake:${input.requestId}` };
  }

  async cancelRequest(_providerRequestId: string): Promise<void> {
    return undefined;
  }
}
