import type {
  CreateSignatureProviderRequest,
  CreateSignatureProviderResult,
  SignatureProvider,
} from "./signatureProvider.js";

export class FakeSignatureProvider implements SignatureProvider {
  lastCreate?: CreateSignatureProviderRequest;

  async createRequest(
    input: CreateSignatureProviderRequest
  ): Promise<CreateSignatureProviderResult> {
    this.lastCreate = structuredClone(input);
    return { providerRequestId: `fake:${input.requestId}` };
  }

  async cancelRequest(_providerRequestId: string): Promise<void> {
    return undefined;
  }
}
