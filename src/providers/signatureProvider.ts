export type CreateSignatureProviderRequest = {
  requestId: string;
  documentSha256: string;
};

export type CreateSignatureProviderResult = {
  providerRequestId: string;
};

export interface SignatureProvider {
  createRequest(
    input: CreateSignatureProviderRequest
  ): Promise<CreateSignatureProviderResult>;

  cancelRequest(providerRequestId: string): Promise<void>;
}
