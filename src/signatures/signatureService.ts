import type { SignatureRepository } from "../db/signatureRepository.js";
import { sha256 } from "../documents/documentHash.js";
import type { DocumentStore } from "../documents/documentStore.js";
import type { SignatureProvider } from "../providers/signatureProvider.js";
import type { TenantContext } from "../security/tenantContext.js";
import {
  transitionSignatureStatus,
  type SignatureRequest,
} from "./domain.js";

export type SignatureServiceDependencies = {
  repository: SignatureRepository;
  documentStore: DocumentStore;
  provider: SignatureProvider;
  idFactory: () => string;
  now: () => string;
};

export type CreateSignatureRequestInput = {
  document: Buffer;
  contentType?: string;
  signer: {
    name: string;
    document?: string;
    email?: string;
  };
};

export class SignatureService {
  constructor(private readonly dependencies: SignatureServiceDependencies) {}

  async createSignatureRequest(
    context: TenantContext,
    input: CreateSignatureRequestInput
  ): Promise<SignatureRequest> {
    const id = this.dependencies.idFactory();
    const documentSha256 = sha256(input.document);

    const stored = await this.dependencies.documentStore.put({
      tenantId: context.tenantId,
      requestId: id,
      bytes: input.document,
      contentType: input.contentType,
    });

    const draft: SignatureRequest = {
      id,
      tenantId: context.tenantId,
      status: "draft",
      documentSha256,
      signer: structuredClone(input.signer),
    };

    await this.dependencies.repository.create(context.tenantId, draft);

    try {
      const providerResult = await this.dependencies.provider.createRequest({
        requestId: id,
        documentSha256,
      });

      await this.dependencies.repository.setProviderRequestId(
        context.tenantId,
        id,
        providerResult.providerRequestId
      );

      const pending = transitionSignatureStatus("draft", "pending");
      await this.dependencies.repository.updateStatus(context.tenantId, id, pending);
      await this.dependencies.repository.appendEvidence(context.tenantId, {
        id: `${id}:requested`,
        requestId: id,
        tenantId: context.tenantId,
        type: "signature.requested",
        payload: {
          subject: context.subject,
          documentSha256,
          storageKey: stored.key,
          providerRequestId: providerResult.providerRequestId,
        },
        createdAt: this.dependencies.now(),
      });
    } catch (error) {
      const failed = transitionSignatureStatus("draft", "failed");
      await this.dependencies.repository.updateStatus(context.tenantId, id, failed);
      throw error;
    }

    const result = await this.dependencies.repository.findById(context.tenantId, id);
    if (!result) throw new Error("SIGNATURE_REQUEST_NOT_FOUND_AFTER_CREATE");
    return result;
  }

  async getSignatureRequest(
    context: TenantContext,
    id: string
  ): Promise<SignatureRequest | null> {
    return this.dependencies.repository.findById(context.tenantId, id);
  }
}
