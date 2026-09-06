import type { SignatureRepository } from "../db/signatureRepository.js";
import type { TenantContext } from "../security/tenantContext.js";
import {
  transitionSignatureStatus,
  type SignatureStatus,
} from "../signatures/domain.js";

export type ProviderWebhookEvent = {
  eventId: string;
  requestId: string;
  providerRequestId: string;
  status: Extract<SignatureStatus, "signed" | "rejected" | "expired" | "failed">;
};

export interface ProviderEventStore {
  executeOnce<T>(
    tenantId: string,
    eventId: string,
    effect: () => Promise<T>
  ): Promise<{ duplicate: boolean; value?: T }>;
}

export class InMemoryProviderEventStore implements ProviderEventStore {
  private readonly claimed = new Set<string>();

  async executeOnce<T>(
    tenantId: string,
    eventId: string,
    effect: () => Promise<T>
  ): Promise<{ duplicate: boolean; value?: T }> {
    const key = `${tenantId}:${eventId}`;
    if (this.claimed.has(key)) return { duplicate: true };

    this.claimed.add(key);
    try {
      const value = await effect();
      return { duplicate: false, value };
    } catch (error) {
      this.claimed.delete(key);
      throw error;
    }
  }
}

export type ProviderWebhookHandlerDependencies = {
  repository: SignatureRepository;
  eventStore: ProviderEventStore;
  now: () => string;
};

export class ProviderWebhookHandler {
  constructor(private readonly dependencies: ProviderWebhookHandlerDependencies) {}

  async handle(context: TenantContext, event: ProviderWebhookEvent): Promise<{ duplicate: boolean }> {
    const result = await this.dependencies.eventStore.executeOnce(
      context.tenantId,
      event.eventId,
      async () => {
        const request = await this.dependencies.repository.findById(
          context.tenantId,
          event.requestId
        );

        if (!request) {
          throw new Error("SIGNATURE_REQUEST_NOT_FOUND");
        }

        if (request.providerRequestId !== event.providerRequestId) {
          throw new Error("PROVIDER_REQUEST_MISMATCH");
        }

        const nextStatus = transitionSignatureStatus(request.status, event.status);
        const updated = await this.dependencies.repository.updateStatus(
          context.tenantId,
          request.id,
          nextStatus
        );

        if (!updated) {
          throw new Error("SIGNATURE_REQUEST_UPDATE_FAILED");
        }

        await this.dependencies.repository.appendEvidence(context.tenantId, {
          id: `${request.id}:provider:${event.eventId}`,
          requestId: request.id,
          tenantId: context.tenantId,
          type: "signature.provider-status",
          payload: {
            subject: context.subject,
            eventId: event.eventId,
            providerRequestId: event.providerRequestId,
            status: nextStatus,
          },
          createdAt: this.dependencies.now(),
        });
      }
    );

    return { duplicate: result.duplicate };
  }
}
