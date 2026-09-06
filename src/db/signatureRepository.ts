import type { SignatureRequest, SignatureStatus } from "../signatures/domain.js";

export type SignatureEvidence = {
  id: string;
  requestId: string;
  tenantId: string;
  type: string;
  payload: Record<string, unknown>;
  createdAt: string;
};

export interface SignatureRepository {
  create(tenantId: string, request: SignatureRequest): Promise<void>;
  findById(tenantId: string, id: string): Promise<SignatureRequest | null>;
  updateStatus(tenantId: string, id: string, status: SignatureStatus): Promise<boolean>;
  appendEvidence(tenantId: string, evidence: SignatureEvidence): Promise<void>;
}

export class InMemorySignatureRepository implements SignatureRepository {
  private readonly requests = new Map<string, SignatureRequest>();
  private readonly evidence: SignatureEvidence[] = [];

  private key(tenantId: string, id: string): string {
    return `${tenantId}:${id}`;
  }

  async create(tenantId: string, request: SignatureRequest): Promise<void> {
    if (request.tenantId !== tenantId) {
      throw new Error("TENANT_MISMATCH");
    }
    this.requests.set(this.key(tenantId, request.id), structuredClone(request));
  }

  async findById(tenantId: string, id: string): Promise<SignatureRequest | null> {
    const request = this.requests.get(this.key(tenantId, id));
    return request ? structuredClone(request) : null;
  }

  async updateStatus(
    tenantId: string,
    id: string,
    status: SignatureStatus
  ): Promise<boolean> {
    const key = this.key(tenantId, id);
    const current = this.requests.get(key);
    if (!current) return false;
    this.requests.set(key, { ...current, status });
    return true;
  }

  async appendEvidence(tenantId: string, evidence: SignatureEvidence): Promise<void> {
    if (evidence.tenantId !== tenantId) {
      throw new Error("TENANT_MISMATCH");
    }
    this.evidence.push(structuredClone(evidence));
  }
}
