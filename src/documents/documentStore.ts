export type StoredDocument = {
  key: string;
  sizeBytes: number;
  contentType?: string;
};

export interface DocumentStore {
  put(input: {
    tenantId: string;
    requestId: string;
    bytes: Buffer;
    contentType?: string;
  }): Promise<StoredDocument>;

  get(input: { tenantId: string; key: string }): Promise<Buffer | null>;
}
