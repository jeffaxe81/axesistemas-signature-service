import {
  index,
  jsonb,
  pgTable,
  primaryKey,
  text,
  timestamp,
  varchar,
} from "drizzle-orm/pg-core";

export const signatureRequests = pgTable(
  "signature_requests",
  {
    tenantId: text("tenant_id").notNull(),
    id: text("id").notNull(),
    status: text("status").notNull(),
    documentSha256: varchar("document_sha256", { length: 64 }).notNull(),
    providerRequestId: text("provider_request_id"),
    signer: jsonb("signer").$type<{
      name: string;
      document?: string;
      email?: string;
    }>().notNull(),
    createdAt: timestamp("created_at", { withTimezone: true }).defaultNow().notNull(),
    updatedAt: timestamp("updated_at", { withTimezone: true }).defaultNow().notNull(),
  },
  table => [
    primaryKey({ columns: [table.tenantId, table.id] }),
    index("signature_requests_tenant_status_idx").on(table.tenantId, table.status),
  ]
);

export const signatureEvidence = pgTable(
  "signature_evidence",
  {
    tenantId: text("tenant_id").notNull(),
    id: text("id").notNull(),
    requestId: text("request_id").notNull(),
    type: text("type").notNull(),
    payload: jsonb("payload").$type<Record<string, unknown>>().notNull(),
    createdAt: timestamp("created_at", { withTimezone: true }).defaultNow().notNull(),
  },
  table => [
    primaryKey({ columns: [table.tenantId, table.id] }),
    index("signature_evidence_tenant_request_idx").on(table.tenantId, table.requestId),
  ]
);
