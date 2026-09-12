import {
  boolean,
  index,
  integer,
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

export const signatureParticipants = pgTable(
  "signature_participants",
  {
    tenantId: text("tenant_id").notNull(),
    requestId: text("request_id").notNull(),
    id: text("id").notNull(),
    role: text("role").notNull(),
    status: text("status").notNull(),
    signingOrder: integer("signing_order"),
    identity: jsonb("identity").$type<Record<string, unknown>>().notNull(),
    authenticationMethods: jsonb("authentication_methods").$type<string[]>().notNull(),
    createdAt: timestamp("created_at", { withTimezone: true }).defaultNow().notNull(),
    updatedAt: timestamp("updated_at", { withTimezone: true }).defaultNow().notNull(),
  },
  table => [
    primaryKey({ columns: [table.tenantId, table.id] }),
    index("signature_participants_tenant_request_idx").on(table.tenantId, table.requestId),
  ]
);

export const providerBindings = pgTable(
  "provider_bindings",
  {
    tenantId: text("tenant_id").notNull(),
    id: text("id").notNull(),
    requestId: text("request_id").notNull(),
    participantId: text("participant_id"),
    providerId: text("provider_id").notNull(),
    providerKind: text("provider_kind").notNull(),
    providerRequestId: text("provider_request_id"),
    trustMode: text("trust_mode").notNull(),
    createdAt: timestamp("created_at", { withTimezone: true }).defaultNow().notNull(),
  },
  table => [
    primaryKey({ columns: [table.tenantId, table.id] }),
    index("provider_bindings_tenant_request_idx").on(table.tenantId, table.requestId),
  ]
);

export const documentArtifacts = pgTable(
  "document_artifacts",
  {
    tenantId: text("tenant_id").notNull(),
    id: text("id").notNull(),
    requestId: text("request_id").notNull(),
    storageKey: text("storage_key").notNull(),
    sha256: varchar("sha256", { length: 64 }).notNull(),
    contentType: text("content_type"),
    sizeBytes: integer("size_bytes"),
    createdAt: timestamp("created_at", { withTimezone: true }).defaultNow().notNull(),
  },
  table => [
    primaryKey({ columns: [table.tenantId, table.id] }),
    index("document_artifacts_tenant_request_idx").on(table.tenantId, table.requestId),
  ]
);

export const signatureArtifacts = pgTable(
  "signature_artifacts",
  {
    tenantId: text("tenant_id").notNull(),
    id: text("id").notNull(),
    requestId: text("request_id").notNull(),
    participantId: text("participant_id"),
    providerId: text("provider_id").notNull(),
    storageKey: text("storage_key").notNull(),
    sha256: varchar("sha256", { length: 64 }).notNull(),
    trustMode: text("trust_mode").notNull(),
    createdAt: timestamp("created_at", { withTimezone: true }).defaultNow().notNull(),
  },
  table => [
    primaryKey({ columns: [table.tenantId, table.id] }),
    index("signature_artifacts_tenant_request_idx").on(table.tenantId, table.requestId),
  ]
);

export const validationResults = pgTable(
  "validation_results",
  {
    tenantId: text("tenant_id").notNull(),
    id: text("id").notNull(),
    requestId: text("request_id").notNull(),
    participantId: text("participant_id"),
    providerId: text("provider_id").notNull(),
    valid: boolean("valid").notNull(),
    code: text("code"),
    trustMode: text("trust_mode").notNull(),
    evidence: jsonb("evidence").$type<Record<string, unknown>>().notNull(),
    createdAt: timestamp("created_at", { withTimezone: true }).defaultNow().notNull(),
  },
  table => [
    primaryKey({ columns: [table.tenantId, table.id] }),
    index("validation_results_tenant_request_idx").on(table.tenantId, table.requestId),
  ]
);

export const trustProfiles = pgTable(
  "trust_profiles",
  {
    tenantId: text("tenant_id").notNull(),
    id: text("id").notNull(),
    trustMode: text("trust_mode").notNull(),
    config: jsonb("config").$type<Record<string, unknown>>().notNull(),
    createdAt: timestamp("created_at", { withTimezone: true }).defaultNow().notNull(),
    updatedAt: timestamp("updated_at", { withTimezone: true }).defaultNow().notNull(),
  },
  table => [
    primaryKey({ columns: [table.tenantId, table.id] }),
    index("trust_profiles_tenant_mode_idx").on(table.tenantId, table.trustMode),
  ]
);
