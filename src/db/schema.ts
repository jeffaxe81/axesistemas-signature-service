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

export const identitySessions = pgTable(
  "identity_sessions",
  {
    tenantId: text("tenant_id").notNull(),
    id: text("id").notNull(),
    requestId: text("request_id").notNull(),
    participantId: text("participant_id").notNull(),
    providerId: text("provider_id").notNull(),
    providerSessionId: text("provider_session_id").notNull(),
    method: text("method").notNull(),
    purpose: text("purpose").notNull(),
    status: text("status").notNull(),
    challengeId: text("challenge_id").notNull(),
    challengeDigest: varchar("challenge_digest", { length: 64 }).notNull(),
    expiresAt: timestamp("expires_at", { withTimezone: true }).notNull(),
    attemptCount: integer("attempt_count").notNull(),
    maxAttempts: integer("max_attempts").notNull(),
    createdAt: timestamp("created_at", { withTimezone: true }).notNull(),
    updatedAt: timestamp("updated_at", { withTimezone: true }).notNull(),
    completedAt: timestamp("completed_at", { withTimezone: true }),
  },
  table => [
    primaryKey({ columns: [table.tenantId, table.id] }),
    index("identity_sessions_tenant_request_participant_idx").on(
      table.tenantId,
      table.requestId,
      table.participantId
    ),
  ]
);

export const identityEvidences = pgTable(
  "identity_evidences",
  {
    tenantId: text("tenant_id").notNull(),
    id: text("id").notNull(),
    requestId: text("request_id").notNull(),
    participantId: text("participant_id").notNull(),
    identitySessionId: text("identity_session_id").notNull(),
    providerId: text("provider_id").notNull(),
    method: text("method").notNull(),
    assurance: text("assurance").notNull(),
    acr: text("acr"),
    amr: jsonb("amr").$type<string[]>(),
    externalSubjectHash: varchar("external_subject_hash", { length: 64 }),
    verifiedAt: timestamp("verified_at", { withTimezone: true }).notNull(),
    providerEvidence: jsonb("provider_evidence").$type<Record<string, unknown>>().notNull(),
    createdAt: timestamp("created_at", { withTimezone: true }).notNull(),
  },
  table => [
    primaryKey({ columns: [table.tenantId, table.id] }),
    index("identity_evidences_tenant_request_participant_idx").on(
      table.tenantId,
      table.requestId,
      table.participantId
    ),
  ]
);

export const consentRecords = pgTable(
  "consent_records",
  {
    tenantId: text("tenant_id").notNull(),
    id: text("id").notNull(),
    requestId: text("request_id").notNull(),
    participantId: text("participant_id").notNull(),
    identityEvidenceId: text("identity_evidence_id").notNull(),
    documentSha256: varchar("document_sha256", { length: 64 }).notNull(),
    statementHash: varchar("statement_hash", { length: 64 }).notNull(),
    decision: text("decision").notNull(),
    status: text("status").notNull(),
    providerId: text("provider_id").notNull(),
    acceptedAt: timestamp("accepted_at", { withTimezone: true }),
    declinedAt: timestamp("declined_at", { withTimezone: true }),
    expiresAt: timestamp("expires_at", { withTimezone: true }),
    providerEvidence: jsonb("provider_evidence").$type<Record<string, unknown>>().notNull(),
    createdAt: timestamp("created_at", { withTimezone: true }).notNull(),
  },
  table => [
    primaryKey({ columns: [table.tenantId, table.id] }),
    index("consent_records_tenant_request_participant_idx").on(
      table.tenantId,
      table.requestId,
      table.participantId
    ),
  ]
);
