CREATE TABLE "identity_sessions" (
  "tenant_id" text NOT NULL,
  "id" text NOT NULL,
  "request_id" text NOT NULL,
  "participant_id" text NOT NULL,
  "provider_id" text NOT NULL,
  "provider_session_id" text NOT NULL,
  "method" text NOT NULL,
  "purpose" text NOT NULL,
  "status" text NOT NULL,
  "challenge_id" text NOT NULL,
  "challenge_digest" varchar(64) NOT NULL,
  "expires_at" timestamp with time zone NOT NULL,
  "attempt_count" integer NOT NULL,
  "max_attempts" integer NOT NULL,
  "created_at" timestamp with time zone NOT NULL,
  "updated_at" timestamp with time zone NOT NULL,
  "completed_at" timestamp with time zone,
  CONSTRAINT "identity_sessions_tenant_id_id_pk" PRIMARY KEY("tenant_id", "id")
);
--> statement-breakpoint
CREATE INDEX "identity_sessions_tenant_request_participant_idx" ON "identity_sessions" USING btree ("tenant_id", "request_id", "participant_id");
--> statement-breakpoint
CREATE TABLE "identity_evidences" (
  "tenant_id" text NOT NULL,
  "id" text NOT NULL,
  "request_id" text NOT NULL,
  "participant_id" text NOT NULL,
  "identity_session_id" text NOT NULL,
  "provider_id" text NOT NULL,
  "method" text NOT NULL,
  "assurance" text NOT NULL,
  "acr" text,
  "amr" jsonb,
  "external_subject_hash" varchar(64),
  "verified_at" timestamp with time zone NOT NULL,
  "provider_evidence" jsonb NOT NULL,
  "created_at" timestamp with time zone NOT NULL,
  CONSTRAINT "identity_evidences_tenant_id_id_pk" PRIMARY KEY("tenant_id", "id")
);
--> statement-breakpoint
CREATE INDEX "identity_evidences_tenant_request_participant_idx" ON "identity_evidences" USING btree ("tenant_id", "request_id", "participant_id");
--> statement-breakpoint
CREATE TABLE "consent_records" (
  "tenant_id" text NOT NULL,
  "id" text NOT NULL,
  "request_id" text NOT NULL,
  "participant_id" text NOT NULL,
  "identity_evidence_id" text NOT NULL,
  "document_sha256" varchar(64) NOT NULL,
  "statement_hash" varchar(64) NOT NULL,
  "decision" text NOT NULL,
  "status" text NOT NULL,
  "provider_id" text NOT NULL,
  "accepted_at" timestamp with time zone,
  "declined_at" timestamp with time zone,
  "expires_at" timestamp with time zone,
  "provider_evidence" jsonb NOT NULL,
  "created_at" timestamp with time zone NOT NULL,
  CONSTRAINT "consent_records_tenant_id_id_pk" PRIMARY KEY("tenant_id", "id")
);
--> statement-breakpoint
CREATE INDEX "consent_records_tenant_request_participant_idx" ON "consent_records" USING btree ("tenant_id", "request_id", "participant_id");
