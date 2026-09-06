CREATE TABLE "signature_requests" (
  "tenant_id" text NOT NULL,
  "id" text NOT NULL,
  "status" text NOT NULL,
  "document_sha256" varchar(64) NOT NULL,
  "provider_request_id" text,
  "signer" jsonb NOT NULL,
  "created_at" timestamp with time zone DEFAULT now() NOT NULL,
  "updated_at" timestamp with time zone DEFAULT now() NOT NULL,
  CONSTRAINT "signature_requests_tenant_id_id_pk" PRIMARY KEY("tenant_id", "id")
);
--> statement-breakpoint
CREATE INDEX "signature_requests_tenant_status_idx" ON "signature_requests" USING btree ("tenant_id", "status");
--> statement-breakpoint
CREATE TABLE "signature_evidence" (
  "tenant_id" text NOT NULL,
  "id" text NOT NULL,
  "request_id" text NOT NULL,
  "type" text NOT NULL,
  "payload" jsonb NOT NULL,
  "created_at" timestamp with time zone DEFAULT now() NOT NULL,
  CONSTRAINT "signature_evidence_tenant_id_id_pk" PRIMARY KEY("tenant_id", "id")
);
--> statement-breakpoint
CREATE INDEX "signature_evidence_tenant_request_idx" ON "signature_evidence" USING btree ("tenant_id", "request_id");
