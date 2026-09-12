CREATE TABLE "signature_participants" (
  "tenant_id" text NOT NULL,
  "request_id" text NOT NULL,
  "id" text NOT NULL,
  "role" text NOT NULL,
  "status" text NOT NULL,
  "signing_order" integer,
  "identity" jsonb NOT NULL,
  "authentication_methods" jsonb NOT NULL,
  "created_at" timestamp with time zone DEFAULT now() NOT NULL,
  "updated_at" timestamp with time zone DEFAULT now() NOT NULL,
  CONSTRAINT "signature_participants_tenant_id_id_pk" PRIMARY KEY("tenant_id", "id")
);
--> statement-breakpoint
CREATE INDEX "signature_participants_tenant_request_idx" ON "signature_participants" USING btree ("tenant_id", "request_id");
--> statement-breakpoint
CREATE TABLE "provider_bindings" (
  "tenant_id" text NOT NULL,
  "id" text NOT NULL,
  "request_id" text NOT NULL,
  "participant_id" text,
  "provider_id" text NOT NULL,
  "provider_kind" text NOT NULL,
  "provider_request_id" text,
  "trust_mode" text NOT NULL,
  "created_at" timestamp with time zone DEFAULT now() NOT NULL,
  CONSTRAINT "provider_bindings_tenant_id_id_pk" PRIMARY KEY("tenant_id", "id")
);
--> statement-breakpoint
CREATE INDEX "provider_bindings_tenant_request_idx" ON "provider_bindings" USING btree ("tenant_id", "request_id");
--> statement-breakpoint
CREATE TABLE "document_artifacts" (
  "tenant_id" text NOT NULL,
  "id" text NOT NULL,
  "request_id" text NOT NULL,
  "storage_key" text NOT NULL,
  "sha256" varchar(64) NOT NULL,
  "content_type" text,
  "size_bytes" integer,
  "created_at" timestamp with time zone DEFAULT now() NOT NULL,
  CONSTRAINT "document_artifacts_tenant_id_id_pk" PRIMARY KEY("tenant_id", "id")
);
--> statement-breakpoint
CREATE INDEX "document_artifacts_tenant_request_idx" ON "document_artifacts" USING btree ("tenant_id", "request_id");
--> statement-breakpoint
CREATE TABLE "signature_artifacts" (
  "tenant_id" text NOT NULL,
  "id" text NOT NULL,
  "request_id" text NOT NULL,
  "participant_id" text,
  "provider_id" text NOT NULL,
  "storage_key" text NOT NULL,
  "sha256" varchar(64) NOT NULL,
  "trust_mode" text NOT NULL,
  "created_at" timestamp with time zone DEFAULT now() NOT NULL,
  CONSTRAINT "signature_artifacts_tenant_id_id_pk" PRIMARY KEY("tenant_id", "id")
);
--> statement-breakpoint
CREATE INDEX "signature_artifacts_tenant_request_idx" ON "signature_artifacts" USING btree ("tenant_id", "request_id");
--> statement-breakpoint
CREATE TABLE "validation_results" (
  "tenant_id" text NOT NULL,
  "id" text NOT NULL,
  "request_id" text NOT NULL,
  "participant_id" text,
  "provider_id" text NOT NULL,
  "valid" boolean NOT NULL,
  "code" text,
  "trust_mode" text NOT NULL,
  "evidence" jsonb NOT NULL,
  "created_at" timestamp with time zone DEFAULT now() NOT NULL,
  CONSTRAINT "validation_results_tenant_id_id_pk" PRIMARY KEY("tenant_id", "id")
);
--> statement-breakpoint
CREATE INDEX "validation_results_tenant_request_idx" ON "validation_results" USING btree ("tenant_id", "request_id");
--> statement-breakpoint
CREATE TABLE "trust_profiles" (
  "tenant_id" text NOT NULL,
  "id" text NOT NULL,
  "trust_mode" text NOT NULL,
  "config" jsonb NOT NULL,
  "created_at" timestamp with time zone DEFAULT now() NOT NULL,
  "updated_at" timestamp with time zone DEFAULT now() NOT NULL,
  CONSTRAINT "trust_profiles_tenant_id_id_pk" PRIMARY KEY("tenant_id", "id")
);
--> statement-breakpoint
CREATE INDEX "trust_profiles_tenant_mode_idx" ON "trust_profiles" USING btree ("tenant_id", "trust_mode");
