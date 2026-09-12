import { readFileSync } from "node:fs";
import { describe, expect, it } from "vitest";
import {
  consentRecords,
  identityEvidences,
  identitySessions,
} from "./schema.js";

describe("D-009C database schema", () => {
  it("exports the three tenant-scoped D-009C tables", () => {
    expect(identitySessions).toBeDefined();
    expect(identityEvidences).toBeDefined();
    expect(consentRecords).toBeDefined();
  });

  it("ships an additive migration with the three tables and indexes", () => {
    const migration = readFileSync(
      new URL("../../drizzle/0002_d009c_identity_consent.sql", import.meta.url),
      "utf8"
    );

    expect(migration).toContain('CREATE TABLE "identity_sessions"');
    expect(migration).toContain('CREATE TABLE "identity_evidences"');
    expect(migration).toContain('CREATE TABLE "consent_records"');
    expect(migration).toContain("identity_sessions_tenant_request_participant_idx");
    expect(migration).toContain("identity_evidences_tenant_request_participant_idx");
    expect(migration).toContain("consent_records_tenant_request_participant_idx");
    expect(migration).not.toMatch(/\b(DROP|TRUNCATE)\b|ALTER\s+TABLE[\s\S]*DROP/i);
  });

  it("does not introduce obvious reusable-secret columns", () => {
    const migration = readFileSync(
      new URL("../../drizzle/0002_d009c_identity_consent.sql", import.meta.url),
      "utf8"
    );
    expect(migration).not.toMatch(
      /plain.*otp|password|refresh.*token|private.*key|totp.*secret|bearer.*token/i
    );
    expect(migration).toContain('"challenge_digest" varchar(64) NOT NULL');
    expect(migration).toContain('"provider_session_id" text NOT NULL');
  });
});
