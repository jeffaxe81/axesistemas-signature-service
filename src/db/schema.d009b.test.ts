import { expect, it } from "vitest";
import {
  documentArtifacts,
  providerBindings,
  signatureArtifacts,
  signatureParticipants,
  trustProfiles,
  validationResults,
} from "./schema.js";

it("expõe as tabelas aditivas D-009B com tenant explícito", () => {
  for (const table of [
    signatureParticipants,
    providerBindings,
    documentArtifacts,
    signatureArtifacts,
    validationResults,
    trustProfiles,
  ]) {
    expect(table.tenantId.name).toBe("tenant_id");
  }
});
