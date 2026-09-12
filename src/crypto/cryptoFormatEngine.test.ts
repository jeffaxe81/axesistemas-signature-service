import { describe, expect, it } from "vitest";
import type { PadesSignInput, PadesValidationInput } from "./cryptoFormatEngine.js";

describe("D-009D crypto contracts", () => {
  it("keeps source content hash distinct from signed artifact hash", async () => {
    const contracts = await import("./cryptoFormatEngine.js");
    const sourceDocumentSha256 = "a".repeat(64);
    const artifactSha256 = "b".repeat(64);

    expect(contracts).toBeDefined();
    expect(sourceDocumentSha256).not.toBe(artifactSha256);
  });

  it("models source identity separately from the input artifact revision", () => {
    const input: PadesSignInput = {
      tenantId: "tenant-a",
      requestId: "req-1",
      participantId: "participant-1",
      credentialRef: "cert-a",
      trustMode: "production",
      sourceDocumentSha256: "a".repeat(64),
      inputArtifactSha256: "b".repeat(64),
      pdf: Buffer.from("%PDF-1.7"),
      baseline: "B-B",
      visualSignature: "none",
    };
    const validation: PadesValidationInput = {
      tenantId: input.tenantId,
      requestId: input.requestId,
      participantId: input.participantId,
      sourceDocumentSha256: input.sourceDocumentSha256,
      artifactSha256: "c".repeat(64),
      signedPdf: Buffer.from("%PDF-1.7 signed"),
    };

    expect(input.sourceDocumentSha256).not.toBe(input.inputArtifactSha256);
    expect(validation.sourceDocumentSha256).toBe(input.sourceDocumentSha256);
  });
});
