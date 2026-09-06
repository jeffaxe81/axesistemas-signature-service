import { describe, expect, it } from "vitest";
import { sha256 } from "../documents/documentHash.js";
import { validateEvidence } from "./evidenceValidator.js";

describe("validateEvidence", () => {
  it("accepts the signed document only when the stored signed hash matches", () => {
    const signedDocument = Buffer.from("signed");
    const expectedSha256 = sha256(signedDocument);
    expect(validateEvidence({ signedDocument, expectedSha256 })).toEqual({ valid: true });
  });

  it("rejects tampered signed bytes", () => {
    expect(
      validateEvidence({
        signedDocument: Buffer.from("tampered"),
        expectedSha256: sha256(Buffer.from("signed")),
      })
    ).toEqual({ valid: false, reason: "SIGNED_DOCUMENT_HASH_MISMATCH" });
  });
});
