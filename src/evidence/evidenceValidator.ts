import { sha256 } from "../documents/documentHash.js";

export type EvidenceValidationInput = {
  signedDocument: Buffer;
  expectedSha256: string;
};

export type EvidenceValidationResult =
  | { valid: true }
  | { valid: false; reason: "SIGNED_DOCUMENT_HASH_MISMATCH" };

export function validateEvidence(
  input: EvidenceValidationInput
): EvidenceValidationResult {
  const actualSha256 = sha256(input.signedDocument);
  if (actualSha256 !== input.expectedSha256.toLowerCase()) {
    return { valid: false, reason: "SIGNED_DOCUMENT_HASH_MISMATCH" };
  }
  return { valid: true };
}
