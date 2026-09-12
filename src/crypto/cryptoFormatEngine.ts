import type { TrustMode } from "../trust/capabilities.js";

export type PadesBaseline = "B-B";
export type VisualSignatureMode = "none" | "standard";

export type PadesSignInput = {
  tenantId: string;
  requestId: string;
  participantId: string;
  credentialRef: string;
  trustMode: TrustMode;
  sourceDocumentSha256: string;
  inputArtifactSha256: string;
  pdf: Buffer;
  baseline: PadesBaseline;
  visualSignature: VisualSignatureMode;
};

export type PadesSignResult = {
  operationId: string;
  signedPdf: Buffer;
  artifactSha256: string;
  trustMode: TrustMode;
  engine: "DSS";
  engineVersion: string;
  certificate: {
    fingerprintSha256: string;
    serial: string;
    subject?: string;
    issuer?: string;
    notBefore: string;
    notAfter: string;
    signatureAlgorithm: string;
  };
};

export type PadesValidationInput = {
  tenantId: string;
  requestId: string;
  participantId: string;
  sourceDocumentSha256: string;
  artifactSha256: string;
  signedPdf: Buffer;
};

export type PadesValidationResult = {
  valid: boolean;
  code?: string;
  trustMode: TrustMode;
  format: "pades";
  baseline: "B-B";
  evidence: Record<string, unknown>;
};

export interface CryptoFormatEngine {
  signPades(input: PadesSignInput): Promise<PadesSignResult>;
  validatePades(input: PadesValidationInput): Promise<PadesValidationResult>;
}
