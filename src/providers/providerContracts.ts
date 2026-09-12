import type {
  ProviderDescriptor,
  SignatureFormat,
  SignatureLevel,
  TrustMode,
} from "../trust/capabilities.js";

export type SigningInput = {
  requestId: string;
  participantId: string;
  documentSha256: string;
  level: SignatureLevel;
  format: SignatureFormat;
};

export type SigningResult = {
  providerRequestId: string;
  status: "pending" | "signed";
  signedArtifact?: Buffer;
  evidence?: Record<string, unknown>;
};

export interface SigningProvider {
  readonly descriptor: ProviderDescriptor;
  sign(input: SigningInput): Promise<SigningResult>;
  cancel(providerRequestId: string): Promise<void>;
}

export interface IdentityProvider {
  readonly descriptor: ProviderDescriptor;
  verify(input: {
    requestId: string;
    participantId: string;
    method: string;
  }): Promise<{ verified: boolean; evidence: Record<string, unknown> }>;
}

export interface ConsentProvider {
  readonly descriptor: ProviderDescriptor;
  record(input: {
    requestId: string;
    participantId: string;
    statementHash: string;
  }): Promise<{ recorded: boolean; evidence: Record<string, unknown> }>;
}

export interface ValidationProvider {
  readonly descriptor: ProviderDescriptor;
  validate(input: {
    documentSha256: string;
    signedArtifact: Buffer;
  }): Promise<{
    valid: boolean;
    trustMode: TrustMode;
    code?: string;
    evidence: Record<string, unknown>;
  }>;
}

export interface TimestampProvider {
  readonly descriptor: ProviderDescriptor;
  timestamp(input: { artifactSha256: string }): Promise<{
    token: string;
    issuedAt: string;
    trustMode: TrustMode;
    evidence: Record<string, unknown>;
  }>;
}
