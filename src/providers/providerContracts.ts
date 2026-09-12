import type {
  ProviderDescriptor,
  SignatureFormat,
  SignatureLevel,
  TrustMode,
} from "../trust/capabilities.js";
import type {
  AuthenticationMethod,
  IdentityAssurance,
} from "../identity/identityPolicy.js";

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

export type BeginIdentityVerificationInput = {
  tenantId: string;
  requestId: string;
  participantId: string;
  method: AuthenticationMethod;
};

export type BeginIdentityVerificationResult = {
  providerSessionId: string;
  challengeId: string;
  clientData: Record<string, unknown>;
  evidence: Record<string, unknown>;
};

export type CompleteIdentityVerificationInput = {
  tenantId: string;
  requestId: string;
  participantId: string;
  providerSessionId: string;
  challengeId: string;
  response: Record<string, unknown>;
};

export type CompleteIdentityVerificationResult = {
  verified: boolean;
  denied?: boolean;
  assurance?: IdentityAssurance;
  acr?: string;
  amr?: string[];
  externalSubject?: string;
  evidence: Record<string, unknown>;
};

export interface IdentityProvider {
  readonly descriptor: ProviderDescriptor;
  beginVerification(
    input: BeginIdentityVerificationInput
  ): Promise<BeginIdentityVerificationResult>;
  completeVerification(
    input: CompleteIdentityVerificationInput
  ): Promise<CompleteIdentityVerificationResult>;
}

export type RecordConsentInput = {
  tenantId: string;
  requestId: string;
  participantId: string;
  identityEvidenceId: string;
  documentSha256: string;
  statementHash: string;
  decision: "accepted" | "declined";
};

export interface ConsentProvider {
  readonly descriptor: ProviderDescriptor;
  record(input: RecordConsentInput): Promise<{
    recorded: boolean;
    evidence: Record<string, unknown>;
  }>;
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
