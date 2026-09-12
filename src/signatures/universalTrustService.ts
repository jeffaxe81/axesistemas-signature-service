import { createHash } from "node:crypto";
import type {
  SigningProvider,
  TimestampProvider,
  ValidationProvider,
} from "../providers/providerContracts.js";
import type { SignatureFormat, SignatureLevel } from "../trust/capabilities.js";
import {
  ProviderRegistry,
  type RegisteredProvider,
} from "../trust/providerRegistry.js";
import {
  fakeDevProfile,
  productionStandardProfile,
  sandboxProfile,
  type TrustProfile,
} from "../trust/trustProfile.js";
import type { Participant } from "./participant.js";
import type { UniversalSignatureStatus } from "./domain.js";

export type UniversalTrustExecutionInput = {
  tenantId: string;
  requestId: string;
  trustProfileId: "fake-dev" | "sandbox" | "production-standard";
  document: Buffer;
  level: SignatureLevel;
  format: SignatureFormat;
  participants: Participant[];
};

export type UniversalValidationResult = {
  valid: boolean;
  trustMode: "fake" | "sandbox" | "production";
  code?: string;
  evidence: Record<string, unknown>;
};

export type UniversalTrustExecutionResult = {
  requestId: string;
  tenantId: string;
  status: UniversalSignatureStatus;
  documentSha256: string;
  providerRequestIds: string[];
  validation?: UniversalValidationResult;
  validations: UniversalValidationResult[];
};

export type UniversalTrustServiceDependencies = {
  registry: ProviderRegistry;
};

export class UniversalTrustService {
  constructor(private readonly dependencies: UniversalTrustServiceDependencies) {}

  async execute(input: UniversalTrustExecutionInput): Promise<UniversalTrustExecutionResult> {
    if (input.participants.length === 0) {
      throw new Error("TRUST_POLICY_VIOLATION");
    }

    const documentSha256 = createHash("sha256").update(input.document).digest("hex");
    const profile = resolveProfile(input.trustProfileId);
    const signing = asSigningProvider(
      this.dependencies.registry.resolve("signing", profile, {
        level: input.level,
        format: input.format,
      })
    );

    const providerRequestIds: string[] = [];
    const validations: UniversalValidationResult[] = [];

    for (const participant of input.participants) {
      const signed = await signing.sign({
        requestId: input.requestId,
        participantId: participant.id,
        documentSha256,
        level: input.level,
        format: input.format,
      });
      providerRequestIds.push(signed.providerRequestId);

      if (signed.status === "pending") {
        return {
          requestId: input.requestId,
          tenantId: input.tenantId,
          status: "awaiting_participants",
          documentSha256,
          providerRequestIds,
          validations,
        };
      }

      if (!signed.signedArtifact) {
        throw new Error("PROVIDER_PROTOCOL_ERROR");
      }

      if (profile.timestampRequired) {
        const timestampProvider = asTimestampProvider(
          this.dependencies.registry.resolve("timestamp", profile, {
            level: input.level,
            format: input.format,
          })
        );
        const artifactSha256 = createHash("sha256")
          .update(signed.signedArtifact)
          .digest("hex");
        await timestampProvider.timestamp({ artifactSha256 });
      }

      const validationProvider = asValidationProvider(
        this.dependencies.registry.resolve("validation", profile, {
          level: input.level,
          format: input.format,
        })
      );
      const validation = await validationProvider.validate({
        documentSha256,
        signedArtifact: signed.signedArtifact,
      });
      validations.push(validation);

      if (!validation.valid) {
        throw new Error(validation.code ?? "SIGNATURE_INVALID");
      }
    }

    return {
      requestId: input.requestId,
      tenantId: input.tenantId,
      status: "completed",
      documentSha256,
      providerRequestIds,
      validation: validations.at(-1),
      validations,
    };
  }
}

function resolveProfile(id: UniversalTrustExecutionInput["trustProfileId"]): TrustProfile {
  switch (id) {
    case "fake-dev":
      return fakeDevProfile;
    case "sandbox":
      return sandboxProfile;
    case "production-standard":
      return productionStandardProfile;
  }
}

function asSigningProvider(provider: RegisteredProvider): SigningProvider {
  const candidate = provider as RegisteredProvider & Partial<SigningProvider>;
  if (typeof candidate.sign !== "function" || typeof candidate.cancel !== "function") {
    throw new Error("PROVIDER_PROTOCOL_ERROR");
  }
  return candidate as SigningProvider;
}

function asValidationProvider(provider: RegisteredProvider): ValidationProvider {
  const candidate = provider as RegisteredProvider & Partial<ValidationProvider>;
  if (typeof candidate.validate !== "function") {
    throw new Error("PROVIDER_PROTOCOL_ERROR");
  }
  return candidate as ValidationProvider;
}

function asTimestampProvider(provider: RegisteredProvider): TimestampProvider {
  const candidate = provider as RegisteredProvider & Partial<TimestampProvider>;
  if (typeof candidate.timestamp !== "function") {
    throw new Error("PROVIDER_PROTOCOL_ERROR");
  }
  return candidate as TimestampProvider;
}
