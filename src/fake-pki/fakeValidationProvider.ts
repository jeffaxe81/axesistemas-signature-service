import { createHash, createPublicKey, verify as cryptoVerify } from "node:crypto";
import type { ProviderDescriptor } from "../trust/capabilities.js";
import type { ValidationProvider } from "../providers/providerContracts.js";
import type { FakeCertificateAuthority } from "./fakeCertificateAuthority.js";
import {
  deserializeFakeSignedArtifact,
  type FakeSignedArtifact,
} from "./fakeSigningProvider.js";

export type FakeValidationResult = {
  valid: boolean;
  trustMode: "fake";
  code?:
    | "CERTIFICATE_EXPIRED"
    | "CERTIFICATE_REVOKED"
    | "CERTIFICATE_UNTRUSTED"
    | "SIGNATURE_INVALID"
    | "DOCUMENT_HASH_MISMATCH";
  evidence: Record<string, unknown>;
};

export class FakeValidationProvider implements ValidationProvider {
  readonly descriptor: ProviderDescriptor = {
    id: "fake-pki-validation",
    version: "1.0.0",
    kind: "validation",
    trustMode: "fake",
    signatureLevels: ["simple", "advanced", "qualified"],
    signatureFormats: ["detached"],
  };

  constructor(private readonly authority: FakeCertificateAuthority) {}

  async validateFakeArtifact(
    artifact: FakeSignedArtifact
  ): Promise<FakeValidationResult> {
    const certificateStatus = this.authority.status(artifact.certificateSerial);
    if (certificateStatus === "unknown") {
      return this.failure("CERTIFICATE_UNTRUSTED", artifact);
    }
    if (certificateStatus === "expired") {
      return this.failure("CERTIFICATE_EXPIRED", artifact);
    }
    if (certificateStatus === "revoked") {
      return this.failure("CERTIFICATE_REVOKED", artifact);
    }

    const payloadSha256 = createHash("sha256").update(artifact.payload).digest("hex");
    if (payloadSha256 !== artifact.payloadSha256) {
      return this.failure("DOCUMENT_HASH_MISMATCH", artifact);
    }

    const certificate = this.authority.getCertificate(artifact.certificateSerial);
    if (!certificate) {
      return this.failure("CERTIFICATE_UNTRUSTED", artifact);
    }

    const verified = cryptoVerify(
      null,
      artifact.payload,
      createPublicKey(certificate.publicKeyPem),
      Buffer.from(artifact.signatureBase64, "base64")
    );
    if (!verified) {
      return this.failure("SIGNATURE_INVALID", artifact);
    }

    return {
      valid: true,
      trustMode: "fake",
      evidence: {
        certificateSerial: artifact.certificateSerial,
        certificateStatus,
        payloadSha256,
      },
    };
  }

  async validate(input: {
    documentSha256: string;
    signedArtifact: Buffer;
  }): Promise<FakeValidationResult> {
    let artifact: FakeSignedArtifact;
    try {
      artifact = deserializeFakeSignedArtifact(input.signedArtifact);
    } catch {
      return {
        valid: false,
        trustMode: "fake",
        code: "SIGNATURE_INVALID",
        evidence: { reason: "artifact-deserialization" },
      };
    }

    const validation = await this.validateFakeArtifact(artifact);
    if (!validation.valid) return validation;

    if (artifact.payload.toString("utf8") !== input.documentSha256) {
      return this.failure("DOCUMENT_HASH_MISMATCH", artifact);
    }

    return validation;
  }

  private failure(
    code: NonNullable<FakeValidationResult["code"]>,
    artifact: FakeSignedArtifact
  ): FakeValidationResult {
    return {
      valid: false,
      trustMode: "fake",
      code,
      evidence: {
        certificateSerial: artifact.certificateSerial,
      },
    };
  }
}
