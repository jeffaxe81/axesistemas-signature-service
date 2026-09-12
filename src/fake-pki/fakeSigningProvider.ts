import { createHash, sign as cryptoSign } from "node:crypto";
import type { ProviderDescriptor } from "../trust/capabilities.js";
import type {
  SigningInput,
  SigningProvider,
  SigningResult,
} from "../providers/providerContracts.js";
import type { FakeCertificateAuthority } from "./fakeCertificateAuthority.js";

export type FakeSignedArtifact = {
  payload: Buffer;
  payloadSha256: string;
  certificateSerial: string;
  signatureBase64: string;
  trustMode: "fake";
};

type SerializedFakeSignedArtifact = {
  payloadBase64: string;
  payloadSha256: string;
  certificateSerial: string;
  signatureBase64: string;
  trustMode: "fake";
};

export function serializeFakeSignedArtifact(artifact: FakeSignedArtifact): Buffer {
  const serialized: SerializedFakeSignedArtifact = {
    payloadBase64: artifact.payload.toString("base64"),
    payloadSha256: artifact.payloadSha256,
    certificateSerial: artifact.certificateSerial,
    signatureBase64: artifact.signatureBase64,
    trustMode: "fake",
  };
  return Buffer.from(JSON.stringify(serialized), "utf8");
}

export function deserializeFakeSignedArtifact(bytes: Buffer): FakeSignedArtifact {
  const parsed = JSON.parse(bytes.toString("utf8")) as SerializedFakeSignedArtifact;
  if (
    parsed.trustMode !== "fake" ||
    typeof parsed.payloadBase64 !== "string" ||
    typeof parsed.payloadSha256 !== "string" ||
    typeof parsed.certificateSerial !== "string" ||
    typeof parsed.signatureBase64 !== "string"
  ) {
    throw new Error("SIGNATURE_INVALID");
  }

  return {
    payload: Buffer.from(parsed.payloadBase64, "base64"),
    payloadSha256: parsed.payloadSha256,
    certificateSerial: parsed.certificateSerial,
    signatureBase64: parsed.signatureBase64,
    trustMode: "fake",
  };
}

export class FakeSigningProvider implements SigningProvider {
  readonly descriptor: ProviderDescriptor = {
    id: "fake-pki-signing",
    version: "1.0.0",
    kind: "signing",
    trustMode: "fake",
    signatureLevels: ["simple", "advanced", "qualified"],
    signatureFormats: ["detached"],
  };

  signCalls = 0;

  constructor(
    private readonly authority: FakeCertificateAuthority,
    private readonly certificateSerial: string
  ) {}

  async signBytes(bytes: Buffer): Promise<FakeSignedArtifact> {
    const privateKey = this.authority.getPrivateKey(this.certificateSerial);
    if (!privateKey) {
      throw new Error("CERTIFICATE_UNTRUSTED");
    }

    return {
      payload: Buffer.from(bytes),
      payloadSha256: createHash("sha256").update(bytes).digest("hex"),
      certificateSerial: this.certificateSerial,
      signatureBase64: cryptoSign(null, bytes, privateKey).toString("base64"),
      trustMode: "fake",
    };
  }

  async sign(input: SigningInput): Promise<SigningResult> {
    this.signCalls += 1;
    const artifact = await this.signBytes(Buffer.from(input.documentSha256, "utf8"));
    return {
      providerRequestId: `fake-pki:${input.requestId}`,
      status: "signed",
      signedArtifact: serializeFakeSignedArtifact(artifact),
      evidence: {
        trustMode: "fake",
        certificateSerial: this.certificateSerial,
        participantId: input.participantId,
      },
    };
  }

  async cancel(_providerRequestId: string): Promise<void> {
    return undefined;
  }
}
