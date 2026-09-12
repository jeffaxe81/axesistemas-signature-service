import { createHash } from "node:crypto";
import type { ProviderDescriptor } from "../trust/capabilities.js";
import type { TimestampProvider } from "../providers/providerContracts.js";

export type FakeTimestampProviderOptions = {
  now: () => Date;
};

type FakeTimestampTokenPayload = {
  artifactSha256: string;
  issuedAt: string;
  providerId: "fake-timestamp";
  trustMode: "fake";
  integritySha256: string;
};

export class FakeTimestampProvider implements TimestampProvider {
  readonly descriptor: ProviderDescriptor = {
    id: "fake-timestamp",
    version: "1.0.0",
    kind: "timestamp",
    trustMode: "fake",
    signatureLevels: ["simple", "advanced", "qualified"],
    signatureFormats: ["detached"],
  };

  constructor(
    private readonly options: FakeTimestampProviderOptions = {
      now: () => new Date(),
    }
  ) {}

  async timestamp(input: { artifactSha256: string }): Promise<{
    token: string;
    issuedAt: string;
    trustMode: "fake";
    evidence: Record<string, unknown>;
  }> {
    const issuedAt = this.options.now().toISOString();
    const payload: FakeTimestampTokenPayload = {
      artifactSha256: input.artifactSha256,
      issuedAt,
      providerId: "fake-timestamp",
      trustMode: "fake",
      integritySha256: this.integrity(input.artifactSha256, issuedAt),
    };

    return {
      token: Buffer.from(JSON.stringify(payload), "utf8").toString("base64url"),
      issuedAt,
      trustMode: "fake",
      evidence: {
        providerId: "fake-timestamp",
        artifactSha256: input.artifactSha256,
      },
    };
  }

  validateToken(token: string): {
    valid: boolean;
    trustMode: "fake";
    code?: "TIMESTAMP_INVALID";
    evidence: Record<string, unknown>;
  } {
    try {
      const parsed = JSON.parse(
        Buffer.from(token, "base64url").toString("utf8")
      ) as FakeTimestampTokenPayload;
      const expected = this.integrity(parsed.artifactSha256, parsed.issuedAt);
      const valid =
        parsed.providerId === "fake-timestamp" &&
        parsed.trustMode === "fake" &&
        parsed.integritySha256 === expected;

      return {
        valid,
        trustMode: "fake",
        ...(valid ? {} : { code: "TIMESTAMP_INVALID" as const }),
        evidence: {
          artifactSha256: parsed.artifactSha256,
          issuedAt: parsed.issuedAt,
        },
      };
    } catch {
      return {
        valid: false,
        trustMode: "fake",
        code: "TIMESTAMP_INVALID",
        evidence: { reason: "token-deserialization" },
      };
    }
  }

  private integrity(artifactSha256: string, issuedAt: string): string {
    return createHash("sha256")
      .update(`${artifactSha256}|${issuedAt}|fake-timestamp|fake`)
      .digest("hex");
  }
}
