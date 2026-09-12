import { randomUUID } from "node:crypto";
import type { ProviderDescriptor } from "../trust/capabilities.js";
import type { IdentityAssurance } from "../identity/identityPolicy.js";
import type {
  BeginIdentityVerificationInput,
  BeginIdentityVerificationResult,
  CompleteIdentityVerificationInput,
  CompleteIdentityVerificationResult,
  IdentityProvider,
} from "./providerContracts.js";

export type FakeIdentityProviderOptions = {
  assurance: IdentityAssurance;
  fail?: boolean;
};

type FakeProviderSession = {
  challengeId: string;
  tenantId: string;
  requestId: string;
  participantId: string;
};

export class FakeIdentityProvider implements IdentityProvider {
  readonly descriptor: ProviderDescriptor = {
    id: "fake-identity",
    version: "0.1.0",
    kind: "identity",
    trustMode: "fake",
    signatureLevels: ["simple"],
    signatureFormats: ["detached"],
  };

  beginCalls = 0;
  completeCalls = 0;

  private readonly sessions = new Map<string, FakeProviderSession>();

  constructor(private readonly options: FakeIdentityProviderOptions) {}

  async beginVerification(
    input: BeginIdentityVerificationInput
  ): Promise<BeginIdentityVerificationResult> {
    this.beginCalls += 1;
    const providerSessionId = randomUUID();
    const challengeId = randomUUID();
    this.sessions.set(providerSessionId, {
      challengeId,
      tenantId: input.tenantId,
      requestId: input.requestId,
      participantId: input.participantId,
    });

    return {
      providerSessionId,
      challengeId,
      clientData: { prompt: "Enter FAKE-OK" },
      evidence: { provider: "fake-identity", outcome: "challenge-created" },
    };
  }

  async completeVerification(
    input: CompleteIdentityVerificationInput
  ): Promise<CompleteIdentityVerificationResult> {
    this.completeCalls += 1;

    if (this.options.fail) {
      throw new Error("IDENTITY_PROVIDER_UNAVAILABLE");
    }

    const session = this.sessions.get(input.providerSessionId);
    if (
      !session ||
      session.challengeId !== input.challengeId ||
      session.tenantId !== input.tenantId ||
      session.requestId !== input.requestId ||
      session.participantId !== input.participantId
    ) {
      throw new Error("PROVIDER_PROTOCOL_ERROR");
    }

    const answer = input.response.answer;
    if (answer === "FAKE-DENY") {
      return {
        verified: false,
        denied: true,
        evidence: { provider: "fake-identity", outcome: "denied" },
      };
    }

    if (answer !== "FAKE-OK") {
      return {
        verified: false,
        evidence: { provider: "fake-identity", outcome: "invalid" },
      };
    }

    return {
      verified: true,
      assurance: this.options.assurance,
      acr: "axesistemas:fake",
      amr: ["fake"],
      externalSubject: `fake:${input.participantId}`,
      evidence: { provider: "fake-identity", outcome: "verified" },
    };
  }
}
