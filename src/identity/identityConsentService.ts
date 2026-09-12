import { createHash } from "node:crypto";
import {
  createConsentRecord,
  type ConsentDecision,
  type ConsentRecord,
} from "../consent/consentRecord.js";
import type {
  ConsentProvider,
  IdentityProvider,
} from "../providers/providerContracts.js";
import type { Participant } from "../signatures/participant.js";
import type { RegisteredProvider } from "../trust/providerRegistry.js";
import { ProviderRegistry } from "../trust/providerRegistry.js";
import type { TrustProfile } from "../trust/trustProfile.js";
import {
  createIdentityEvidence,
  type IdentityEvidence,
} from "./identityEvidence.js";
import {
  assertAssuranceSatisfied,
  assertIdentityProviderAllowed,
  type AuthenticationMethod,
  type IdentityPolicy,
} from "./identityPolicy.js";
import type { IdentityConsentRepository } from "./identityConsentRepository.js";
import {
  assertSessionUsable,
  createIdentitySession,
  incrementIdentityAttempt,
  transitionIdentitySession,
} from "./identitySession.js";
import {
  evaluateReadiness,
  type ParticipantReadiness,
} from "./readiness.js";

export interface IdentityAuditSink {
  append(input: {
    tenantId: string;
    requestId: string;
    participantId: string;
    type: string;
    payload: Record<string, unknown>;
  }): Promise<void>;
}

export type IdentityConsentServiceDependencies = {
  registry: ProviderRegistry;
  repository: IdentityConsentRepository;
  audit: IdentityAuditSink;
  now: () => Date;
  randomId: () => string;
};

export class IdentityConsentService {
  constructor(private readonly dependencies: IdentityConsentServiceDependencies) {}

  async startIdentityVerification(input: {
    tenantId: string;
    requestId: string;
    participant: Participant;
    trustProfile: TrustProfile;
    identityPolicy: IdentityPolicy;
    method: AuthenticationMethod;
  }): Promise<{
    sessionId: string;
    challengeId: string;
    clientData: Record<string, unknown>;
  }> {
    const provider = asIdentityProvider(
      this.dependencies.registry.resolve("identity", input.trustProfile, {
        level: "simple",
        format: "detached",
      })
    );
    assertIdentityProviderAllowed(input.identityPolicy, provider.descriptor, input.method);

    const started = await provider.beginVerification({
      tenantId: input.tenantId,
      requestId: input.requestId,
      participantId: input.participant.id,
      method: input.method,
    });
    const now = this.dependencies.now();
    const sessionId = this.dependencies.randomId();
    const challengeDigest = createHash("sha256")
      .update(
        JSON.stringify({
          challengeId: started.challengeId,
          clientData: started.clientData,
        }),
        "utf8"
      )
      .digest("hex");

    const session = createIdentitySession({
      tenantId: input.tenantId,
      id: sessionId,
      requestId: input.requestId,
      participantId: input.participant.id,
      providerId: provider.descriptor.id,
      providerSessionId: started.providerSessionId,
      method: input.method,
      challengeId: started.challengeId,
      challengeDigest,
      now,
      ttlSeconds: input.identityPolicy.challengeTtlSeconds,
      maxAttempts: input.identityPolicy.maxChallengeAttempts,
    });
    await this.dependencies.repository.saveSession(session);
    await this.dependencies.audit.append({
      tenantId: input.tenantId,
      requestId: input.requestId,
      participantId: input.participant.id,
      type: "identity.challenge.created",
      payload: {
        sessionId,
        providerId: provider.descriptor.id,
        method: input.method,
      },
    });

    return {
      sessionId,
      challengeId: started.challengeId,
      clientData: started.clientData,
    };
  }

  async completeIdentityVerification(input: {
    tenantId: string;
    requestId: string;
    participant: Participant;
    trustProfile: TrustProfile;
    identityPolicy: IdentityPolicy;
    sessionId: string;
    response: Record<string, unknown>;
  }): Promise<IdentityEvidence> {
    const session = await this.dependencies.repository.getSession(
      input.tenantId,
      input.sessionId
    );
    if (!session) {
      throw new Error("IDENTITY_CHALLENGE_INVALID");
    }
    if (
      session.requestId !== input.requestId ||
      session.participantId !== input.participant.id
    ) {
      throw new Error("IDENTITY_CHALLENGE_INVALID");
    }

    const now = this.dependencies.now();
    try {
      assertSessionUsable(session, now);
    } catch (error) {
      if (
        error instanceof Error &&
        error.message === "IDENTITY_CHALLENGE_EXPIRED" &&
        session.status === "challenge_pending"
      ) {
        await this.dependencies.repository.saveSession(
          transitionIdentitySession(session, "expired", now)
        );
        await this.dependencies.audit.append({
          tenantId: input.tenantId,
          requestId: input.requestId,
          participantId: input.participant.id,
          type: "identity.expired",
          payload: { sessionId: session.id, providerId: session.providerId },
        });
      }
      throw error;
    }

    const provider = asIdentityProvider(
      this.dependencies.registry.resolve("identity", input.trustProfile, {
        level: "simple",
        format: "detached",
      })
    );
    assertIdentityProviderAllowed(input.identityPolicy, provider.descriptor, session.method);
    if (provider.descriptor.id !== session.providerId) {
      throw new Error("PROVIDER_PROTOCOL_ERROR");
    }

    const result = await provider.completeVerification({
      tenantId: input.tenantId,
      requestId: input.requestId,
      participantId: input.participant.id,
      providerSessionId: session.providerSessionId,
      challengeId: session.challengeId,
      response: input.response,
    });

    if (!result.verified) {
      if (result.denied) {
        await this.dependencies.repository.saveSession(
          transitionIdentitySession(session, "denied", now)
        );
        await this.dependencies.audit.append({
          tenantId: input.tenantId,
          requestId: input.requestId,
          participantId: input.participant.id,
          type: "identity.denied",
          payload: { sessionId: session.id, providerId: session.providerId },
        });
      } else {
        let attempted = incrementIdentityAttempt(session, now);
        if (attempted.attemptCount >= attempted.maxAttempts) {
          attempted = transitionIdentitySession(attempted, "failed", now);
        }
        await this.dependencies.repository.saveSession(attempted);
        await this.dependencies.audit.append({
          tenantId: input.tenantId,
          requestId: input.requestId,
          participantId: input.participant.id,
          type: "identity.challenge.failed",
          payload: {
            sessionId: session.id,
            providerId: session.providerId,
            attemptCount: attempted.attemptCount,
          },
        });
      }
      throw new Error("IDENTITY_CHALLENGE_INVALID");
    }

    if (!result.assurance) {
      await this.dependencies.repository.saveSession(
        transitionIdentitySession(session, "failed", now)
      );
      throw new Error("PROVIDER_PROTOCOL_ERROR");
    }

    try {
      assertAssuranceSatisfied(input.identityPolicy, result.assurance);
    } catch (error) {
      await this.dependencies.repository.saveSession(
        transitionIdentitySession(session, "failed", now)
      );
      throw error;
    }

    const evidence = createIdentityEvidence({
      tenantId: input.tenantId,
      id: this.dependencies.randomId(),
      requestId: input.requestId,
      participantId: input.participant.id,
      identitySessionId: session.id,
      providerId: provider.descriptor.id,
      method: session.method,
      assurance: result.assurance,
      ...(result.acr ? { acr: result.acr } : {}),
      ...(result.amr ? { amr: result.amr } : {}),
      ...(result.externalSubject
        ? {
            externalSubjectHash: createHash("sha256")
              .update(result.externalSubject, "utf8")
              .digest("hex"),
          }
        : {}),
      verifiedAt: now,
      providerEvidence: result.evidence,
      createdAt: now,
    });

    await this.dependencies.repository.saveIdentityEvidence(evidence);
    await this.dependencies.repository.saveSession(
      transitionIdentitySession(session, "verified", now)
    );
    await this.dependencies.audit.append({
      tenantId: input.tenantId,
      requestId: input.requestId,
      participantId: input.participant.id,
      type: "identity.verified",
      payload: {
        identityEvidenceId: evidence.id,
        providerId: evidence.providerId,
        method: evidence.method,
        assurance: evidence.assurance,
      },
    });

    return evidence;
  }

  async recordConsent(input: {
    tenantId: string;
    requestId: string;
    participant: Participant;
    trustProfile: TrustProfile;
    identityPolicy: IdentityPolicy;
    documentSha256: string;
    statement: string;
    decision: ConsentDecision;
  }): Promise<ConsentRecord> {
    const evidence = await this.dependencies.repository.getLatestIdentityEvidence(
      input.tenantId,
      input.requestId,
      input.participant.id
    );
    if (!evidence) {
      throw new Error("IDENTITY_REQUIRED");
    }
    if (evidence.tenantId !== input.tenantId) {
      throw new Error("CROSS_TENANT_ACCESS_DENIED");
    }
    if (
      evidence.requestId !== input.requestId ||
      evidence.participantId !== input.participant.id
    ) {
      throw new Error("CONSENT_IDENTITY_MISMATCH");
    }

    const normalizedStatement = input.statement.trim().replace(/\r\n/g, "\n");
    const statementHash = createHash("sha256")
      .update(normalizedStatement, "utf8")
      .digest("hex");

    const preConsentReadiness = evaluateReadiness({
      tenantId: input.tenantId,
      requestId: input.requestId,
      policy: input.identityPolicy,
      participant: input.participant,
      documentSha256: input.documentSha256,
      statementHash,
      identityEvidence: evidence,
      consent: undefined,
      now: this.dependencies.now(),
    });
    if (preConsentReadiness === "awaiting_identity") {
      throw new Error("IDENTITY_REQUIRED");
    }

    const provider = asConsentProvider(
      this.dependencies.registry.resolve("consent", input.trustProfile, {
        level: "simple",
        format: "detached",
      })
    );
    assertIdentityPolicyProviderAllowed(
      input.identityPolicy,
      provider.descriptor.id,
      provider.descriptor.kind,
      "consent"
    );

    const result = await provider.record({
      tenantId: input.tenantId,
      requestId: input.requestId,
      participantId: input.participant.id,
      identityEvidenceId: evidence.id,
      documentSha256: input.documentSha256,
      statementHash,
      decision: input.decision,
    });
    if (!result.recorded) {
      throw new Error("PROVIDER_PROTOCOL_ERROR");
    }

    const now = this.dependencies.now();
    const consent = createConsentRecord({
      tenantId: input.tenantId,
      id: this.dependencies.randomId(),
      requestId: input.requestId,
      participantId: input.participant.id,
      identityEvidenceId: evidence.id,
      documentSha256: input.documentSha256,
      statementHash,
      decision: input.decision,
      providerId: provider.descriptor.id,
      providerEvidence: result.evidence,
      now,
    });
    await this.dependencies.repository.saveConsent(consent);
    await this.dependencies.audit.append({
      tenantId: input.tenantId,
      requestId: input.requestId,
      participantId: input.participant.id,
      type: input.decision === "accepted" ? "consent.accepted" : "consent.declined",
      payload: {
        consentId: consent.id,
        identityEvidenceId: evidence.id,
        providerId: provider.descriptor.id,
        documentSha256: input.documentSha256,
        statementHash,
      },
    });

    return consent;
  }

  async evaluateParticipantReadiness(input: {
    tenantId: string;
    requestId: string;
    participant: Participant;
    identityPolicy: IdentityPolicy;
    documentSha256: string;
    statementHash: string;
  }): Promise<ParticipantReadiness> {
    const identityEvidence = await this.dependencies.repository.getLatestIdentityEvidence(
      input.tenantId,
      input.requestId,
      input.participant.id
    );
    const consent = await this.dependencies.repository.getLatestConsent(
      input.tenantId,
      input.requestId,
      input.participant.id
    );

    return evaluateReadiness({
      tenantId: input.tenantId,
      requestId: input.requestId,
      policy: input.identityPolicy,
      participant: input.participant,
      documentSha256: input.documentSha256,
      statementHash: input.statementHash,
      identityEvidence,
      consent,
      now: this.dependencies.now(),
    });
  }
}

function asIdentityProvider(provider: RegisteredProvider): IdentityProvider {
  const candidate = provider as RegisteredProvider & Partial<IdentityProvider>;
  if (
    typeof candidate.beginVerification !== "function" ||
    typeof candidate.completeVerification !== "function"
  ) {
    throw new Error("PROVIDER_PROTOCOL_ERROR");
  }
  return candidate as IdentityProvider;
}

function asConsentProvider(provider: RegisteredProvider): ConsentProvider {
  const candidate = provider as RegisteredProvider & Partial<ConsentProvider>;
  if (typeof candidate.record !== "function") {
    throw new Error("PROVIDER_PROTOCOL_ERROR");
  }
  return candidate as ConsentProvider;
}

function assertIdentityPolicyProviderAllowed(
  policy: IdentityPolicy,
  providerId: string,
  actualKind: string,
  expectedKind: "consent"
): void {
  if (actualKind !== expectedKind) {
    throw new Error("TRUST_POLICY_VIOLATION");
  }
  if (policy.allowedProviderIds !== "*" && !policy.allowedProviderIds.includes(providerId)) {
    throw new Error("TRUST_POLICY_VIOLATION");
  }
}
