import { createHash } from "node:crypto";
import type { FastifyInstance, FastifyRequest } from "fastify";
import { z } from "zod";
import type { IdentityConsentService } from "../identity/identityConsentService.js";
import type {
  AuthenticationMethod,
  IdentityPolicy,
} from "../identity/identityPolicy.js";
import type { ChallengeRateLimiter } from "../security/challengeRateLimiter.js";
import {
  resolveTenantContext,
  type TenantContext,
} from "../security/tenantContext.js";
import type { Participant } from "../signatures/participant.js";
import type { TrustProfile } from "../trust/trustProfile.js";
import type { ResolveAuthIdentity } from "./signatureRoutes.js";

export type IdentityConsentRouteOptions = {
  service: IdentityConsentService;
  resolveAuthIdentity: ResolveAuthIdentity;
  resolveParticipant(input: {
    tenantId: string;
    requestId: string;
    participantId: string;
  }): Promise<Participant | undefined>;
  resolveTrustProfile(input: {
    tenantId: string;
    requestId: string;
  }): Promise<TrustProfile | undefined>;
  resolveIdentityPolicy(input: {
    tenantId: string;
    requestId: string;
    participantId: string;
  }): Promise<IdentityPolicy | undefined>;
  resolveDocumentSha256(input: {
    tenantId: string;
    requestId: string;
  }): Promise<string | undefined>;
  resolveConsentStatement(input: {
    tenantId: string;
    requestId: string;
    participantId: string;
  }): Promise<string | undefined>;
  rateLimiter: ChallengeRateLimiter;
  now: () => Date;
};

const authenticationMethods = [
  "fake",
  "email_otp",
  "sms_otp",
  "totp",
  "oidc",
  "webauthn",
  "biometric",
  "govbr",
] as const satisfies readonly AuthenticationMethod[];

const baseParamsSchema = z
  .object({
    requestId: z.string().trim().min(1).max(200),
    participantId: z.string().trim().min(1).max(200),
  })
  .strict();

const completeParamsSchema = baseParamsSchema
  .extend({ sessionId: z.string().trim().min(1).max(200) })
  .strict();

const startSchema = z
  .object({ method: z.enum(authenticationMethods) })
  .strict();

const completeSchema = z
  .object({ response: z.record(z.string(), z.unknown()) })
  .strict();

const consentSchema = z
  .object({
    statement: z.string().min(1).max(20_000),
    decision: z.enum(["accepted", "declined"]),
  })
  .strict();

const statusByError: Record<string, number> = {
  IDENTITY_REQUIRED: 409,
  CONSENT_REQUIRED: 409,
  IDENTITY_CHALLENGE_EXPIRED: 410,
  IDENTITY_CHALLENGE_INVALID: 400,
  IDENTITY_REPLAY_DETECTED: 409,
  IDENTITY_ASSURANCE_INSUFFICIENT: 403,
  IDENTITY_PROVIDER_UNAVAILABLE: 503,
  CONSENT_IDENTITY_MISMATCH: 409,
  CONSENT_DOCUMENT_MISMATCH: 409,
  CONSENT_ALREADY_FINALIZED: 409,
  CROSS_TENANT_ACCESS_DENIED: 404,
  TRUST_POLICY_VIOLATION: 403,
  PROVIDER_PROTOCOL_ERROR: 502,
};

function authenticatedContext(
  request: FastifyRequest,
  resolveAuthIdentity: ResolveAuthIdentity
): { ok: true; context: TenantContext } | { ok: false; statusCode: 401 | 403 } {
  const identity = resolveAuthIdentity(request.headers.authorization);
  if (!identity) return { ok: false, statusCode: 401 };
  try {
    return { ok: true, context: resolveTenantContext(identity) };
  } catch {
    return { ok: false, statusCode: 403 };
  }
}

async function resolveContext(
  options: IdentityConsentRouteOptions,
  tenantId: string,
  requestId: string,
  participantId: string
): Promise<
  | {
      participant: Participant;
      trustProfile: TrustProfile;
      identityPolicy: IdentityPolicy;
      documentSha256: string;
      consentStatement: string;
    }
  | undefined
> {
  const [participant, trustProfile, identityPolicy, documentSha256, consentStatement] =
    await Promise.all([
      options.resolveParticipant({ tenantId, requestId, participantId }),
      options.resolveTrustProfile({ tenantId, requestId }),
      options.resolveIdentityPolicy({ tenantId, requestId, participantId }),
      options.resolveDocumentSha256({ tenantId, requestId }),
      options.resolveConsentStatement({ tenantId, requestId, participantId }),
    ]);

  if (!participant || !trustProfile || !identityPolicy || !documentSha256 || !consentStatement) {
    return undefined;
  }

  return { participant, trustProfile, identityPolicy, documentSha256, consentStatement };
}

function normalizedStatement(value: string): string {
  return value.trim().replace(/\r\n/g, "\n");
}

function sha256(value: string): string {
  return createHash("sha256").update(value, "utf8").digest("hex");
}

function sendDomainError(reply: { code(statusCode: number): { send(payload: unknown): unknown } }, error: unknown) {
  if (!(error instanceof Error)) {
    return reply.code(500).send({ error: "IDENTITY_CONSENT_INTERNAL_ERROR" });
  }
  const statusCode = statusByError[error.message];
  if (!statusCode) {
    return reply.code(500).send({ error: "IDENTITY_CONSENT_INTERNAL_ERROR" });
  }
  return reply.code(statusCode).send({ error: error.message });
}

export function registerIdentityConsentRoutes(
  app: FastifyInstance,
  options: IdentityConsentRouteOptions
): void {
  app.post(
    "/v1/signature-requests/:requestId/participants/:participantId/identity-sessions",
    async (request, reply) => {
      const auth = authenticatedContext(request, options.resolveAuthIdentity);
      if (!auth.ok) {
        return reply.code(auth.statusCode).send({ error: "UNAUTHORIZED_SIGNATURE_CONTEXT" });
      }
      const params = baseParamsSchema.safeParse(request.params);
      const body = startSchema.safeParse(request.body);
      if (!params.success || !body.success) {
        return reply.code(400).send({ error: "INVALID_IDENTITY_REQUEST" });
      }

      const context = await resolveContext(
        options,
        auth.context.tenantId,
        params.data.requestId,
        params.data.participantId
      );
      if (!context) {
        return reply.code(404).send({ error: "PARTICIPANT_NOT_FOUND" });
      }

      const limited = options.rateLimiter.consume(
        `${auth.context.tenantId}:${params.data.requestId}:${params.data.participantId}:identity-start`,
        options.now()
      );
      if (!limited.allowed) {
        return reply
          .code(429)
          .send({ error: "RATE_LIMITED", retryAfterSeconds: limited.retryAfterSeconds });
      }

      try {
        const result = await options.service.startIdentityVerification({
          tenantId: auth.context.tenantId,
          requestId: params.data.requestId,
          participant: context.participant,
          trustProfile: context.trustProfile,
          identityPolicy: context.identityPolicy,
          method: body.data.method,
        });
        return reply.code(201).send(result);
      } catch (error) {
        return sendDomainError(reply, error);
      }
    }
  );

  app.post(
    "/v1/signature-requests/:requestId/participants/:participantId/identity-sessions/:sessionId/complete",
    async (request, reply) => {
      const auth = authenticatedContext(request, options.resolveAuthIdentity);
      if (!auth.ok) {
        return reply.code(auth.statusCode).send({ error: "UNAUTHORIZED_SIGNATURE_CONTEXT" });
      }
      const params = completeParamsSchema.safeParse(request.params);
      const body = completeSchema.safeParse(request.body);
      if (!params.success || !body.success) {
        return reply.code(400).send({ error: "INVALID_IDENTITY_REQUEST" });
      }

      const context = await resolveContext(
        options,
        auth.context.tenantId,
        params.data.requestId,
        params.data.participantId
      );
      if (!context) {
        return reply.code(404).send({ error: "PARTICIPANT_NOT_FOUND" });
      }

      const limited = options.rateLimiter.consume(
        `${auth.context.tenantId}:${params.data.requestId}:${params.data.participantId}:identity-complete`,
        options.now()
      );
      if (!limited.allowed) {
        return reply
          .code(429)
          .send({ error: "RATE_LIMITED", retryAfterSeconds: limited.retryAfterSeconds });
      }

      try {
        const evidence = await options.service.completeIdentityVerification({
          tenantId: auth.context.tenantId,
          requestId: params.data.requestId,
          participant: context.participant,
          trustProfile: context.trustProfile,
          identityPolicy: context.identityPolicy,
          sessionId: params.data.sessionId,
          response: body.data.response,
        });
        return reply.send({
          status: "authenticated",
          identityEvidenceId: evidence.id,
          assurance: evidence.assurance,
          method: evidence.method,
          verifiedAt: evidence.verifiedAt.toISOString(),
        });
      } catch (error) {
        return sendDomainError(reply, error);
      }
    }
  );

  app.post(
    "/v1/signature-requests/:requestId/participants/:participantId/consents",
    async (request, reply) => {
      const auth = authenticatedContext(request, options.resolveAuthIdentity);
      if (!auth.ok) {
        return reply.code(auth.statusCode).send({ error: "UNAUTHORIZED_SIGNATURE_CONTEXT" });
      }
      const params = baseParamsSchema.safeParse(request.params);
      const body = consentSchema.safeParse(request.body);
      if (!params.success || !body.success) {
        return reply.code(400).send({ error: "INVALID_CONSENT_REQUEST" });
      }

      const context = await resolveContext(
        options,
        auth.context.tenantId,
        params.data.requestId,
        params.data.participantId
      );
      if (!context) {
        return reply.code(404).send({ error: "PARTICIPANT_NOT_FOUND" });
      }
      if (normalizedStatement(body.data.statement) !== normalizedStatement(context.consentStatement)) {
        return reply.code(400).send({ error: "INVALID_CONSENT_REQUEST" });
      }

      try {
        const consent = await options.service.recordConsent({
          tenantId: auth.context.tenantId,
          requestId: params.data.requestId,
          participant: context.participant,
          trustProfile: context.trustProfile,
          identityPolicy: context.identityPolicy,
          documentSha256: context.documentSha256,
          statement: context.consentStatement,
          decision: body.data.decision,
        });
        return reply.code(201).send({
          consentId: consent.id,
          status: consent.status,
          statementHash: consent.statementHash,
          decision: consent.decision,
        });
      } catch (error) {
        return sendDomainError(reply, error);
      }
    }
  );

  app.get(
    "/v1/signature-requests/:requestId/participants/:participantId/readiness",
    async (request, reply) => {
      const auth = authenticatedContext(request, options.resolveAuthIdentity);
      if (!auth.ok) {
        return reply.code(auth.statusCode).send({ error: "UNAUTHORIZED_SIGNATURE_CONTEXT" });
      }
      const params = baseParamsSchema.safeParse(request.params);
      if (!params.success) {
        return reply.code(400).send({ error: "INVALID_IDENTITY_REQUEST" });
      }

      const context = await resolveContext(
        options,
        auth.context.tenantId,
        params.data.requestId,
        params.data.participantId
      );
      if (!context) {
        return reply.code(404).send({ error: "PARTICIPANT_NOT_FOUND" });
      }

      try {
        const readiness = await options.service.evaluateParticipantReadiness({
          tenantId: auth.context.tenantId,
          requestId: params.data.requestId,
          participant: context.participant,
          identityPolicy: context.identityPolicy,
          documentSha256: context.documentSha256,
          statementHash: sha256(normalizedStatement(context.consentStatement)),
        });
        return reply.send({ readiness });
      } catch (error) {
        return sendDomainError(reply, error);
      }
    }
  );
}
