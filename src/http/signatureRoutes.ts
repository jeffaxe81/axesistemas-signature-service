import type { FastifyInstance, FastifyRequest } from "fastify";
import { z } from "zod";
import {
  resolveTenantContext,
  type AuthIdentity,
  type TenantContext,
} from "../security/tenantContext.js";
import type { SignatureRequest } from "../signatures/domain.js";
import type { SignatureService } from "../signatures/signatureService.js";

export type ResolveAuthIdentity = (
  authorization: string | undefined
) => AuthIdentity | null;

export type SignatureRouteOptions = {
  signatureService: SignatureService;
  resolveAuthIdentity: ResolveAuthIdentity;
};

const signerSchema = z
  .object({
    name: z.string().trim().min(1).max(200),
    document: z.string().trim().min(1).max(100).optional(),
    email: z.string().email().max(320).optional(),
  })
  .strict();

const createRequestSchema = z
  .object({
    tenantId: z.unknown().optional(),
    signer: signerSchema,
    documentBase64: z
      .string()
      .min(1)
      .max(14_000_000)
      .regex(/^[A-Za-z0-9+/]+={0,2}$/),
    contentType: z.string().trim().min(1).max(200).optional(),
  })
  .strict();

const paramsSchema = z.object({ id: z.string().trim().min(1).max(200) }).strict();

function publicSignatureRequest(request: SignatureRequest) {
  return {
    id: request.id,
    status: request.status,
    documentSha256: request.documentSha256,
    providerRequestId: request.providerRequestId,
    signer: request.signer,
  };
}

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

export function registerSignatureRoutes(
  app: FastifyInstance,
  options: SignatureRouteOptions
): void {
  app.post("/v1/signature-requests", async (request, reply) => {
    const auth = authenticatedContext(request, options.resolveAuthIdentity);
    if (!auth.ok) {
      return reply.code(auth.statusCode).send({ error: "UNAUTHORIZED_SIGNATURE_CONTEXT" });
    }

    const parsed = createRequestSchema.safeParse(request.body);
    if (!parsed.success) {
      return reply.code(400).send({ error: "INVALID_SIGNATURE_REQUEST" });
    }

    const result = await options.signatureService.createSignatureRequest(auth.context, {
      document: Buffer.from(parsed.data.documentBase64, "base64"),
      signer: parsed.data.signer,
      contentType: parsed.data.contentType,
    });

    return reply.code(201).send(publicSignatureRequest(result));
  });

  app.get("/v1/signature-requests/:id", async (request, reply) => {
    const auth = authenticatedContext(request, options.resolveAuthIdentity);
    if (!auth.ok) {
      return reply.code(auth.statusCode).send({ error: "UNAUTHORIZED_SIGNATURE_CONTEXT" });
    }

    const parsedParams = paramsSchema.safeParse(request.params);
    if (!parsedParams.success) {
      return reply.code(400).send({ error: "INVALID_SIGNATURE_REQUEST_ID" });
    }

    const result = await options.signatureService.getSignatureRequest(
      auth.context,
      parsedParams.data.id
    );

    if (!result) {
      return reply.code(404).send({ error: "SIGNATURE_REQUEST_NOT_FOUND" });
    }

    return reply.send(publicSignatureRequest(result));
  });
}
