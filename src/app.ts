import Fastify from "fastify";
import {
  registerSignatureRoutes,
  type ResolveAuthIdentity,
} from "./http/signatureRoutes.js";
import type { SignatureService } from "./signatures/signatureService.js";

export type BuildAppOptions = {
  signatureService?: SignatureService;
  resolveAuthIdentity?: ResolveAuthIdentity;
};

export function buildApp(options: BuildAppOptions = {}) {
  const app = Fastify();

  app.get("/health", async () => ({ status: "ok" }));

  if (options.signatureService && options.resolveAuthIdentity) {
    registerSignatureRoutes(app, {
      signatureService: options.signatureService,
      resolveAuthIdentity: options.resolveAuthIdentity,
    });
  }

  return app;
}
