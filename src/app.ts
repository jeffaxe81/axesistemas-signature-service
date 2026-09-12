import Fastify from "fastify";
import {
  registerIdentityConsentRoutes,
  type IdentityConsentRouteOptions,
} from "./http/identityConsentRoutes.js";
import {
  registerSignatureRoutes,
  type ResolveAuthIdentity,
} from "./http/signatureRoutes.js";
import type { SignatureService } from "./signatures/signatureService.js";

export type BuildAppOptions = {
  signatureService?: SignatureService;
  resolveAuthIdentity?: ResolveAuthIdentity;
  identityConsentRoutes?: IdentityConsentRouteOptions;
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

  if (options.identityConsentRoutes) {
    registerIdentityConsentRoutes(app, options.identityConsentRoutes);
  }

  return app;
}
