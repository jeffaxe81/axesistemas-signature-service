import fs from "node:fs";
import path from "node:path";

const root = process.cwd();
const read = relative => fs.readFileSync(path.join(root, relative), "utf8");
const requireCondition = (condition, message) => {
  if (!condition) throw new Error(message);
};

const routes = read("src/http/signatureRoutes.ts");
const identityRoutes = read("src/http/identityConsentRoutes.ts");
const repository = read("src/db/signatureRepository.ts");
const identityRepository = read("src/db/identityConsentRepository.ts");
const schema = read("src/db/schema.ts");
const webhookVerifier = read("src/webhooks/webhookVerifier.ts");
const webhookHandler = read("src/webhooks/providerWebhookHandler.ts");
const drizzleConfig = read("drizzle.config.ts");
const trustProfile = read("src/trust/trustProfile.ts");
const providerRegistry = read("src/trust/providerRegistry.ts");
const fakeCa = read("src/fake-pki/fakeCertificateAuthority.ts");
const fakeIdentity = read("src/providers/fakeIdentityProvider.ts");
const fakeConsent = read("src/providers/fakeConsentProvider.ts");
const identitySession = read("src/identity/identitySession.ts");
const universalService = read("src/signatures/universalTrustService.ts");
const universalTests = read("src/signatures/universalTrustService.test.ts");

requireCondition(
  routes.includes("tenantId: z.unknown().optional()") &&
    routes.includes("createSignatureRequest(auth.context") &&
    !routes.includes("tenantId: parsed.data.tenantId"),
  "A API pública passou a autorizar tenantId vindo do payload."
);

requireCondition(
  repository.includes("findById(tenantId: string, id: string)") &&
    !/findById\s*\(\s*id\s*:/.test(repository),
  "O repositório expõe busca sem escopo obrigatório de tenant."
);

requireCondition(
  identityRoutes.includes("auth.context.tenantId") &&
    identityRoutes.includes("resolveParticipant({ tenantId, requestId, participantId })") &&
    identityRoutes.includes("resolveDocumentSha256({ tenantId, requestId })") &&
    !identityRoutes.includes("parsed.data.tenantId"),
  "As rotas D-009C perderam o escopo obrigatório de tenant autenticado."
);
requireCondition(
  identityRepository.includes("eq(identitySessions.tenantId, tenantId)") &&
    identityRepository.includes("eq(identityEvidences.tenantId, tenantId)") &&
    identityRepository.includes("eq(consentRecords.tenantId, tenantId)"),
  "O repositório D-009C perdeu filtro explícito de tenant."
);

requireCondition(
  webhookVerifier.includes("createHmac") && webhookVerifier.includes("timingSafeEqual"),
  "O webhook perdeu HMAC ou comparação timing-safe."
);
requireCondition(
  webhookHandler.includes("executeOnce") && webhookHandler.includes("event.eventId"),
  "O webhook perdeu o gate de idempotência por evento."
);
requireCondition(
  webhookHandler.includes("context.tenantId") && webhookHandler.includes("PROVIDER_REQUEST_MISMATCH"),
  "O webhook perdeu isolamento de tenant ou vínculo com providerRequestId."
);

requireCondition(
  trustProfile.includes('profile.trustMode === "production" && provider.trustMode === "fake"'),
  "O profile produtivo deixou de rejeitar provider fake."
);
const fallbackSource = [providerRegistry, universalService, identityRoutes, identityRepository].join("\n");
requireCondition(
  !/fallbackFake|fallbackToFake|allowFakeInProduction/.test(fallbackSource),
  "Foi introduzido fallback explícito ou liberação produtiva para provider fake."
);
requireCondition(
  fakeCa.includes("Map<string, KeyObject>") && !fakeCa.includes('from "node:fs"'),
  "A PKI fake deixou de manter suas chaves efêmeras exclusivamente em memória."
);
requireCondition(
  fakeIdentity.includes('trustMode: "fake"') && fakeConsent.includes('trustMode: "fake"'),
  "Providers FAKE de identidade/consentimento perderam trustMode fake."
);

const privateKeyPattern = /private[_-]?key|privateKey|BEGIN PRIVATE KEY|pem\s*:/i;
requireCondition(
  !privateKeyPattern.test(schema),
  "O schema passou a persistir material de chave privada."
);
for (const relative of [
  "src/signatures/domain.ts",
  "src/providers/signatureProvider.ts",
  "drizzle/0000_d009a_signature_service.sql",
  "drizzle/0001_d009b_universal_trust.sql",
  "drizzle/0002_d009c_identity_consent.sql",
]) {
  requireCondition(
    !privateKeyPattern.test(read(relative)),
    `Material de chave privada detectado em ${relative}.`
  );
}

const migrationD009B = read("drizzle/0001_d009b_universal_trust.sql");
requireCondition(
  !/\b(DROP|TRUNCATE)\b|ALTER\s+TABLE[\s\S]*\bDROP\b/i.test(migrationD009B),
  "A migration D-009B deixou de ser estritamente aditiva."
);

const migrationD009C = read("drizzle/0002_d009c_identity_consent.sql");
requireCondition(
  !/\b(DROP|TRUNCATE)\b|ALTER\s+TABLE[\s\S]*\bDROP\b/i.test(migrationD009C),
  "A migration D-009C deixou de ser estritamente aditiva."
);
for (const table of ["identity_sessions", "identity_evidences", "consent_records"]) {
  const match = migrationD009C.match(
    new RegExp(`CREATE TABLE "${table}" \\(([\\s\\S]*?)\\n\\);`, "m")
  );
  requireCondition(Boolean(match?.[1]?.includes('"tenant_id" text NOT NULL')), `Tabela ${table} sem tenant_id obrigatório.`);
}

const secretBearingPattern = /(plain.*otp|password|refresh.*token|private.*key|totp.*secret|bearer.*token)/i;
requireCondition(
  !secretBearingPattern.test(schema) && !secretBearingPattern.test(migrationD009C),
  "Schema/migration D-009C introduziu coluna evidente de segredo persistido."
);
requireCondition(
  schema.includes('challengeDigest: varchar("challenge_digest"') &&
    !schema.includes('challengeResponse:') &&
    !migrationD009C.includes('"challenge_response"'),
  "O challenge D-009C deixou de persistir apenas digest/correlação segura."
);

requireCondition(
  identitySession.includes("IDENTITY_REPLAY_DETECTED") &&
    identitySession.includes("IDENTITY_CHALLENGE_EXPIRED"),
  "A sessão de identidade perdeu proteção explícita de replay ou expiração."
);
requireCondition(
  identityRoutes.includes(":identity-start`") && identityRoutes.includes(":identity-complete`"),
  "As operações de challenge perderam chaves de rate limit segregadas."
);

const readinessIndex = universalService.indexOf("identityReadiness");
const signingResolveIndex = universalService.indexOf('registry.resolve("signing"');
requireCondition(
  readinessIndex >= 0 && signingResolveIndex >= 0 && readinessIndex < signingResolveIndex,
  "UniversalTrustService pode resolver assinatura antes do gate de readiness D-009C."
);
const zeroSigningAssertions = universalTests.match(/expect\(signingProvider\.signCalls\)\.toBe\(0\)/g) ?? [];
requireCondition(
  universalTests.includes('status).toBe("awaiting_identity")') &&
    universalTests.includes('status).toBe("awaiting_consent")') &&
    zeroSigningAssertions.length >= 2,
  "Os testes deixaram de provar bloqueio de assinatura antes de identidade/consentimento."
);

const journal = JSON.parse(read("drizzle/meta/_journal.json"));
const tags = journal.entries.map(entry => entry.tag);
const migrationFiles = fs
  .readdirSync(path.join(root, "drizzle"))
  .filter(name => /^\d{4}_.+\.sql$/.test(name));
const journalFiles = tags.map(tag => `${tag}.sql`);
requireCondition(
  migrationFiles.length === journalFiles.length &&
    migrationFiles.every(file => journalFiles.includes(file)),
  "Há migration SQL fora do journal ou entrada de journal sem SQL correspondente."
);

const tenantPrimaryKeys = schema.match(
  /primaryKey\(\{ columns: \[table\.tenantId, table\.id\] \}\)/g
) ?? [];
requireCondition(
  tenantPrimaryKeys.length >= 11,
  "Uma tabela D-009B/D-009C deixou de usar tenant na chave primária."
);
requireCondition(
  !drizzleConfig.includes("DATABASE_URL") && !drizzleConfig.includes("dbCredentials"),
  "A configuração de geração passou a carregar conexão de banco."
);

console.log(
  "D-009A/B/C security regression gate aprovado: tenant fail-closed, webhook seguro, fake isolado de produção, replay/expiração protegidos, readiness antes da assinatura, segredos fora do schema e migrations aditivas/journaled."
);
