import fs from "node:fs";
import path from "node:path";

const root = process.cwd();
const read = relative => fs.readFileSync(path.join(root, relative), "utf8");
const requireCondition = (condition, message) => {
  if (!condition) throw new Error(message);
};

const routes = read("src/http/signatureRoutes.ts");
const repository = read("src/db/signatureRepository.ts");
const schema = read("src/db/schema.ts");
const webhookVerifier = read("src/webhooks/webhookVerifier.ts");
const webhookHandler = read("src/webhooks/providerWebhookHandler.ts");
const drizzleConfig = read("drizzle.config.ts");
const trustProfile = read("src/trust/trustProfile.ts");
const providerRegistry = read("src/trust/providerRegistry.ts");
const fakeCa = read("src/fake-pki/fakeCertificateAuthority.ts");

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
requireCondition(
  !providerRegistry.includes("fallbackFake") && !providerRegistry.includes("fallbackToFake"),
  "O registry introduziu fallback explícito para provider fake."
);
requireCondition(
  fakeCa.includes("Map<string, KeyObject>") && !fakeCa.includes('from "node:fs"'),
  "A PKI fake deixou de manter suas chaves efêmeras exclusivamente em memória."
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
  tenantPrimaryKeys.length >= 8,
  "Uma tabela D-009B deixou de usar tenant na chave primária."
);
requireCondition(
  !drizzleConfig.includes("DATABASE_URL") && !drizzleConfig.includes("dbCredentials"),
  "A configuração de geração passou a carregar conexão de banco."
);

console.log(
  "D-009B security regression gate aprovado: tenant fail-closed, webhook seguro, fake bloqueado em produção, sem fallback fake, chaves fake apenas em memória e migrations aditivas/journaled."
);
