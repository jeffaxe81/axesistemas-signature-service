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

const privateKeyPattern = /private[_-]?key|privateKey|BEGIN PRIVATE KEY|pem\s*:/i;
requireCondition(!privateKeyPattern.test(schema), "O schema passou a persistir material de chave privada.");
for (const relative of [
  "src/signatures/domain.ts",
  "src/providers/signatureProvider.ts",
  "drizzle/0000_d009a_signature_service.sql",
]) {
  requireCondition(!privateKeyPattern.test(read(relative)), `Material de chave privada detectado em ${relative}.`);
}

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

requireCondition(
  schema.includes('primaryKey({ columns: [table.tenantId, table.id] })'),
  "A chave primária de assinatura deixou de incluir tenant."
);
requireCondition(
  !drizzleConfig.includes("DATABASE_URL") && !drizzleConfig.includes("dbCredentials"),
  "A configuração de geração passou a carregar conexão de banco."
);

console.log("D-009A security regression gate aprovado: tenant fail-closed, webhook seguro, sem chave privada e migration journaled.");
