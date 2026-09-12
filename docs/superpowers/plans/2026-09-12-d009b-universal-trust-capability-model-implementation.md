# D-009B Universal Trust Capability Model Implementation Plan

> **For agentic workers:** REQUIRED SUB-SKILL: Use superpowers:subagent-driven-development (recommended) or superpowers:executing-plans to implement this plan task-by-task. Steps use checkbox (`- [ ]`) syntax for tracking.

**Goal:** Evoluir o `axesistemas-signature-service` para um núcleo universal de confiança documental orientado a capacidades, com multi-signatário, políticas de confiança e PKI/certificação FAKE isolada de produção, preservando a compatibilidade v0.1.0.

**Architecture:** O Core permanece TypeScript/Fastify e passa a separar identidade, consentimento, assinatura, validação, timestamp e política de confiança por interfaces pequenas. Providers são registrados por capacidades e filtrados por `TrustProfile`; integrações complexas poderão ser adapters externos. A PKI FAKE é infraestrutura exclusiva de desenvolvimento/teste e deve falhar de forma fechada em qualquer perfil produtivo.

**Tech Stack:** Node.js >=24, TypeScript 5.9, Fastify 5, Vitest 3, PostgreSQL, Drizzle ORM/Kit, `node:crypto`, Zod 4.

**Spec:** `docs/superpowers/specs/2026-09-12-d009b-universal-trust-capability-model-design.md`

## Global Constraints

- Core agnóstico de fornecedor.
- Multi-tenant fail-closed em todas as operações.
- O serviço central não persiste chave privada de signatário.
- Providers declaram capacidades explicitamente.
- Autenticação, consentimento, assinatura, validação e timestamp geram evidências.
- O provider fake v0.1.0 e endpoints `/v1/signature-requests` permanecem compatíveis durante a D-009B.
- Perfis de confiança iniciais: `fake-dev`, `sandbox`, `production-standard`.
- `production-standard` rejeita qualquer provider, certificado ou timestamp com `trustMode: "fake"`.
- Não existe fallback automático de provider real para provider fake.
- Migração PostgreSQL é aditiva e preserva `signature_requests` e `signature_evidence` existentes.
- Gates obrigatórios antes de merge: `pnpm security:check`, `pnpm check`, `pnpm test`, `pnpm build`.

---

### Task 1: Capability Model e Trust Profiles

**Files:**
- Create: `src/trust/capabilities.ts`
- Create: `src/trust/trustProfile.ts`
- Create: `src/trust/trustProfile.test.ts`

**Interfaces:**
- Consumes: nenhum contrato novo.
- Produces: `TrustMode`, `SignatureLevel`, `SignatureFormat`, `ProviderKind`, `ProviderDescriptor`, `TrustProfile`, `assertProviderAllowed(profile, provider)`.

- [ ] **Step 1: Escrever testes vermelhos de política de confiança**

```ts
import { describe, expect, it } from "vitest";
import { fakeDevProfile, productionStandardProfile, assertProviderAllowed } from "./trustProfile.js";
import type { ProviderDescriptor } from "./capabilities.js";

const fakeProvider: ProviderDescriptor = {
  id: "fake-signing",
  version: "1.0.0",
  kind: "signing",
  trustMode: "fake",
  signatureLevels: ["simple", "advanced"],
  signatureFormats: ["detached"],
};

describe("TrustProfile", () => {
  it("permite provider fake somente no profile fake-dev", () => {
    expect(() => assertProviderAllowed(fakeDevProfile, fakeProvider)).not.toThrow();
  });

  it("rejeita provider fake no profile production-standard", () => {
    expect(() => assertProviderAllowed(productionStandardProfile, fakeProvider)).toThrow(
      "TRUST_POLICY_VIOLATION"
    );
  });
});
```

- [ ] **Step 2: Rodar o teste e confirmar falha**

Run: `pnpm vitest run src/trust/trustProfile.test.ts`

Expected: FAIL porque `trustProfile.ts` e `capabilities.ts` ainda não existem.

- [ ] **Step 3: Implementar os tipos de capacidade**

```ts
export type TrustMode = "fake" | "sandbox" | "production";
export type SignatureLevel = "simple" | "advanced" | "qualified";
export type SignatureFormat =
  | "pades"
  | "cades"
  | "xades"
  | "xmldsig"
  | "detached"
  | "asic"
  | "jades"
  | "proprietary";
export type ProviderKind = "identity" | "consent" | "signing" | "validation" | "timestamp";

export type ProviderDescriptor = {
  id: string;
  version: string;
  kind: ProviderKind;
  trustMode: TrustMode;
  signatureLevels: SignatureLevel[];
  signatureFormats: SignatureFormat[];
};
```

- [ ] **Step 4: Implementar `TrustProfile` com rejeição explícita do modo fake em produção**

```ts
import type { ProviderDescriptor, SignatureFormat, SignatureLevel, TrustMode } from "./capabilities.js";

export type TrustProfile = {
  id: "fake-dev" | "sandbox" | "production-standard";
  trustMode: TrustMode;
  allowedProviderIds: string[] | "*";
  allowedLevels: SignatureLevel[];
  allowedFormats: SignatureFormat[];
  timestampRequired: boolean;
};

export const fakeDevProfile: TrustProfile = {
  id: "fake-dev",
  trustMode: "fake",
  allowedProviderIds: "*",
  allowedLevels: ["simple", "advanced", "qualified"],
  allowedFormats: ["pades", "cades", "xades", "xmldsig", "detached", "asic", "jades", "proprietary"],
  timestampRequired: false,
};

export const productionStandardProfile: TrustProfile = {
  id: "production-standard",
  trustMode: "production",
  allowedProviderIds: [],
  allowedLevels: ["simple", "advanced", "qualified"],
  allowedFormats: ["pades", "cades", "xades", "xmldsig", "detached", "asic", "jades", "proprietary"],
  timestampRequired: false,
};

export function assertProviderAllowed(profile: TrustProfile, provider: ProviderDescriptor): void {
  if (profile.trustMode === "production" && provider.trustMode === "fake") {
    throw new Error("TRUST_POLICY_VIOLATION");
  }
  if (profile.allowedProviderIds !== "*" && !profile.allowedProviderIds.includes(provider.id)) {
    throw new Error("TRUST_POLICY_VIOLATION");
  }
}
```

- [ ] **Step 5: Rodar os testes e commit**

Run: `pnpm vitest run src/trust/trustProfile.test.ts && pnpm check`

Expected: PASS.

```bash
git add src/trust
git commit -m "feat: add trust capability model"
```

---

### Task 2: Contratos independentes de providers e adapter legado

**Files:**
- Create: `src/providers/providerContracts.ts`
- Create: `src/providers/legacySignatureProviderAdapter.ts`
- Create: `src/providers/legacySignatureProviderAdapter.test.ts`
- Preserve: `src/providers/signatureProvider.ts`
- Preserve: `src/providers/fakeSignatureProvider.ts`

**Interfaces:**
- Consumes: `ProviderDescriptor`, `SignatureLevel`, `SignatureFormat` da Task 1; contrato v0.1.0 `SignatureProvider`.
- Produces: `IdentityProvider`, `ConsentProvider`, `SigningProvider`, `ValidationProvider`, `TimestampProvider`, `LegacySignatureProviderAdapter`.

- [ ] **Step 1: Escrever teste vermelho do adapter legado**

```ts
import { describe, expect, it } from "vitest";
import { FakeSignatureProvider } from "./fakeSignatureProvider.js";
import { LegacySignatureProviderAdapter } from "./legacySignatureProviderAdapter.js";

it("adapta o provider v0.1.0 sem alterar seu contrato", async () => {
  const legacy = new FakeSignatureProvider();
  const adapter = new LegacySignatureProviderAdapter(legacy);
  const result = await adapter.sign({
    requestId: "req-1",
    participantId: "participant-1",
    documentSha256: "abc",
    level: "simple",
    format: "detached",
  });
  expect(result).toEqual({ providerRequestId: "fake:req-1", status: "pending" });
});
```

- [ ] **Step 2: Rodar e confirmar falha**

Run: `pnpm vitest run src/providers/legacySignatureProviderAdapter.test.ts`

Expected: FAIL por módulos ausentes.

- [ ] **Step 3: Criar contratos focados**

```ts
import type { ProviderDescriptor, SignatureFormat, SignatureLevel } from "../trust/capabilities.js";

export type SigningInput = {
  requestId: string;
  participantId: string;
  documentSha256: string;
  level: SignatureLevel;
  format: SignatureFormat;
};

export interface SigningProvider {
  readonly descriptor: ProviderDescriptor;
  sign(input: SigningInput): Promise<{ providerRequestId: string; status: "pending" | "signed" }>;
  cancel(providerRequestId: string): Promise<void>;
}

export interface IdentityProvider {
  readonly descriptor: ProviderDescriptor;
  verify(input: { requestId: string; participantId: string; method: string }): Promise<{ verified: boolean; evidence: Record<string, unknown> }>;
}

export interface ConsentProvider {
  readonly descriptor: ProviderDescriptor;
  record(input: { requestId: string; participantId: string; statementHash: string }): Promise<{ recorded: boolean; evidence: Record<string, unknown> }>;
}

export interface ValidationProvider {
  readonly descriptor: ProviderDescriptor;
  validate(input: { documentSha256: string; signedArtifact: Buffer }): Promise<{ valid: boolean; code?: string; evidence: Record<string, unknown> }>;
}

export interface TimestampProvider {
  readonly descriptor: ProviderDescriptor;
  timestamp(input: { artifactSha256: string }): Promise<{ token: string; issuedAt: string; evidence: Record<string, unknown> }>;
}
```

- [ ] **Step 4: Implementar adapter legado limitado a assinatura assíncrona**

```ts
import type { SignatureProvider } from "./signatureProvider.js";
import type { SigningInput, SigningProvider } from "./providerContracts.js";

export class LegacySignatureProviderAdapter implements SigningProvider {
  readonly descriptor = {
    id: "legacy-signature-provider",
    version: "0.1.0",
    kind: "signing" as const,
    trustMode: "fake" as const,
    signatureLevels: ["simple"] as const,
    signatureFormats: ["detached"] as const,
  };

  constructor(private readonly legacy: SignatureProvider) {}

  async sign(input: SigningInput) {
    const result = await this.legacy.createRequest({ requestId: input.requestId, documentSha256: input.documentSha256 });
    return { providerRequestId: result.providerRequestId, status: "pending" as const };
  }

  async cancel(providerRequestId: string): Promise<void> {
    await this.legacy.cancelRequest(providerRequestId);
  }
}
```

- [ ] **Step 5: Validar compatibilidade e commit**

Run: `pnpm vitest run src/providers/fakeSignatureProvider.test.ts src/providers/legacySignatureProviderAdapter.test.ts && pnpm check`

Expected: ambos PASS, provando que o contrato antigo continua intacto.

```bash
git add src/providers
git commit -m "feat: split universal provider contracts"
```

---

### Task 3: Domínio multi-participante sem quebrar o domínio legado

**Files:**
- Create: `src/signatures/participant.ts`
- Create: `src/signatures/participant.test.ts`
- Modify: `src/signatures/domain.ts`
- Modify: `src/signatures/domain.test.ts`

**Interfaces:**
- Consumes: tipos de nível/formato da Task 1.
- Produces: `Participant`, `ParticipantStatus`, `UniversalSignatureRequest`, `UniversalSignatureStatus`, `transitionParticipantStatus`, `transitionUniversalSignatureStatus`.

- [ ] **Step 1: Escrever testes vermelhos para ciclos independentes**

```ts
import { describe, expect, it } from "vitest";
import { transitionParticipantStatus } from "./participant.js";

it("permite autenticar, consentir e assinar um participante", () => {
  expect(transitionParticipantStatus("invited", "authenticated")).toBe("authenticated");
  expect(transitionParticipantStatus("authenticated", "consented")).toBe("consented");
  expect(transitionParticipantStatus("consented", "signed")).toBe("signed");
});

it("não permite signed voltar para pending", () => {
  expect(() => transitionParticipantStatus("signed", "pending")).toThrow("INVALID_PARTICIPANT_TRANSITION");
});
```

- [ ] **Step 2: Confirmar falha**

Run: `pnpm vitest run src/signatures/participant.test.ts`

Expected: FAIL por arquivo ausente.

- [ ] **Step 3: Implementar domínio de participante**

```ts
export type ParticipantRole = "signer" | "approver" | "witness" | "seal";
export type ParticipantStatus = "invited" | "pending" | "authenticated" | "consented" | "signed" | "rejected" | "expired" | "failed";

export type Participant = {
  id: string;
  role: ParticipantRole;
  order?: number;
  status: ParticipantStatus;
  identity: { name: string; document?: string; email?: string };
  authenticationMethods: string[];
};

const allowed: Record<ParticipantStatus, readonly ParticipantStatus[]> = {
  invited: ["pending", "authenticated", "rejected", "expired", "failed"],
  pending: ["authenticated", "rejected", "expired", "failed"],
  authenticated: ["consented", "signed", "rejected", "expired", "failed"],
  consented: ["signed", "rejected", "expired", "failed"],
  signed: [], rejected: [], expired: [], failed: [],
};

export function transitionParticipantStatus(current: ParticipantStatus, next: ParticipantStatus): ParticipantStatus {
  if (!allowed[current].includes(next)) throw new Error("INVALID_PARTICIPANT_TRANSITION");
  return next;
}
```

- [ ] **Step 4: Adicionar tipos universais em `domain.ts` sem remover `SignatureRequest` e `SignatureStatus` existentes**

```ts
export type UniversalSignatureStatus =
  | "draft"
  | "awaiting_participants"
  | "partially_completed"
  | "validating"
  | "completed"
  | "rejected"
  | "expired"
  | "cancelled"
  | "failed";

export type UniversalSignatureRequest = {
  id: string;
  tenantId: string;
  status: UniversalSignatureStatus;
  documentSha256: string;
  trustProfileId: string;
  signatureLevel: import("../trust/capabilities.js").SignatureLevel;
  signatureFormat: import("../trust/capabilities.js").SignatureFormat;
  signingMode: "parallel" | "sequential";
  participants: import("./participant.js").Participant[];
};
```

Adicionar `transitionUniversalSignatureStatus` com transições explícitas, mantendo `transitionSignatureStatus` legado inalterado.

- [ ] **Step 5: Rodar regressão completa do domínio e commit**

Run: `pnpm vitest run src/signatures/domain.test.ts src/signatures/participant.test.ts && pnpm check`

Expected: testes novos e legados PASS.

```bash
git add src/signatures
git commit -m "feat: add multi-participant trust domain"
```

---

### Task 4: PKI/Certificação FAKE de validação do produto

**Files:**
- Create: `src/fake-pki/fakeCertificateAuthority.ts`
- Create: `src/fake-pki/fakeCertificateProvider.ts`
- Create: `src/fake-pki/fakeSigningProvider.ts`
- Create: `src/fake-pki/fakeValidationProvider.ts`
- Create: `src/fake-pki/fakeTimestampProvider.ts`
- Create: `src/fake-pki/fakePki.test.ts`

**Interfaces:**
- Consumes: `SigningProvider`, `ValidationProvider`, `TimestampProvider`, `ProviderDescriptor`.
- Produces: fake certificates em memória, assinatura criptográfica de teste, validação de status e timestamp fake; nenhum material privado persistido.

- [ ] **Step 1: Escrever teste ponta a ponta vermelho da PKI FAKE**

```ts
import { describe, expect, it } from "vitest";
import { FakeCertificateAuthority } from "./fakeCertificateAuthority.js";
import { FakeSigningProvider } from "./fakeSigningProvider.js";
import { FakeValidationProvider } from "./fakeValidationProvider.js";

it("emite, assina e valida um artefato fake", async () => {
  const ca = new FakeCertificateAuthority({ now: () => new Date("2026-09-12T12:00:00Z") });
  const certificate = ca.issue({ subject: "FAKE TEST Ana", validForSeconds: 3600 });
  const signer = new FakeSigningProvider(ca, certificate.serial);
  const validator = new FakeValidationProvider(ca);
  const signed = await signer.signBytes(Buffer.from("documento"));
  await expect(validator.validateFakeArtifact(signed)).resolves.toMatchObject({ valid: true, trustMode: "fake" });
});

it("rejeita certificado expirado e revogado", async () => {
  const ca = new FakeCertificateAuthority({ now: () => new Date("2026-09-12T12:00:00Z") });
  const expired = ca.issue({ subject: "FAKE EXPIRED", validForSeconds: -1 });
  expect(ca.status(expired.serial)).toBe("expired");
  const active = ca.issue({ subject: "FAKE REVOKED", validForSeconds: 3600 });
  ca.revoke(active.serial);
  expect(ca.status(active.serial)).toBe("revoked");
});
```

- [ ] **Step 2: Confirmar falha**

Run: `pnpm vitest run src/fake-pki/fakePki.test.ts`

Expected: FAIL por módulos ausentes.

- [ ] **Step 3: Implementar CA fake exclusivamente em memória usando `node:crypto`**

A CA deve usar `generateKeyPairSync("ed25519")`, manter as chaves privadas apenas em memória do objeto e emitir um `FakeCertificate` estruturado:

```ts
export type FakeCertificateStatus = "valid" | "expired" | "revoked" | "unknown";
export type FakeCertificate = {
  serial: string;
  subject: string;
  issuer: "AXESISTEMAS FAKE DEV ROOT";
  notBefore: string;
  notAfter: string;
  publicKeyPem: string;
  trustMode: "fake";
};
```

O serial deve ser derivado de SHA-256 de `subject + issuedAt + sequence`; nenhuma chave privada entra no objeto público do certificado.

- [ ] **Step 4: Implementar assinatura, validação e timestamp fake**

`FakeSigningProvider` deve assinar bytes com a chave privada em memória da CA e retornar artefato contendo `certificateSerial`, `payloadSha256`, `signatureBase64`, `trustMode: "fake"`. `FakeValidationProvider` deve verificar hash, assinatura, existência da cadeia e status `valid`. `FakeTimestampProvider` deve emitir token estruturado com `artifactSha256`, `issuedAt`, `providerId: "fake-timestamp"`, `trustMode: "fake"` e hash de integridade.

- [ ] **Step 5: Adicionar casos negativos**

Testar explicitamente: `CERTIFICATE_EXPIRED`, `CERTIFICATE_REVOKED`, `CERTIFICATE_UNTRUSTED`, `SIGNATURE_INVALID`, `DOCUMENT_HASH_MISMATCH` e timestamp adulterado.

Run: `pnpm vitest run src/fake-pki/fakePki.test.ts`

Expected: todos PASS.

- [ ] **Step 6: Commit**

```bash
git add src/fake-pki
git commit -m "feat: add isolated fake PKI test infrastructure"
```

---

### Task 5: Capability Registry e seleção fail-closed

**Files:**
- Create: `src/trust/providerRegistry.ts`
- Create: `src/trust/providerRegistry.test.ts`

**Interfaces:**
- Consumes: descriptors e `TrustProfile`; contratos das Tasks 1 e 2.
- Produces: `ProviderRegistry.register(provider)`, `ProviderRegistry.resolve(kind, profile, requirements)`.

- [ ] **Step 1: Escrever testes vermelhos**

```ts
import { expect, it } from "vitest";
import { ProviderRegistry } from "./providerRegistry.js";
import { fakeDevProfile, productionStandardProfile } from "./trustProfile.js";

it("resolve provider pela capacidade e política", () => {
  const registry = new ProviderRegistry();
  registry.register({ descriptor: { id: "fake-sign", version: "1", kind: "signing", trustMode: "fake", signatureLevels: ["advanced"], signatureFormats: ["detached"] } });
  expect(registry.resolve("signing", fakeDevProfile, { level: "advanced", format: "detached" }).descriptor.id).toBe("fake-sign");
});

it("não faz fallback fake em produção", () => {
  const registry = new ProviderRegistry();
  registry.register({ descriptor: { id: "fake-sign", version: "1", kind: "signing", trustMode: "fake", signatureLevels: ["advanced"], signatureFormats: ["detached"] } });
  expect(() => registry.resolve("signing", productionStandardProfile, { level: "advanced", format: "detached" })).toThrow("UNSUPPORTED_CAPABILITY");
});
```

- [ ] **Step 2: Confirmar falha**

Run: `pnpm vitest run src/trust/providerRegistry.test.ts`

Expected: FAIL.

- [ ] **Step 3: Implementar registro determinístico e fail-closed**

A resolução deve filtrar nesta ordem: `kind` → política (`assertProviderAllowed`) → nível → formato. Se nenhum candidato restar, lançar `UNSUPPORTED_CAPABILITY`. Não tentar provider de outro `trustMode` e não selecionar automaticamente o primeiro provider fake para satisfazer perfil real.

- [ ] **Step 4: Rodar testes e commit**

Run: `pnpm vitest run src/trust/providerRegistry.test.ts src/trust/trustProfile.test.ts && pnpm check`

Expected: PASS.

```bash
git add src/trust
git commit -m "feat: add fail-closed provider registry"
```

---

### Task 6: Persistência aditiva para participantes, bindings, artefatos e validações

**Files:**
- Modify: `src/db/schema.ts`
- Create: `drizzle/0001_d009b_universal_trust.sql`
- Modify: `drizzle/meta/_journal.json`
- Modify: `src/db/signatureRepository.test.ts`

**Interfaces:**
- Consumes: entidades universais das Tasks 1–3.
- Produces: tabelas tenant-scoped adicionais sem remover colunas/tabelas v0.1.0.

- [ ] **Step 1: Escrever teste de regressão estrutural no repositório in-memory**

Manter os testes existentes que provam que `findById` e `updateStatus` nunca atravessam tenants. Adicionar um teste de evidência para garantir rejeição de `tenantId` divergente:

```ts
it("rejects evidence from another tenant", async () => {
  const repo = new InMemorySignatureRepository();
  await expect(repo.appendEvidence("tenant-a", {
    id: "ev-1", requestId: "req-1", tenantId: "tenant-b", type: "validation.completed", payload: {}, createdAt: "2026-09-12T12:00:00Z"
  })).rejects.toThrow("TENANT_MISMATCH");
});
```

- [ ] **Step 2: Expandir `schema.ts` com tabelas aditivas**

Criar: `signature_participants`, `provider_bindings`, `document_artifacts`, `signature_artifacts`, `validation_results`, `trust_profiles`. Toda tabela operacional deve conter `tenant_id`; chaves primárias devem incluir `tenant_id`. Não adicionar campo contendo `privateKey`, `private_key`, PEM privado ou segredo de certificado.

- [ ] **Step 3: Criar migration `0001_d009b_universal_trust.sql`**

A migration deve somente usar `CREATE TABLE`/`CREATE INDEX` para as novas entidades; não executar `DROP`, `TRUNCATE` ou alteração destrutiva de `signature_requests`/`signature_evidence`. Exemplo obrigatório para participantes:

```sql
CREATE TABLE "signature_participants" (
  "tenant_id" text NOT NULL,
  "request_id" text NOT NULL,
  "id" text NOT NULL,
  "role" text NOT NULL,
  "status" text NOT NULL,
  "signing_order" integer,
  "identity" jsonb NOT NULL,
  "authentication_methods" jsonb NOT NULL,
  "created_at" timestamp with time zone DEFAULT now() NOT NULL,
  "updated_at" timestamp with time zone DEFAULT now() NOT NULL,
  CONSTRAINT "signature_participants_tenant_id_id_pk" PRIMARY KEY("tenant_id", "id")
);
CREATE INDEX "signature_participants_tenant_request_idx" ON "signature_participants" ("tenant_id", "request_id");
```

- [ ] **Step 4: Journalar a migration**

Adicionar entrada `idx: 1`, `version: "7"`, `tag: "0001_d009b_universal_trust"`, `breakpoints: true` em `drizzle/meta/_journal.json`. Não inserir conexão de banco no `drizzle.config.ts`.

- [ ] **Step 5: Rodar gates de schema**

Run: `pnpm db:generate`

Expected: nenhuma divergência destrutiva; se o Drizzle gerar migration adicional inesperada, corrigir `schema.ts`/migration antes de seguir e manter exatamente uma migration D-009B journaled.

Run: `pnpm security:check && pnpm vitest run src/db/signatureRepository.test.ts && pnpm check`

Expected: PASS.

- [ ] **Step 6: Commit**

```bash
git add src/db drizzle
git commit -m "feat: add additive D-009B trust schema"
```

---

### Task 7: Orquestração universal, compatibilidade v1, documentação e gates finais

**Files:**
- Create: `src/signatures/universalTrustService.ts`
- Create: `src/signatures/universalTrustService.test.ts`
- Modify: `scripts/security-regression-check.mjs`
- Modify: `docs/openapi.yaml`
- Modify: `README.md`
- Modify: `CHANGELOG.md`
- Verify: `.github/workflows/quality.yml`
- Preserve behavior: `src/http/signatureRoutes.ts`, `src/signatures/signatureService.ts`

**Interfaces:**
- Consumes: `ProviderRegistry`, `TrustProfile`, multi-participante e providers fake.
- Produces: `UniversalTrustService` como nova orquestração D-009B sem substituir `SignatureService` v1.

- [ ] **Step 1: Escrever teste vermelho do fluxo universal fake-dev**

```ts
import { expect, it } from "vitest";
import { UniversalTrustService } from "./universalTrustService.js";

it("completa somente depois de assinatura e validação permitidas pelo trust profile", async () => {
  const result = await makeFakeUniversalService().execute({
    tenantId: "tenant-a",
    requestId: "req-1",
    trustProfileId: "fake-dev",
    document: Buffer.from("doc"),
    level: "advanced",
    format: "detached",
    participants: [{ id: "p1", role: "signer", identity: { name: "Ana" }, authenticationMethods: ["fake"] }],
  });
  expect(result.status).toBe("completed");
  expect(result.validation.valid).toBe(true);
  expect(result.validation.trustMode).toBe("fake");
});
```

Adicionar teste equivalente com `trustProfileId: "production-standard"` que espere `TRUST_POLICY_VIOLATION`/`UNSUPPORTED_CAPABILITY` antes de qualquer assinatura fake.

- [ ] **Step 2: Implementar `UniversalTrustService` mínimo**

O serviço deve: calcular SHA-256; resolver `TrustProfile`; resolver `SigningProvider` via registry; executar assinatura; aplicar timestamp quando o profile exigir; resolver `ValidationProvider`; validar; retornar `completed` somente com `valid === true`. Cada exceção deve ser mapeada para os códigos de domínio definidos na spec; não capturar falha real e tentar provider fake.

- [ ] **Step 3: Revalidar API v1 sem alteração funcional**

Run: `pnpm vitest run src/http/signatureRoutes.test.ts src/signatures/signatureService.test.ts src/providers/fakeSignatureProvider.test.ts`

Expected: todos os testes v0.1.0 continuam PASS e `/v1/signature-requests` continua retornando `pending` com `providerRequestId: fake:req-*` no fixture legado.

- [ ] **Step 4: Fortalecer security regression gate**

Em `scripts/security-regression-check.mjs`, adicionar leituras de `src/trust/trustProfile.ts`, `src/fake-pki/fakeCertificateAuthority.ts` e `src/db/schema.ts`. O script deve falhar se:

```js
!trustProfile.includes('profile.trustMode === "production" && provider.trustMode === "fake"')
```

ou se o schema contiver o padrão existente de chave privada. Adicionar também condição que confirme a presença do `trustMode: "fake"` nos providers fake e ausência de fallback textual `fallback` do registry para modo fake.

- [ ] **Step 5: Atualizar OpenAPI e documentação**

`docs/openapi.yaml`: manter integralmente os paths v1 atuais e acrescentar schemas reutilizáveis `TrustMode`, `SignatureLevel`, `SignatureFormat`, `Participant` e `ProviderCapability`; não anunciar provider ICP-Brasil real como disponível.

`README.md`: substituir o estado obsoleto “D-009A em desenvolvimento” por “v0.1.0/D-009A encerrada; D-009B em evolução”, documentar PKI FAKE como não produtiva e incluir comandos de qualidade.

`CHANGELOG.md`: adicionar seção `Unreleased / D-009B` com capability model, multi-participante, trust profiles e PKI FAKE, deixando claro que não há certificado legalmente válido nesta etapa.

- [ ] **Step 6: Rodar todos os gates**

Run:

```bash
pnpm security:check
pnpm check
pnpm test
pnpm build
```

Expected: todos GREEN.

- [ ] **Step 7: Commit de fechamento da implementação D-009B**

```bash
git add src scripts docs README.md CHANGELOG.md .github/workflows/quality.yml
git commit -m "feat: complete D-009B universal trust foundation"
```

- [ ] **Step 8: Evidência de aceite**

Registrar no PR/relatório de release os resultados dos quatro gates, quantidade de testes executados e os cenários obrigatórios da PKI FAKE: válido, expirado, revogado, cadeia desconhecida, assinatura inválida, hash divergente e timestamp adulterado. Não declarar suporte produtivo ICP-Brasil, PAdES/CAdES/XAdES ou provider comercial até as histórias D-009D–D-009G correspondentes.

---

## Self-review do plano

- Cobertura da spec: capability registry, contratos separados, multi-participante, trust profiles, PKI FAKE, persistência aditiva, compatibilidade v1, evidências de validação e security gates estão mapeados às Tasks 1–7.
- Não há integração produtiva com provider real nesta D-009B; isso permanece deliberadamente fora do escopo.
- Tipos centrais usados por tasks posteriores são definidos nas Tasks 1–3.
- A PKI FAKE mantém chave privada somente em memória de teste e é bloqueada por política em produção.
- O endpoint v1 e `SignatureProvider` legado permanecem preservados até depreciação futura explícita.
