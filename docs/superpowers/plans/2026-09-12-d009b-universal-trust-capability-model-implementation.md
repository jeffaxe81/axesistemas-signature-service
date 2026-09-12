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
- O repositório atual usa migration SQL + `_journal.json` sem snapshot Drizzle; a D-009B deve seguir o mesmo padrão e não executar migration em banco real.
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
  it("permite provider fake no profile fake-dev", () => {
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

Expected: FAIL porque os módulos ainda não existem.

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

- [ ] **Step 4: Implementar `TrustProfile` com bloqueio explícito de FAKE em produção**

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

export const sandboxProfile: TrustProfile = {
  id: "sandbox",
  trustMode: "sandbox",
  allowedProviderIds: [],
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

- [ ] **Step 5: Rodar testes e commit**

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
- Produces: `IdentityProvider`, `ConsentProvider`, `SigningProvider`, `SigningResult`, `ValidationProvider`, `TimestampProvider`, `LegacySignatureProviderAdapter`.

- [ ] **Step 1: Escrever teste vermelho do adapter legado**

```ts
import { expect, it } from "vitest";
import { FakeSignatureProvider } from "./fakeSignatureProvider.js";
import { LegacySignatureProviderAdapter } from "./legacySignatureProviderAdapter.js";

it("adapta o provider v0.1.0 sem alterar seu contrato", async () => {
  const adapter = new LegacySignatureProviderAdapter(new FakeSignatureProvider());
  await expect(adapter.sign({
    requestId: "req-1",
    participantId: "participant-1",
    documentSha256: "abc",
    level: "simple",
    format: "detached",
  })).resolves.toEqual({ providerRequestId: "fake:req-1", status: "pending" });
});
```

- [ ] **Step 2: Rodar e confirmar falha**

Run: `pnpm vitest run src/providers/legacySignatureProviderAdapter.test.ts`

Expected: FAIL por módulos ausentes.

- [ ] **Step 3: Criar contratos focados, incluindo artefato assinado opcional**

```ts
import type { ProviderDescriptor, SignatureFormat, SignatureLevel } from "../trust/capabilities.js";

export type SigningInput = {
  requestId: string;
  participantId: string;
  documentSha256: string;
  level: SignatureLevel;
  format: SignatureFormat;
};

export type SigningResult = {
  providerRequestId: string;
  status: "pending" | "signed";
  signedArtifact?: Buffer;
  evidence?: Record<string, unknown>;
};

export interface SigningProvider {
  readonly descriptor: ProviderDescriptor;
  sign(input: SigningInput): Promise<SigningResult>;
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
  validate(input: { documentSha256: string; signedArtifact: Buffer }): Promise<{ valid: boolean; trustMode: "fake" | "sandbox" | "production"; code?: string; evidence: Record<string, unknown> }>;
}

export interface TimestampProvider {
  readonly descriptor: ProviderDescriptor;
  timestamp(input: { artifactSha256: string }): Promise<{ token: string; issuedAt: string; trustMode: "fake" | "sandbox" | "production"; evidence: Record<string, unknown> }>;
}
```

- [ ] **Step 4: Implementar adapter legado como provider assíncrono limitado**

```ts
import type { ProviderDescriptor } from "../trust/capabilities.js";
import type { SignatureProvider } from "./signatureProvider.js";
import type { SigningInput, SigningProvider, SigningResult } from "./providerContracts.js";

export class LegacySignatureProviderAdapter implements SigningProvider {
  readonly descriptor: ProviderDescriptor = {
    id: "legacy-signature-provider",
    version: "0.1.0",
    kind: "signing",
    trustMode: "fake",
    signatureLevels: ["simple"],
    signatureFormats: ["detached"],
  };

  constructor(private readonly legacy: SignatureProvider) {}

  async sign(input: SigningInput): Promise<SigningResult> {
    const result = await this.legacy.createRequest({ requestId: input.requestId, documentSha256: input.documentSha256 });
    return { providerRequestId: result.providerRequestId, status: "pending" };
  }

  async cancel(providerRequestId: string): Promise<void> {
    await this.legacy.cancelRequest(providerRequestId);
  }
}
```

- [ ] **Step 5: Validar compatibilidade e commit**

Run: `pnpm vitest run src/providers/fakeSignatureProvider.test.ts src/providers/legacySignatureProviderAdapter.test.ts && pnpm check`

Expected: PASS.

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
import { expect, it } from "vitest";
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

Expected: FAIL.

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

- [ ] **Step 4: Adicionar domínio universal a `domain.ts` preservando tipos v0.1.0**

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

Implementar `transitionUniversalSignatureStatus` por tabela explícita, mantendo `SignatureStatus`, `SignatureRequest` e `transitionSignatureStatus` atuais sem mudança incompatível.

- [ ] **Step 5: Rodar regressão e commit**

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
- Consumes: `SigningProvider`, `SigningResult`, `ValidationProvider`, `TimestampProvider`.
- Produces: certificado fake estruturado, assinatura criptográfica de teste, validação de cadeia/status e timestamp fake; nenhuma chave privada persistida.

- [ ] **Step 1: Escrever testes ponta a ponta vermelhos**

```ts
import { expect, it } from "vitest";
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

it("expõe estados expirado e revogado", () => {
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

Expected: FAIL.

- [ ] **Step 3: Implementar CA fake em memória usando `node:crypto`**

Usar `generateKeyPairSync("ed25519")`. O objeto público deve ser:

```ts
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

A CA mantém as chaves privadas em `Map<string, KeyObject>` somente em memória. `issue()` calcula serial via SHA-256 de `subject + issuedAt + sequence`; `revoke()` mantém um `Set<string>`; `status()` retorna `valid | expired | revoked | unknown`.

- [ ] **Step 4: Implementar provider fake de assinatura com artefato verificável**

Definir:

```ts
export type FakeSignedArtifact = {
  payload: Buffer;
  payloadSha256: string;
  certificateSerial: string;
  signatureBase64: string;
  trustMode: "fake";
};
```

`signBytes(bytes)` deve usar `crypto.sign(null, bytes, privateKey)`. `sign(input)` deve produzir um artefato serializado em `Buffer`, retornar `status: "signed"`, `providerRequestId: fake-pki:<requestId>` e `signedArtifact` preenchido.

- [ ] **Step 5: Implementar validação e timestamp fake**

`FakeValidationProvider` desserializa o artefato, recalcula SHA-256, consulta `ca.status(serial)`, obtém a chave pública e usa `crypto.verify`. Mapear falhas exatamente para `CERTIFICATE_EXPIRED`, `CERTIFICATE_REVOKED`, `CERTIFICATE_UNTRUSTED`, `SIGNATURE_INVALID`, `DOCUMENT_HASH_MISMATCH`.

`FakeTimestampProvider` retorna token JSON-base64 contendo `artifactSha256`, `issuedAt`, `providerId: "fake-timestamp"`, `trustMode: "fake"` e `integritySha256`. A validação do token recalcula `integritySha256` e rejeita alteração.

- [ ] **Step 6: Adicionar cenários negativos e commit**

Cobrir certificado expirado, revogado, serial desconhecido, assinatura adulterada, hash divergente e timestamp adulterado.

Run: `pnpm vitest run src/fake-pki/fakePki.test.ts && pnpm check`

Expected: PASS.

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
- Consumes: `ProviderDescriptor`, `TrustProfile`, `assertProviderAllowed`.
- Produces: `ProviderRegistry.register(provider)`, `ProviderRegistry.resolve(kind, profile, requirements)`.

- [ ] **Step 1: Escrever testes vermelhos de resolução**

```ts
import { expect, it } from "vitest";
import { ProviderRegistry } from "./providerRegistry.js";
import { fakeDevProfile, productionStandardProfile } from "./trustProfile.js";

const fake = {
  descriptor: {
    id: "fake-sign", version: "1", kind: "signing" as const, trustMode: "fake" as const,
    signatureLevels: ["advanced" as const], signatureFormats: ["detached" as const],
  },
};

it("resolve provider compatível com capacidade e profile", () => {
  const registry = new ProviderRegistry();
  registry.register(fake);
  expect(registry.resolve("signing", fakeDevProfile, { level: "advanced", format: "detached" }).descriptor.id).toBe("fake-sign");
});

it("não faz fallback fake em produção", () => {
  const registry = new ProviderRegistry();
  registry.register(fake);
  expect(() => registry.resolve("signing", productionStandardProfile, { level: "advanced", format: "detached" })).toThrow("UNSUPPORTED_CAPABILITY");
});
```

- [ ] **Step 2: Confirmar falha**

Run: `pnpm vitest run src/trust/providerRegistry.test.ts`

Expected: FAIL.

- [ ] **Step 3: Implementar registro determinístico**

```ts
import type { ProviderDescriptor, ProviderKind, SignatureFormat, SignatureLevel } from "./capabilities.js";
import type { TrustProfile } from "./trustProfile.js";
import { assertProviderAllowed } from "./trustProfile.js";

export type RegisteredProvider = { descriptor: ProviderDescriptor };

export class ProviderRegistry {
  private readonly providers: RegisteredProvider[] = [];
  register(provider: RegisteredProvider): void { this.providers.push(provider); }

  resolve(kind: ProviderKind, profile: TrustProfile, requirements: { level: SignatureLevel; format: SignatureFormat }): RegisteredProvider {
    const candidate = this.providers.find(provider => {
      if (provider.descriptor.kind !== kind) return false;
      try { assertProviderAllowed(profile, provider.descriptor); } catch { return false; }
      return provider.descriptor.signatureLevels.includes(requirements.level)
        && provider.descriptor.signatureFormats.includes(requirements.format);
    });
    if (!candidate) throw new Error("UNSUPPORTED_CAPABILITY");
    return candidate;
  }
}
```

Não adicionar segunda tentativa com provider de outro `trustMode`.

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
- Produces: tabelas tenant-scoped adicionais sem alterar destrutivamente o schema v0.1.0.

- [ ] **Step 1: Fortalecer teste de tenant em evidências**

```ts
it("rejects evidence from another tenant", async () => {
  const repo = new InMemorySignatureRepository();
  await expect(repo.appendEvidence("tenant-a", {
    id: "ev-1",
    requestId: "req-1",
    tenantId: "tenant-b",
    type: "validation.completed",
    payload: {},
    createdAt: "2026-09-12T12:00:00Z",
  })).rejects.toThrow("TENANT_MISMATCH");
});
```

Run: `pnpm vitest run src/db/signatureRepository.test.ts`

Expected: PASS no código atual; esse teste fixa a regressão antes de expandir o schema.

- [ ] **Step 2: Expandir `schema.ts` de forma aditiva**

Criar tabelas `signature_participants`, `provider_bindings`, `document_artifacts`, `signature_artifacts`, `validation_results`, `trust_profiles`. Toda tabela operacional deve conter `tenant_id`, e as chaves primárias devem incluir `tenant_id`. Não criar coluna com nome ou conteúdo de chave privada.

Exemplo da tabela de participantes:

```ts
export const signatureParticipants = pgTable("signature_participants", {
  tenantId: text("tenant_id").notNull(),
  requestId: text("request_id").notNull(),
  id: text("id").notNull(),
  role: text("role").notNull(),
  status: text("status").notNull(),
  signingOrder: integer("signing_order"),
  identity: jsonb("identity").$type<Record<string, unknown>>().notNull(),
  authenticationMethods: jsonb("authentication_methods").$type<string[]>().notNull(),
  createdAt: timestamp("created_at", { withTimezone: true }).defaultNow().notNull(),
  updatedAt: timestamp("updated_at", { withTimezone: true }).defaultNow().notNull(),
}, table => [
  primaryKey({ columns: [table.tenantId, table.id] }),
  index("signature_participants_tenant_request_idx").on(table.tenantId, table.requestId),
]);
```

Adicionar `integer` aos imports de `drizzle-orm/pg-core`.

- [ ] **Step 3: Criar migration manual seguindo o padrão atual do repositório**

Criar `drizzle/0001_d009b_universal_trust.sql` somente com `CREATE TABLE` e `CREATE INDEX` correspondentes às seis novas tabelas. Não usar `DROP`, `TRUNCATE`, `ALTER ... DROP` e não recriar `signature_requests` nem `signature_evidence`.

Trecho obrigatório:

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
--> statement-breakpoint
CREATE INDEX "signature_participants_tenant_request_idx" ON "signature_participants" USING btree ("tenant_id", "request_id");
```

- [ ] **Step 4: Atualizar journal no mesmo padrão da migration 0000**

Adicionar exatamente uma segunda entrada em `drizzle/meta/_journal.json`:

```json
{
  "idx": 1,
  "version": "7",
  "when": 1789236000000,
  "tag": "0001_d009b_universal_trust",
  "breakpoints": true
}
```

Não executar `pnpm db:generate` nesta task, porque o repositório atual não possui snapshot Drizzle e a geração automática poderia reconstruir o schema inicial. Não aplicar a migration em banco real.

- [ ] **Step 5: Rodar gates de schema e commit**

Run: `pnpm security:check && pnpm vitest run src/db/signatureRepository.test.ts && pnpm check`

Expected: migration e journal com contagem 1:1, nenhuma chave privada detectada, testes PASS.

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
- Consumes: `ProviderRegistry`, `TrustProfile`, multi-participante, `SigningProvider`, `ValidationProvider`, `TimestampProvider` e PKI FAKE.
- Produces: `UniversalTrustService.execute()` como nova orquestração D-009B sem substituir `SignatureService` v1.

- [ ] **Step 1: Escrever teste vermelho do fluxo `fake-dev`**

```ts
import { expect, it } from "vitest";
import { makeFakeUniversalService } from "../fake-pki/testFactory.js";

it("completa somente após assinatura e validação aprovadas", async () => {
  const service = makeFakeUniversalService();
  const result = await service.execute({
    tenantId: "tenant-a",
    requestId: "req-1",
    trustProfileId: "fake-dev",
    document: Buffer.from("doc"),
    level: "advanced",
    format: "detached",
    participants: [{
      id: "p1", role: "signer", status: "authenticated",
      identity: { name: "Ana" }, authenticationMethods: ["fake"],
    }],
  });
  expect(result.status).toBe("completed");
  expect(result.validation).toMatchObject({ valid: true, trustMode: "fake" });
});
```

Criar `src/fake-pki/testFactory.ts` na mesma task para compor CA, providers e registry exclusivamente para testes.

Adicionar teste com `trustProfileId: "production-standard"` que espere `UNSUPPORTED_CAPABILITY` antes de `FakeSigningProvider.sign()` ser chamado.

- [ ] **Step 2: Implementar `UniversalTrustService` mínimo**

Fluxo obrigatório: calcular SHA-256 → resolver profile → resolver signing provider → assinar → se `pending`, retornar `awaiting_participants` sem validação → se `signed`, exigir `signedArtifact` → opcionalmente timestamp conforme profile → resolver validation provider → validar → retornar `completed` apenas com `valid === true`.

Assinatura pública mínima:

```ts
export class UniversalTrustService {
  async execute(input: UniversalTrustExecutionInput): Promise<UniversalTrustExecutionResult> {
    // implementação pelos passos do fluxo acima
  }
}
```

Erros de capacidade/política devem permanecer códigos de domínio. Não capturar erro de provider real para tentar provider fake.

- [ ] **Step 3: Revalidar API v1 sem alteração funcional**

Run: `pnpm vitest run src/http/signatureRoutes.test.ts src/signatures/signatureService.test.ts src/providers/fakeSignatureProvider.test.ts`

Expected: todos PASS; `/v1/signature-requests` continua retornando `pending` com `providerRequestId: fake:req-*` nos fixtures atuais.

- [ ] **Step 4: Fortalecer security regression gate**

Adicionar ao `scripts/security-regression-check.mjs` leitura de `src/trust/trustProfile.ts`, `src/trust/providerRegistry.ts`, `src/fake-pki/fakeCertificateAuthority.ts` e `src/db/schema.ts`.

Adicionar checks equivalentes a:

```js
requireCondition(
  trustProfile.includes('profile.trustMode === "production" && provider.trustMode === "fake"'),
  "O profile produtivo deixou de rejeitar provider fake."
);
requireCondition(
  !/private[_-]?key|privateKey|BEGIN PRIVATE KEY|pem\s*:/i.test(schema),
  "O schema passou a persistir material de chave privada."
);
requireCondition(
  !providerRegistry.includes("fallbackFake") && !providerRegistry.includes("fallbackToFake"),
  "O registry introduziu fallback explícito para provider fake."
);
```

A CA fake pode manter `KeyObject` privado em memória; o gate deve proibir persistência no schema e arquivos de migration, não a existência controlada do material efêmero dentro de `src/fake-pki`.

- [ ] **Step 5: Atualizar OpenAPI e documentação**

`docs/openapi.yaml`: manter integralmente os paths v1 e acrescentar schemas reutilizáveis `TrustMode`, `SignatureLevel`, `SignatureFormat`, `Participant` e `ProviderCapability`. Não anunciar ICP-Brasil real, PAdES/CAdES/XAdES real ou provider comercial como entregue.

`README.md`: corrigir o estado para “v0.1.0/D-009A encerrada; D-009B em evolução”; documentar que PKI FAKE é somente teste/desenvolvimento; manter comandos `security:check`, `check`, `test`, `build`.

`CHANGELOG.md`: adicionar `Unreleased / D-009B` com capability model, multi-participante, trust profiles e PKI FAKE, declarando expressamente que nenhum certificado emitido nesta etapa tem validade jurídica ou confiança pública.

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
git add src scripts docs README.md CHANGELOG.md
git commit -m "feat: complete D-009B universal trust foundation"
```

- [ ] **Step 8: Registrar evidência de aceite**

No PR/relatório de release, registrar resultados dos quatro gates, quantidade real de testes executados e os cenários PKI FAKE comprovados: válido, expirado, revogado, cadeia desconhecida, assinatura inválida, hash divergente e timestamp adulterado. Não declarar suporte produtivo ICP-Brasil ou a formatos criptográficos reais até as histórias D-009D–D-009G.

---

## Self-review do plano

- Cobertura da spec: capability registry, contratos separados, multi-participante, trust profiles, PKI FAKE, persistência aditiva, compatibilidade v1 e security gates estão mapeados às Tasks 1–7.
- O resultado de `SigningProvider` transporta `signedArtifact` opcional; isso permite providers assíncronos legados e a PKI FAKE síncrona no mesmo contrato.
- A migration segue o padrão real do repositório: SQL manual + journal, sem snapshot e sem aplicação em banco real.
- Tipos usados por tasks posteriores são definidos nas Tasks 1–3.
- A PKI FAKE mantém chave privada apenas em memória do componente de teste e é bloqueada por política em produção.
- O endpoint v1 e `SignatureProvider` legado permanecem preservados até depreciação futura explícita.
- Integração produtiva com provider real permanece deliberadamente fora do escopo da D-009B.
