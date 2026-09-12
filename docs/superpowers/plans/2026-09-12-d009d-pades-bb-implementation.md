# D-009D PAdES-B-B Implementation Plan

> **For agentic workers:** REQUIRED SUB-SKILL: Use superpowers:subagent-driven-development (recommended) or superpowers:executing-plans to implement this plan task-by-task. Steps use checkbox (`- [ ]`) syntax for tracking.

**Goal:** Entregar assinatura PDF PAdES-B-B real, validada criptograficamente, usando um sidecar Java/DSS isolado e credenciais FAKE/dev ou PKCS#12/PFX selecionadas por `tenantId + credentialRef`, sem expor material secreto ao core TypeScript.

**Architecture:** O core Node/TypeScript continua autoridade de tenant, TrustProfile, identidade, consentimento, autorização de credencial, workflow, storage e auditoria. Uma nova fronteira `CryptoFormatEngine` chama um sidecar Java via API interna multipart; o sidecar usa DSS para assinar/validar PAdES-B-B e devolve somente PDF e evidências sanitizadas. O documento original permanece imutável e cada assinatura gera uma nova revisão de artefato.

**Tech Stack:** Node.js >=24, TypeScript 5.9, Fastify 5, Zod 4, Vitest 3, Drizzle/PostgreSQL, Java 21, Maven, Spring Boot 4.1.1, DSS 6.5 (`dss-pades-pdfbox` + token/validation modules), Docker Compose, Poppler `pdfsig` apenas como verificador independente de aceite.

**Spec:** `docs/superpowers/specs/2026-09-12-d009d-pades-bb-design.md`

## Global Constraints

- Implementar somente PAdES-B-B neste ciclo; B-T/B-LT/B-LTA, CAdES, XAdES, ASiC, HSM/PKCS#11 e TSA ficam no backlog.
- FAKE/dev nunca pode operar em `production`; não criar fallback real -> fake.
- PAdES-B-B não implica, por si só, nível jurídico `simple`, `advanced` ou `qualified`.
- PKCS#12/PFX não implica confiança pública, ICP-Brasil ou assinatura qualificada.
- Chave privada, senha do PFX e bytes do keystore nunca transitam pelo core TypeScript e nunca são persistidos no banco.
- O sidecar não acessa object storage neste ciclo e não aceita URL/path arbitrário.
- `tenantId + credentialRef` é a chave de autorização/resolução de credencial; cross-tenant falha fechado e sem vazamento de existência.
- `documentSha256` existente representa a identidade do conteúdo original aceito/consentido. Assinaturas incrementais PAdES não alteram essa identidade de consentimento; cada revisão assinada possui `artifactSha256` próprio. Alteração real do documento original exige novo hash/readiness/consentimento.
- O documento original nunca é sobrescrito; cada participante assina a revisão anterior e produz uma nova revisão.
- Toda assinatura deve ser validada criptograficamente antes de ser promovida a `completed`.
- Migração D-009D estritamente aditiva e nunca aplicada automaticamente em produção/ambiente compartilhado.
- Respostas públicas e evidências nunca expõem stack trace, senha, private key, keystore bytes ou bearer/secret reutilizável.
- Commits pequenos; cada tarefa só é aprovada com testes específicos e regressão relevante GREEN.

---

## File Structure Locked for D-009D

### Core TypeScript

- `src/crypto/cryptoFormatEngine.ts` — tipos estáveis e interface de engine, independentes do DSS.
- `src/crypto/credentialPolicy.ts` — allowlist tenant-scoped de `credentialRef` e fail-closed.
- `src/crypto/dssCryptoFormatEngine.ts` — cliente HTTP/multipart do sidecar e tradução de erros.
- `src/crypto/*.test.ts` — testes unitários de contratos, allowlist, timeout, multipart e sanitização.
- `src/providers/providerContracts.ts` — extensão aditiva do `SigningInput` para bytes/revisão/credencial, preservando providers existentes.
- `src/providers/dssPadesSigningProvider.ts` — adapter `SigningProvider` -> `CryptoFormatEngine` para PAdES.
- `src/providers/dssPadesValidationProvider.ts` — adapter `ValidationProvider` -> `CryptoFormatEngine`.
- `src/signatures/universalTrustService.ts` — encadeamento de revisões por participante e validação antes de avanço.
- `src/signatures/universalTrustService.test.ts` — cadeia PDF0 -> PDF1 -> PDF2 e bloqueios.
- `src/db/schema.ts` — metadados aditivos de lineage/format/baseline/credencial/engine e vínculo de validação.
- `src/db/signatureRepository.ts` — contratos/repositório in-memory para artefatos/validações necessários ao fluxo.
- `src/db/signatureArtifactRepository.ts` — adapter Drizzle dedicado a artefatos e validações tenant-scoped.
- `src/db/*.d009d.test.ts` — testes de schema/migration/repository.
- `src/http/padesRoutes.ts` — superfície HTTP para iniciar execução PAdES com `credentialRef` autorizado.
- `src/http/padesRoutes.test.ts` — autenticação, strict payload, tenant isolation e erros estáveis.
- `src/app.ts` — registro opcional das rotas PAdES.
- `docs/openapi.yaml`, `README.md`, `CHANGELOG.md`, `scripts/security-regression-check.mjs` — fechamento documental/segurança.

### DSS sidecar

- `crypto-sidecar/pom.xml` — Java 21, Spring Boot 4.1.1, DSS 6.5 e testes.
- `crypto-sidecar/src/main/java/com/axesistemas/signature/crypto/CryptoSidecarApplication.java` — bootstrap.
- `.../config/CryptoProperties.java` — limites, auth interna e catálogo de credenciais.
- `.../security/InternalAuthFilter.java` — autenticação service-to-service sem log de secret.
- `.../credentials/CredentialCatalog.java` — resolução `tenantId + credentialRef`.
- `.../credentials/CredentialDescriptor.java` — metadados seguros.
- `.../pades/PadesController.java` — endpoints internos multipart.
- `.../pades/PadesSigningService.java` — assinatura DSS PAdES-B-B.
- `.../pades/PadesValidationService.java` — validação DSS e evidência sanitizada.
- `.../pades/PadesEvidence.java`, `PadesError.java` — contrato estável do sidecar.
- `crypto-sidecar/src/test/...` — testes de credencial, assinatura, validação, visual mode e segurança.
- `crypto-sidecar/Dockerfile` — imagem runtime Java não-root.

### Runtime/CI

- `compose.yaml` — core + sidecar; sidecar somente em rede interna.
- `.env.example` — apenas referências/configuração não secreta; senha real não commitada.
- `test/fixtures/pades/` — PDFs mínimos e material de teste não produtivo.
- `.github/workflows/quality.yml` — Node + Java + integração/artefato independente.

---

### Task 1: Core crypto contracts, content identity and credential policy

**Files:**
- Create: `src/crypto/cryptoFormatEngine.ts`
- Create: `src/crypto/credentialPolicy.ts`
- Create: `src/crypto/credentialPolicy.test.ts`
- Create: `src/crypto/cryptoFormatEngine.test.ts`
- Modify: `src/providers/providerContracts.ts`
- Modify: `src/signatures/universalTrustService.test.ts`

**Interfaces:**
- Produces `PadesBaseline = "B-B"`, `VisualSignatureMode = "none" | "standard"`.
- Produces `PadesSignInput`, `PadesSignResult`, `PadesValidationInput`, `PadesValidationResult` and `CryptoFormatEngine`.
- Produces `CredentialPolicy.assertAllowed(tenantId, credentialRef, trustMode): void`.
- Extends `SigningInput` additively with `tenantId`, `document`, `sourceDocumentSha256`, `credentialRef`, `baseline`, `visualSignature` as optional fields so FAKE detached tests remain source-compatible until Task 5.

- [ ] **Step 1: Write failing contract/policy tests**

```ts
it("fails closed when credentialRef is not allowed for tenant", () => {
  const policy = new CredentialPolicy([
    { tenantId: "tenant-a", credentialRef: "cert-a", trustMode: "production" },
  ]);

  expect(() => policy.assertAllowed("tenant-b", "cert-a", "production"))
    .toThrowError("CREDENTIAL_NOT_ALLOWED");
});

it("keeps source content hash distinct from signed artifact hash", () => {
  const sourceDocumentSha256 = "a".repeat(64);
  const artifactSha256 = "b".repeat(64);
  expect(sourceDocumentSha256).not.toBe(artifactSha256);
});
```

- [ ] **Step 2: Run RED**

Run: `corepack pnpm vitest run src/crypto/credentialPolicy.test.ts src/crypto/cryptoFormatEngine.test.ts`
Expected: FAIL because files/types do not exist.

- [ ] **Step 3: Implement minimal contracts**

`cryptoFormatEngine.ts` must define:

```ts
export type PadesBaseline = "B-B";
export type VisualSignatureMode = "none" | "standard";

export type PadesSignInput = {
  tenantId: string;
  requestId: string;
  participantId: string;
  credentialRef: string;
  trustMode: "fake" | "sandbox" | "production";
  sourceDocumentSha256: string;
  inputArtifactSha256: string;
  pdf: Buffer;
  baseline: PadesBaseline;
  visualSignature: VisualSignatureMode;
};

export type PadesSignResult = {
  operationId: string;
  signedPdf: Buffer;
  artifactSha256: string;
  trustMode: "fake" | "sandbox" | "production";
  engine: "DSS";
  engineVersion: string;
  certificate: {
    fingerprintSha256: string;
    serial: string;
    subject?: string;
    issuer?: string;
    notBefore: string;
    notAfter: string;
    signatureAlgorithm: string;
  };
};

export type PadesValidationInput = {
  tenantId: string;
  requestId: string;
  participantId: string;
  sourceDocumentSha256: string;
  artifactSha256: string;
  signedPdf: Buffer;
};

export type PadesValidationResult = {
  valid: boolean;
  code?: string;
  trustMode: "fake" | "sandbox" | "production";
  format: "pades";
  baseline: "B-B";
  evidence: Record<string, unknown>;
};

export interface CryptoFormatEngine {
  signPades(input: PadesSignInput): Promise<PadesSignResult>;
  validatePades(input: PadesValidationInput): Promise<PadesValidationResult>;
}
```

`CredentialPolicy` must compare exact tenant/ref/trustMode and throw only `CREDENTIAL_NOT_ALLOWED` on miss.

- [ ] **Step 4: Run GREEN + regression**

Run: `corepack pnpm vitest run src/crypto/credentialPolicy.test.ts src/crypto/cryptoFormatEngine.test.ts src/signatures/universalTrustService.test.ts`
Expected: PASS.

- [ ] **Step 5: Commit**

```bash
git add src/crypto src/providers/providerContracts.ts src/signatures/universalTrustService.test.ts
git commit -m "feat: define D-009D crypto engine contracts"
```

---

### Task 2: TypeScript DSS sidecar client

**Files:**
- Create: `src/crypto/dssCryptoFormatEngine.ts`
- Create: `src/crypto/dssCryptoFormatEngine.test.ts`

**Interfaces:**
- Consumes `CryptoFormatEngine` from Task 1.
- Constructor: `new DssCryptoFormatEngine({ baseUrl, serviceToken, timeoutMs, maxPdfBytes, fetchImpl? })`.
- `signPades()` calls `POST /internal/v1/pades/sign` multipart with parts `metadata` and `document`.
- `validatePades()` calls `POST /internal/v1/pades/validate` multipart with the same transport pattern.
- Header auth: `Authorization: Bearer <serviceToken>`; token never appears in error text.

- [ ] **Step 1: Write failing tests with fake fetch**

Cover: multipart contains PDF bytes, metadata excludes secrets, SHA mismatch rejects, 401/403 -> `CRYPTO_ENGINE_UNAVAILABLE`, timeout -> `CRYPTO_ENGINE_TIMEOUT`, structured sidecar error maps to stable domain code, unknown body -> `SIGNATURE_GENERATION_FAILED`/`SIGNATURE_VALIDATION_FAILED`.

- [ ] **Step 2: Run RED**

Run: `corepack pnpm vitest run src/crypto/dssCryptoFormatEngine.test.ts`
Expected: FAIL because adapter does not exist.

- [ ] **Step 3: Implement adapter**

Use native Node 24 `fetch`, `FormData`, `Blob`, `AbortSignal.timeout()`; recompute SHA-256 of returned PDF and require exact match with sidecar metadata before returning.

Error mapping must never include raw response body unless it matches the allowlisted error schema `{ code: string }`.

- [ ] **Step 4: Run GREEN**

Run: `corepack pnpm vitest run src/crypto/dssCryptoFormatEngine.test.ts`
Expected: PASS.

- [ ] **Step 5: Commit**

```bash
git add src/crypto/dssCryptoFormatEngine.ts src/crypto/dssCryptoFormatEngine.test.ts
git commit -m "feat: add DSS crypto sidecar client"
```

---

### Task 3: Secure Java sidecar bootstrap and credential catalog

**Files:**
- Create all bootstrap/config/security/credential files under `crypto-sidecar/` listed in File Structure.
- Create: `crypto-sidecar/src/test/java/com/axesistemas/signature/crypto/credentials/CredentialCatalogTest.java`
- Create: `crypto-sidecar/src/test/java/com/axesistemas/signature/crypto/security/InternalAuthFilterTest.java`

**Interfaces:**
- Internal base path `/internal/v1`.
- Config uses environment/property references; password values are read at runtime and never returned from getters used by observability DTOs.
- `CredentialCatalog.resolve(String tenantId, String credentialRef)` either returns one exact credential or throws `CREDENTIAL_NOT_FOUND` without cross-tenant detail.

- [ ] **Step 1: Create Maven project and failing tests**

`pom.xml` pins Java 21, Spring Boot 4.1.1 and DSS 6.5. Include `spring-boot-starter-web`, `spring-boot-starter-validation`, `dss-pades-pdfbox`, `dss-token`, `dss-validation`, and `spring-boot-starter-test`.

Test exact-match tenant isolation and auth header rejection.

- [ ] **Step 2: Run RED/compile**

Run: `mvn -f crypto-sidecar/pom.xml test`
Expected: initial tests fail until catalog/filter are implemented; dependency resolution must complete using official DSS 6.5 artifacts.

- [ ] **Step 3: Implement bootstrap/catalog/auth**

Credential configuration shape:

```yaml
axesistemas:
  crypto:
    max-pdf-bytes: 10485760
    internal-token: ${CRYPTO_INTERNAL_TOKEN}
    credentials:
      - tenant-id: tenant-dev
        credential-ref: fake-dev-01
        trust-mode: fake
        pkcs12-path: /run/secrets/fake-dev-01.p12
        password-env: FAKE_DEV_01_PASSWORD
```

Do not bind raw password into response DTOs. Read password by environment-name indirection at use time.

- [ ] **Step 4: Run GREEN**

Run: `mvn -f crypto-sidecar/pom.xml test`
Expected: PASS.

- [ ] **Step 5: Commit**

```bash
git add crypto-sidecar
git commit -m "feat: bootstrap secure DSS sidecar"
```

---

### Task 4: Real DSS PAdES-B-B signing, validation and optional visual appearance

**Files:**
- Create: `crypto-sidecar/src/main/java/com/axesistemas/signature/crypto/pades/PadesController.java`
- Create: `.../PadesSigningService.java`
- Create: `.../PadesValidationService.java`
- Create: `.../PadesEvidence.java`
- Create: `.../PadesError.java`
- Create tests under `crypto-sidecar/src/test/java/.../pades/`
- Create: `test/fixtures/pades/minimal.pdf`
- Create test-only PFX fixture generation script or JUnit setup; do not commit any production credential.

**Interfaces:**
- `POST /internal/v1/pades/sign`: multipart `metadata` JSON + `document` PDF.
- `POST /internal/v1/pades/validate`: multipart `metadata` JSON + `document` signed PDF.
- Sign response: multipart `metadata` sanitized JSON + `document` signed PDF.
- Validation response: JSON `valid`, `code?`, `trustMode`, `format`, `baseline`, `evidence`.

- [ ] **Step 1: Write RED tests**

Tests must assert:
- generated bytes start `%PDF-`;
- DSS signs with `SignatureLevel.PAdES_BASELINE_B` and SHA-256;
- returned PDF validates cryptographically;
- modified signed PDF fails validation;
- expired/not-yet-valid credential fails stable code;
- wrong hash -> `DOCUMENT_HASH_MISMATCH`;
- non-PDF -> `PDF_INVALID`;
- over limit -> `PDF_TOO_LARGE`;
- `visualSignature=none` signs without appearance requirement;
- `visualSignature=standard` adds a visible field while preserving cryptographic validity;
- response contains fingerprint/serial/validity/algorithm but no password/private key/keystore bytes.

- [ ] **Step 2: Run RED**

Run: `mvn -f crypto-sidecar/pom.xml -Dtest='*Pades*Test' test`
Expected: FAIL until DSS services exist.

- [ ] **Step 3: Implement signing**

Use `Pkcs12SignatureToken` to open the configured PKCS#12 inside the sidecar only. Build `PAdESSignatureParameters`, set `SignatureLevel.PAdES_BASELINE_B`, SHA-256, signing certificate and chain, then use `PAdESService` with PDFBox implementation to obtain data-to-sign, create `SignatureValue`, and produce the signed document.

For `standard` appearance, use DSS/PDFBox visible signature parameters with fixed safe defaults; no arbitrary template/path input.

- [ ] **Step 4: Implement validation**

Use DSS signed-document validation for the returned PDF, reduce DSS reports into stable `PadesEvidence`, and classify only allowlisted errors. Validation must verify the artifact bytes received, not a stored prior result.

- [ ] **Step 5: Run GREEN**

Run: `mvn -f crypto-sidecar/pom.xml test`
Expected: PASS.

- [ ] **Step 6: Commit**

```bash
git add crypto-sidecar test/fixtures/pades
git commit -m "feat: sign and validate PAdES-B-B with DSS"
```

---

### Task 5: PAdES providers and sequential artifact chaining in UniversalTrustService

**Files:**
- Create: `src/providers/dssPadesSigningProvider.ts`
- Create: `src/providers/dssPadesSigningProvider.test.ts`
- Create: `src/providers/dssPadesValidationProvider.ts`
- Create: `src/providers/dssPadesValidationProvider.test.ts`
- Modify: `src/signatures/universalTrustService.ts`
- Modify: `src/signatures/universalTrustService.test.ts`

**Interfaces:**
- `DssPadesSigningProvider` descriptor: kind `signing`, format `["pades"]`, baseline support B-B via engine contract, trustMode supplied by configured instance.
- `DssPadesValidationProvider` descriptor: kind `validation`, format `["pades"]`.
- `UniversalTrustExecutionInput` adds `credentialRefByParticipantId: Record<string,string>` and optional `visualSignatureByParticipantId`.
- Result adds final `artifactSha256` and per-participant revision metadata without changing `documentSha256` source-content identity.

- [ ] **Step 1: Write RED chaining tests**

Core scenario:

```text
source PDF hash = H0 (consent/readiness identity)
participant A signs bytes PDF0 -> PDF1 hash H1 -> validate PDF1
participant B signs bytes PDF1 -> PDF2 hash H2 -> validate PDF2
result.documentSha256 == H0
result.artifactSha256 == H2
H0 != H1 != H2
```

Assert participant B receives PDF1 bytes, not PDF0. Assert all readiness checks are evaluated against H0, not H1/H2. Assert missing credentialRef fails before provider call.

- [ ] **Step 2: Run RED**

Run: `corepack pnpm vitest run src/providers/dssPadesSigningProvider.test.ts src/providers/dssPadesValidationProvider.test.ts src/signatures/universalTrustService.test.ts`
Expected: FAIL on missing PAdES providers/chaining.

- [ ] **Step 3: Implement adapters and chaining**

Inside `UniversalTrustService`, maintain:

```ts
let currentArtifact = Buffer.from(input.document);
let currentArtifactSha256 = createHash("sha256").update(currentArtifact).digest("hex");
```

For each participant: resolve exact credential, sign current artifact, validate returned signed artifact, then assign signed bytes as `currentArtifact` for the next participant. Do not change source `documentSha256` used by identity/consent readiness.

- [ ] **Step 4: Run GREEN + D-009B/C regression**

Run: `corepack pnpm test`
Expected: all existing tests plus new PAdES tests PASS.

- [ ] **Step 5: Commit**

```bash
git add src/providers src/signatures
git commit -m "feat: chain validated PAdES revisions per participant"
```

---

### Task 6: Additive persistence for artifact lineage and validation evidence

**Files:**
- Modify: `src/db/schema.ts`
- Create: `src/db/schema.d009d.test.ts`
- Create: `src/db/signatureArtifactRepository.ts`
- Create: `src/db/signatureArtifactRepository.test.ts`
- Modify: `src/db/signatureRepository.ts` only if needed for shared evidence interface
- Create: `drizzle/0003_d009d_pades_artifacts.sql`
- Modify: `drizzle/meta/_journal.json`

**Interfaces:**
- `signature_artifacts` additions: `source_artifact_id`, `format`, `baseline`, `credential_ref`, `input_sha256`, `certificate_fingerprint_sha256`, `certificate_serial`, `signature_algorithm`, `engine`, `engine_version`, `signed_at`.
- `validation_results` addition: `signature_artifact_id`.
- Repository methods always require `tenantId` and never query by artifact id alone.

- [ ] **Step 1: Write RED schema/repository tests**

Assert all new columns exist, all reads include tenant, immutable inserts do not update prior artifacts, `validation_results.signatureArtifactId` must reference the selected artifact in repository API, and secret-like columns (`password`, `private_key`, `keystore`, `pfx_bytes`) do not exist.

- [ ] **Step 2: Run RED**

Run: `corepack pnpm vitest run src/db/schema.d009d.test.ts src/db/signatureArtifactRepository.test.ts`
Expected: FAIL.

- [ ] **Step 3: Implement schema/repository**

Keep migration CREATE/ALTER ADD COLUMN/CREATE INDEX only; no DROP/RENAME/DELETE/UPDATE data migration. Add tenant+request and tenant+artifact indexes where reads require them.

- [ ] **Step 4: Verify migration text and GREEN**

Run: `corepack pnpm vitest run src/db/schema.d009d.test.ts src/db/signatureArtifactRepository.test.ts`
Run: `corepack pnpm security:check`
Expected: PASS; migration remains unapplied.

- [ ] **Step 5: Commit**

```bash
git add src/db drizzle
git commit -m "feat: persist PAdES artifact lineage and validation"
```

---

### Task 7: Public PAdES execution API with strict tenant authority

**Files:**
- Create: `src/http/padesRoutes.ts`
- Create: `src/http/padesRoutes.test.ts`
- Modify: `src/app.ts`
- Modify: `docs/openapi.yaml`

**Interfaces:**
- Endpoint: `POST /v1/signature-requests/:requestId/pades/execute`.
- Body:

```json
{
  "credentialRefs": {
    "participant-1": "tenant-a-cert-01"
  },
  "visualSignature": "none"
}
```

- `tenantId`, document hashes, trustMode and storage keys are server-resolved and rejected if caller tries to supply them because schema is strict.
- The route receives injected resolvers/service dependencies; no direct DB access from route.

- [ ] **Step 1: Write RED API tests**

Cover 401/403, invalid requestId, missing credential mapping, cross-tenant not found, caller-provided `tenantId` rejected, caller-provided hash rejected, unallowed credential -> stable 403/422 mapping without existence leak, engine timeout -> 503, successful execution returns source `documentSha256`, final `artifactSha256`, status and safe validation summary only.

- [ ] **Step 2: Run RED**

Run: `corepack pnpm vitest run src/http/padesRoutes.test.ts`
Expected: FAIL.

- [ ] **Step 3: Implement route and app registration**

Follow existing `authenticatedContext()` pattern from `signatureRoutes.ts`; reuse `resolveAuthIdentity` and tenant context. Keep route registration optional so legacy app tests still build without D-009D dependencies.

- [ ] **Step 4: Run GREEN + all HTTP tests**

Run: `corepack pnpm vitest run src/http/*.test.ts`
Expected: PASS.

- [ ] **Step 5: Commit**

```bash
git add src/http src/app.ts docs/openapi.yaml
git commit -m "feat: expose tenant-safe PAdES execution API"
```

---

### Task 8: Docker Compose, end-to-end flow and independent interoperability validation

**Files:**
- Create: `compose.yaml`
- Create: `crypto-sidecar/Dockerfile`
- Modify: `Dockerfile` only if core runtime networking/health support needs explicit adjustment
- Modify: `.env.example`
- Create: `test/integration/pades-compose.test.mjs` or shell equivalent invoked by CI
- Modify: `.github/workflows/quality.yml`

**Interfaces:**
- Compose exposes core port to host; sidecar has no host `ports:` mapping, only internal network/expose.
- PFX test fixture is mounted read-only as a secret/test volume.
- Core receives only `CRYPTO_SIDECAR_URL`, `CRYPTO_INTERNAL_TOKEN`, timeout/size configuration; never PFX/password.

- [ ] **Step 1: Add failing CI/integration script**

The script must fail until compose can:
1. start sidecar health;
2. sign `minimal.pdf` through the real core adapter;
3. validate through DSS;
4. write resulting PDF to temporary CI workspace;
5. run `pdfsig` against that artifact and assert at least one cryptographic signature is recognized;
6. mutate a copy and assert product/DSS validation fails.

- [ ] **Step 2: Run RED locally/CI-equivalent**

Run: `docker compose -f compose.yaml up --build -d`
Run integration script.
Expected: FAIL before runtime wiring is complete.

- [ ] **Step 3: Implement containers and workflow**

Use multi-stage Maven build and Java 21 runtime, non-root user. Extend GitHub Actions with Java setup and `mvn -f crypto-sidecar/pom.xml test`; install/use `poppler-utils` only in CI interoperability step, not product image.

- [ ] **Step 4: Run GREEN**

Run:

```bash
corepack pnpm security:check
corepack pnpm check
corepack pnpm test
corepack pnpm build
mvn -f crypto-sidecar/pom.xml test
docker compose -f compose.yaml up --build -d
node test/integration/pades-compose.test.mjs
docker compose -f compose.yaml down -v
```

Expected: all GREEN; `pdfsig` recognizes the produced PDF signature.

- [ ] **Step 5: Commit**

```bash
git add compose.yaml Dockerfile crypto-sidecar/Dockerfile .env.example test/integration .github/workflows/quality.yml
git commit -m "test: verify PAdES flow across core and DSS sidecar"
```

---

### Task 9: Security gate, documentation, final verification and PR

**Files:**
- Modify: `scripts/security-regression-check.mjs`
- Modify: `README.md`
- Modify: `CHANGELOG.md`
- Modify: `docs/openapi.yaml` if final API examples need synchronization
- Create: `docs/operations/d009d-pades-sidecar.md`

**Interfaces:**
- Security gate must fail if secrets appear in schema/migrations, fake provider becomes production-capable, sidecar gets public compose port, migration contains destructive SQL, or PAdES completion can occur without validation.

- [ ] **Step 1: Extend security regression checks first**

Add assertions for:
- no `password|private_key|keystore_bytes|pfx_bytes` columns;
- `0003` contains no `DROP TABLE`, `DROP COLUMN`, `RENAME COLUMN`, destructive data statements;
- compose sidecar has no public port mapping;
- source contains readiness-before-signing and validation-before-completed patterns;
- fake credential/provider remains `trustMode: fake`;
- public HTTP schema does not accept tenantId/documentSha256/artifactSha256/storageKey.

- [ ] **Step 2: Run security gate**

Run: `corepack pnpm security:check`
Expected: PASS only after all D-009D invariants are present.

- [ ] **Step 3: Complete docs**

README/operations must explain:
- FAKE/dev vs PFX;
- secret mounting and password-env indirection;
- `credentialRef` allowlist;
- source content hash vs artifact revision hash;
- PAdES-B-B scope and explicit non-claims;
- how to run compose and tests;
- how to inspect safe certificate metadata;
- migration versioned but not auto-applied;
- backlog B-T/LT/LTA, CAdES/XAdES/ASiC/HSM.

- [ ] **Step 4: Fresh full verification**

Run all commands from Task 8 Step 4 from clean checkout. Record exact counts/results in PR body. Do not claim success from stale earlier runs.

- [ ] **Step 5: Inline diff review**

Review `main...feature/d009d-pades-bb` for unrelated changes, secret leakage, accidental production fake fallback, API authority mistakes and migration destructiveness. Fix findings with a new RED/GREEN cycle when behavior changes.

- [ ] **Step 6: Open PR without merging**

PR title: `feat: D-009D real PAdES-B-B signing`

PR body must include scope, security boundaries, test evidence, independent `pdfsig` check, migration-not-applied statement, non-goals and exact HEAD SHA. Do not auto-merge; wait for explicit user approval.

- [ ] **Step 7: Commit docs/closure**

```bash
git add scripts/security-regression-check.mjs README.md CHANGELOG.md docs
git commit -m "docs: close D-009D PAdES delivery"
```

---

## Plan Self-Review Result

- **Spec coverage:** architecture, PAdES-B-B, DSS sidecar, FAKE/PFX, tenant credential allowlist, streaming/multipart, service auth, artifact lineage, persistence, visual mode, mandatory validation, Docker, independent interoperability, security and docs all map to Tasks 1-9.
- **Scope control:** B-T/B-LT/B-LTA, TSA, CAdES/XAdES/ASiC, HSM/PKCS#11, direct storage access and distributed rate limiting have no implementation task.
- **Type consistency:** `sourceDocumentSha256` is immutable content identity; `inputArtifactSha256`/`artifactSha256` are revision identities. `credentialRef` is always tenant-scoped and never resolves without policy.
- **Compatibility:** legacy FAKE detached flow remains available only under its existing allowed profile; new PAdES dependencies are injected/optional until explicitly configured.
- **No production action:** no migration application, credential provisioning or deployment is part of the plan.
