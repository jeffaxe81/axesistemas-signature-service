# D-009C Identity & Consent Implementation Plan

> **For agentic workers:** REQUIRED SUB-SKILL: Use superpowers:subagent-driven-development (recommended) or superpowers:executing-plans to implement this plan task-by-task. Steps use checkbox (`- [ ]`) syntax for tracking.

**Goal:** Build the provider-agnostic D-009C identity verification and consent foundation so policy-required participants must authenticate and consent to the exact document before the existing universal signing flow can proceed.

**Architecture:** Extend the D-009B Policy + Ports/Adapters model with a dedicated identity/consent domain. `IdentityConsentService` owns challenge lifecycle, assurance evaluation, consent binding, evidence emission and readiness; providers only perform provider-specific verification/consent actions. `UniversalTrustService` consumes readiness through an optional dependency so legacy D-009A/D-009B behavior remains unchanged when no identity policy is configured.

**Tech Stack:** Node.js >=24, TypeScript 5.9, Fastify 5, Zod 4, Drizzle ORM 0.44/PostgreSQL, Vitest 3, pnpm 10.15.

**Spec:** `docs/superpowers/specs/2026-09-12-d009c-identity-consent-design.md`

## Global Constraints

- Authentication, consent and document signing are independent concerns; authentication MUST NOT infer legal signature level.
- FAKE/local providers are for development, QA and homologation only and MUST declare `trustMode: "fake"`.
- Provider selection MUST be authorized by both the active `TrustProfile` and active `IdentityPolicy`; approval by only one layer is insufficient.
- Unknown/unsupported method, assurance, provider or trust-mode combinations MUST fail closed; no automatic downgrade is allowed.
- Challenge replay, expiration and attempt exhaustion are domain/service responsibilities, not provider shortcuts.
- No plaintext OTP, TOTP secret, password, private key, bearer token, refresh token or other reusable secret may be persisted.
- Consent MUST bind to exact `tenantId`, `requestId`, `participantId`, `identityEvidenceId`, `documentSha256` and `statementHash`.
- Accepted/declined consent is immutable; corrections create a new record.
- Every operational persistence table MUST be tenant-scoped.
- Database changes MUST be additive only; D-009C does not apply migrations to production.
- Existing `/v1/signature-requests` behavior MUST remain compatible when no D-009C policy is configured.
- No real Gov.br, production OIDC, SMS/e-mail delivery, browser WebAuthn, production biometrics, ICP-Brasil, real PAdES/CAdES/XAdES/ASiC, HSM or PKCS#11 is delivered by D-009C.

---

## File Structure

Create focused modules rather than extending one large file:

- `src/identity/identityPolicy.ts` — authentication method/assurance policy model and fail-closed policy helpers.
- `src/identity/identitySession.ts` — challenge lifecycle and replay/TTL/attempt state machine.
- `src/identity/identityEvidence.ts` — immutable normalized successful-verification evidence type.
- `src/identity/identityConsentRepository.ts` — persistence port plus in-memory implementation used by unit/service tests.
- `src/identity/identityConsentService.ts` — application orchestration for start/complete/readiness.
- `src/consent/consentRecord.ts` — immutable consent domain and document/identity binding rules.
- `src/providers/fakeIdentityProvider.ts` — deterministic FAKE provider outcomes only.
- `src/providers/fakeConsentProvider.ts` — deterministic FAKE consent outcomes only.
- `src/http/identityConsentRoutes.ts` — additive D-009C HTTP endpoints.
- `src/security/challengeRateLimiter.ts` — endpoint-specific rate-limit port and in-memory implementation.
- `src/db/identityConsentRepository.ts` — PostgreSQL/Drizzle adapter for D-009C persistence.
- `drizzle/0002_d009c_identity_consent.sql` — additive D-009C migration.

Modify only where integration is required:

- `src/providers/providerContracts.ts`
- `src/signatures/participant.ts`
- `src/signatures/domain.ts`
- `src/signatures/universalTrustService.ts`
- `src/fake-pki/testFactory.ts`
- `src/db/schema.ts`
- `src/app.ts`
- `scripts/security-regression-check.mjs`
- `docs/openapi.yaml`
- `README.md`
- `CHANGELOG.md`
- `drizzle/meta/_journal.json`

---

### Task 1: Identity policy, assurance and challenge lifecycle

**Files:**
- Create: `src/identity/identityPolicy.ts`
- Create: `src/identity/identityPolicy.test.ts`
- Create: `src/identity/identitySession.ts`
- Create: `src/identity/identitySession.test.ts`
- Create: `src/identity/identityEvidence.ts`
- Modify: `src/signatures/domain.ts`
- Modify: `src/signatures/domain.test.ts`

**Interfaces:**
- Consumes: `TrustMode` and `ProviderDescriptor` from `src/trust/capabilities.ts`; existing D-009B universal signature status model.
- Produces:

```ts
export type AuthenticationMethod =
  | "fake"
  | "email_otp"
  | "sms_otp"
  | "totp"
  | "oidc"
  | "webauthn"
  | "biometric"
  | "govbr";

export type IdentityAssurance = "basic" | "strong" | "high";

export type IdentityPolicy = {
  id: string;
  identityRequired: boolean;
  consentRequired: boolean;
  allowedMethods: AuthenticationMethod[];
  minimumAssurance: IdentityAssurance;
  allowedProviderIds: string[] | "*";
  challengeTtlSeconds: number;
  maxChallengeAttempts: number;
  identityEvidenceMaxAgeSeconds?: number;
  consentMaxAgeSeconds?: number;
};

export type IdentitySessionStatus =
  | "created"
  | "challenge_pending"
  | "verified"
  | "denied"
  | "expired"
  | "failed";

export type IdentitySession = {
  tenantId: string;
  id: string;
  requestId: string;
  participantId: string;
  providerId: string;
  method: AuthenticationMethod;
  purpose: "document-signing";
  status: IdentitySessionStatus;
  challengeId: string;
  challengeDigest: string;
  expiresAt: Date;
  attemptCount: number;
  maxAttempts: number;
  createdAt: Date;
  updatedAt: Date;
  completedAt?: Date;
};

export type IdentityEvidence = {
  tenantId: string;
  id: string;
  requestId: string;
  participantId: string;
  identitySessionId: string;
  providerId: string;
  method: AuthenticationMethod;
  assurance: IdentityAssurance;
  acr?: string;
  amr?: string[];
  externalSubjectHash?: string;
  verifiedAt: Date;
  providerEvidence: Record<string, unknown>;
  createdAt: Date;
};
```

- [ ] **Step 1: Write failing policy tests**

Create `src/identity/identityPolicy.test.ts` with concrete expectations:

```ts
import { describe, expect, it } from "vitest";
import {
  assertAssuranceSatisfied,
  assertIdentityProviderAllowed,
  type IdentityPolicy,
} from "./identityPolicy.js";

const policy: IdentityPolicy = {
  id: "fake-standard",
  identityRequired: true,
  consentRequired: true,
  allowedMethods: ["fake"],
  minimumAssurance: "strong",
  allowedProviderIds: ["fake-identity"],
  challengeTtlSeconds: 300,
  maxChallengeAttempts: 3,
};

describe("IdentityPolicy", () => {
  it("accepts assurance at or above the configured minimum", () => {
    expect(() => assertAssuranceSatisfied(policy, "strong")).not.toThrow();
    expect(() => assertAssuranceSatisfied(policy, "high")).not.toThrow();
  });

  it("rejects an assurance downgrade", () => {
    expect(() => assertAssuranceSatisfied(policy, "basic"))
      .toThrowError("IDENTITY_ASSURANCE_INSUFFICIENT");
  });

  it("rejects methods and providers not allowed by policy", () => {
    expect(() =>
      assertIdentityProviderAllowed(policy, {
        id: "other-provider",
        version: "0.1.0",
        kind: "identity",
        trustMode: "fake",
        levels: ["simple"],
        formats: ["detached"],
      }, "fake")
    ).toThrowError("TRUST_POLICY_VIOLATION");
  });
});
```

- [ ] **Step 2: Run policy test to verify RED**

Run:

```bash
pnpm vitest run src/identity/identityPolicy.test.ts
```

Expected: FAIL because `identityPolicy.ts` does not exist.

- [ ] **Step 3: Implement policy helpers minimally**

Create `src/identity/identityPolicy.ts`. Use explicit assurance ordering:

```ts
const assuranceRank: Record<IdentityAssurance, number> = {
  basic: 1,
  strong: 2,
  high: 3,
};

export function assertAssuranceSatisfied(
  policy: IdentityPolicy,
  achieved: IdentityAssurance
): void {
  if (assuranceRank[achieved] < assuranceRank[policy.minimumAssurance]) {
    throw new Error("IDENTITY_ASSURANCE_INSUFFICIENT");
  }
}

export function assertIdentityProviderAllowed(
  policy: IdentityPolicy,
  provider: ProviderDescriptor,
  method: AuthenticationMethod
): void {
  if (provider.kind !== "identity") throw new Error("TRUST_POLICY_VIOLATION");
  if (!policy.allowedMethods.includes(method)) throw new Error("TRUST_POLICY_VIOLATION");
  if (policy.allowedProviderIds !== "*" && !policy.allowedProviderIds.includes(provider.id)) {
    throw new Error("TRUST_POLICY_VIOLATION");
  }
}
```

Do not duplicate `TrustProfile` trust-mode checks here; Task 4 will require both policy layers before provider invocation.

- [ ] **Step 4: Write failing identity session state-machine tests**

Create `src/identity/identitySession.test.ts` covering:

```ts
it("expires a pending session after its TTL", () => {
  const now = new Date("2026-09-12T18:00:00Z");
  const session = createIdentitySession({
    tenantId: "tenant-a",
    id: "session-1",
    requestId: "request-1",
    participantId: "participant-1",
    providerId: "fake-identity",
    method: "fake",
    challengeId: "challenge-1",
    challengeDigest: "digest",
    now,
    ttlSeconds: 60,
    maxAttempts: 3,
  });

  expect(() => assertSessionUsable(session, new Date("2026-09-12T18:01:01Z")))
    .toThrowError("IDENTITY_CHALLENGE_EXPIRED");
});

it("rejects replay after a session is verified", () => {
  const verified = transitionIdentitySession(baseSession, "verified", now);
  expect(() => assertSessionUsable(verified, now))
    .toThrowError("IDENTITY_REPLAY_DETECTED");
});

it("rejects a session after max attempts", () => {
  const exhausted = { ...baseSession, attemptCount: 3, maxAttempts: 3 };
  expect(() => assertSessionUsable(exhausted, now))
    .toThrowError("IDENTITY_CHALLENGE_INVALID");
});
```

- [ ] **Step 5: Run identity session tests to verify RED**

Run:

```bash
pnpm vitest run src/identity/identitySession.test.ts
```

Expected: FAIL because session functions do not exist.

- [ ] **Step 6: Implement the session lifecycle and immutable evidence type**

Implement `createIdentitySession`, `incrementIdentityAttempt`, `assertSessionUsable`, and `transitionIdentitySession` in `src/identity/identitySession.ts`. Rules:

```ts
const terminal: IdentitySessionStatus[] = ["verified", "denied", "expired", "failed"];

export function assertSessionUsable(session: IdentitySession, now: Date): void {
  if (session.status === "verified") throw new Error("IDENTITY_REPLAY_DETECTED");
  if (terminal.includes(session.status)) throw new Error("IDENTITY_CHALLENGE_INVALID");
  if (now.getTime() > session.expiresAt.getTime()) throw new Error("IDENTITY_CHALLENGE_EXPIRED");
  if (session.attemptCount >= session.maxAttempts) throw new Error("IDENTITY_CHALLENGE_INVALID");
}
```

State transitions must allow only:

```text
created -> challenge_pending | failed
challenge_pending -> verified | denied | expired | failed
verified/denied/expired/failed -> no transition
```

Create `src/identity/identityEvidence.ts` exporting only the immutable data type plus `createIdentityEvidence(input)` returning `Object.freeze(...)` at the top level.

- [ ] **Step 7: Add universal global states without changing legacy behavior**

Modify `src/signatures/domain.ts` to add `"awaiting_identity"` and `"awaiting_consent"` to `UniversalSignatureStatus`. Extend `src/signatures/domain.test.ts` only to assert the new states are accepted in the universal model; do not change `SignatureStatus` or D-009A transitions.

- [ ] **Step 8: Run task tests and static check**

Run:

```bash
pnpm vitest run src/identity/identityPolicy.test.ts src/identity/identitySession.test.ts src/signatures/domain.test.ts
pnpm check
```

Expected: all PASS.

- [ ] **Step 9: Commit Task 1**

```bash
git add src/identity src/signatures/domain.ts src/signatures/domain.test.ts
git commit -m "feat: add D-009C identity policy and session domain"
```

---

### Task 2: Evolve provider contracts and add deterministic FAKE providers

**Files:**
- Modify: `src/providers/providerContracts.ts`
- Create: `src/providers/fakeIdentityProvider.ts`
- Create: `src/providers/fakeIdentityProvider.test.ts`
- Create: `src/providers/fakeConsentProvider.ts`
- Create: `src/providers/fakeConsentProvider.test.ts`

**Interfaces:**
- Consumes: `AuthenticationMethod`, `IdentityAssurance`, `ProviderDescriptor`.
- Produces:

```ts
export type BeginIdentityVerificationInput = {
  tenantId: string;
  requestId: string;
  participantId: string;
  method: AuthenticationMethod;
};

export type BeginIdentityVerificationResult = {
  providerSessionId: string;
  challengeId: string;
  clientData: Record<string, unknown>;
  evidence: Record<string, unknown>;
};

export type CompleteIdentityVerificationInput = {
  tenantId: string;
  requestId: string;
  participantId: string;
  providerSessionId: string;
  challengeId: string;
  response: Record<string, unknown>;
};

export type CompleteIdentityVerificationResult = {
  verified: boolean;
  denied?: boolean;
  assurance?: IdentityAssurance;
  acr?: string;
  amr?: string[];
  externalSubject?: string;
  evidence: Record<string, unknown>;
};

export interface IdentityProvider {
  readonly descriptor: ProviderDescriptor;
  beginVerification(input: BeginIdentityVerificationInput): Promise<BeginIdentityVerificationResult>;
  completeVerification(input: CompleteIdentityVerificationInput): Promise<CompleteIdentityVerificationResult>;
}

export type RecordConsentInput = {
  tenantId: string;
  requestId: string;
  participantId: string;
  identityEvidenceId: string;
  documentSha256: string;
  statementHash: string;
  decision: "accepted" | "declined";
};

export interface ConsentProvider {
  readonly descriptor: ProviderDescriptor;
  record(input: RecordConsentInput): Promise<{
    recorded: boolean;
    evidence: Record<string, unknown>;
  }>;
}
```

- [ ] **Step 1: Write failing contract/provider tests**

`fakeIdentityProvider.test.ts` must verify:

```ts
it("returns deterministic FAKE verification evidence", async () => {
  const provider = new FakeIdentityProvider({ assurance: "strong" });
  const begin = await provider.beginVerification({
    tenantId: "tenant-a",
    requestId: "request-1",
    participantId: "participant-1",
    method: "fake",
  });

  const result = await provider.completeVerification({
    tenantId: "tenant-a",
    requestId: "request-1",
    participantId: "participant-1",
    providerSessionId: begin.providerSessionId,
    challengeId: begin.challengeId,
    response: { answer: "FAKE-OK" },
  });

  expect(result.verified).toBe(true);
  expect(result.assurance).toBe("strong");
  expect(provider.descriptor.trustMode).toBe("fake");
});
```

Also test response `FAKE-DENY`, invalid answer, insufficient configured assurance, and deterministic provider failure configured with `{ fail: true }`.

`fakeConsentProvider.test.ts` must verify accepted, declined and configured provider failure; descriptor kind must be `consent`, trustMode `fake`.

- [ ] **Step 2: Run tests to verify RED**

```bash
pnpm vitest run src/providers/fakeIdentityProvider.test.ts src/providers/fakeConsentProvider.test.ts
```

Expected: FAIL because providers/new contract methods do not exist.

- [ ] **Step 3: Evolve `providerContracts.ts`**

Replace only the unused D-009B one-shot identity `verify()` contract with the two-phase interface above. Expand `ConsentProvider.record()` to use `RecordConsentInput`. Do not change `SigningProvider`, `ValidationProvider` or `TimestampProvider` signatures.

- [ ] **Step 4: Implement `FakeIdentityProvider`**

Use deterministic in-memory state only. The provider may retain its own provider-session map for the test process, but MUST NOT decide TTL, replay or max attempts.

Required behavior:

```ts
const VALID_ANSWER = "FAKE-OK";
const DENY_ANSWER = "FAKE-DENY";
```

`beginVerification()` returns opaque deterministic IDs generated with `randomUUID()` and client data `{ prompt: "Enter FAKE-OK" }`.

`completeVerification()`:
- throws `IDENTITY_PROVIDER_UNAVAILABLE` when provider configured `fail: true`;
- returns `{ verified: false, denied: true }` for `FAKE-DENY`;
- returns `{ verified: false }` for any other invalid answer;
- returns configured assurance for `FAKE-OK`.

Never emit reusable secrets.

- [ ] **Step 5: Implement `FakeConsentProvider`**

`record()` throws `IDENTITY_PROVIDER_UNAVAILABLE` only when configured failure is enabled; otherwise returns `{ recorded: true, evidence: { provider: "fake-consent", decision: input.decision } }`.

- [ ] **Step 6: Run provider tests plus legacy provider tests**

```bash
pnpm vitest run src/providers/fakeIdentityProvider.test.ts src/providers/fakeConsentProvider.test.ts src/providers/legacySignatureProviderAdapter.test.ts
pnpm check
```

Expected: all PASS; legacy signing adapter unchanged.

- [ ] **Step 7: Commit Task 2**

```bash
git add src/providers
git commit -m "feat: add D-009C identity and consent provider contracts"
```

---

### Task 3: Consent domain and readiness rules

**Files:**
- Create: `src/consent/consentRecord.ts`
- Create: `src/consent/consentRecord.test.ts`
- Create: `src/identity/readiness.ts`
- Create: `src/identity/readiness.test.ts`
- Modify: `src/signatures/participant.ts`
- Modify: `src/signatures/participant.test.ts`

**Interfaces:**
- Consumes: `IdentityPolicy`, `IdentityEvidence`, existing `Participant`.
- Produces:

```ts
export type ConsentDecision = "accepted" | "declined";
export type ConsentStatus = "pending" | "accepted" | "declined" | "expired";

export type ConsentRecord = {
  tenantId: string;
  id: string;
  requestId: string;
  participantId: string;
  identityEvidenceId: string;
  documentSha256: string;
  statementHash: string;
  decision: ConsentDecision;
  status: ConsentStatus;
  providerId: string;
  acceptedAt?: Date;
  declinedAt?: Date;
  expiresAt?: Date;
  providerEvidence: Record<string, unknown>;
  createdAt: Date;
};

export type ParticipantReadiness =
  | "awaiting_identity"
  | "awaiting_consent"
  | "ready_to_sign";
```

- [ ] **Step 1: Write failing consent binding tests**

Create tests proving:

```ts
expect(() => assertConsentMatches({
  consent,
  tenantId: "tenant-a",
  requestId: "request-1",
  participantId: "participant-1",
  identityEvidenceId: "evidence-1",
  documentSha256: "changed-hash",
  statementHash: consent.statementHash,
  now,
})).toThrowError("CONSENT_DOCUMENT_MISMATCH");
```

Also assert:
- different identity evidence -> `CONSENT_IDENTITY_MISMATCH`;
- different tenant/request/participant -> `CROSS_TENANT_ACCESS_DENIED` for tenant mismatch, `CONSENT_IDENTITY_MISMATCH` for same-tenant context mismatch;
- changed `statementHash` -> `CONSENT_DOCUMENT_MISMATCH`;
- expired accepted consent -> `CONSENT_REQUIRED`;
- accepted and declined records cannot transition again -> `CONSENT_ALREADY_FINALIZED`.

- [ ] **Step 2: Run consent tests to verify RED**

```bash
pnpm vitest run src/consent/consentRecord.test.ts
```

Expected: FAIL because consent domain does not exist.

- [ ] **Step 3: Implement consent domain**

Implement `createConsentRecord`, `assertConsentMatches`, and `transitionConsentStatus`. Final states `accepted`, `declined`, `expired` are immutable. `createConsentRecord` returns a frozen top-level object.

- [ ] **Step 4: Write failing readiness tests**

Create `src/identity/readiness.test.ts` covering exactly:

```ts
it("returns awaiting_identity when policy requires identity and none exists", () => {
  expect(evaluateReadiness({
    policy,
    participant,
    documentSha256: "doc",
    statementHash: "statement",
    identityEvidence: undefined,
    consent: undefined,
    now,
  })).toBe("awaiting_identity");
});

it("returns awaiting_consent after valid identity when consent is required", () => {
  expect(evaluateReadiness({ ...base, identityEvidence, consent: undefined }))
    .toBe("awaiting_consent");
});

it("returns ready_to_sign only when identity and consent match current document", () => {
  expect(evaluateReadiness({ ...base, identityEvidence, consent }))
    .toBe("ready_to_sign");
});
```

Also test identity evidence max age and consent max age when configured.

- [ ] **Step 5: Implement readiness evaluation**

`evaluateReadiness()` MUST derive the result each call; do not store a `ready` Boolean. Validate tenant/request/participant, assurance, evidence age, consent status/hash/age and policy requirements in order.

If `identityRequired === false` and `consentRequired === false`, return `ready_to_sign` without evidence.

If `consentRequired === true`, identity evidence is required even if `identityRequired` is false, because consent is bound to authenticated identity.

- [ ] **Step 6: Tighten participant transitions**

Keep existing transitions but ensure the intended happy path remains valid:

```text
invited/pending -> authenticated -> consented -> signed
```

Do not add a direct `pending -> consented` transition. Add a test proving it throws `INVALID_PARTICIPANT_TRANSITION`.

- [ ] **Step 7: Run domain tests**

```bash
pnpm vitest run src/consent/consentRecord.test.ts src/identity/readiness.test.ts src/signatures/participant.test.ts
pnpm check
```

Expected: all PASS.

- [ ] **Step 8: Commit Task 3**

```bash
git add src/consent src/identity/readiness.ts src/identity/readiness.test.ts src/signatures/participant.ts src/signatures/participant.test.ts
git commit -m "feat: add consent binding and participant readiness"
```

---

### Task 4: IdentityConsentService with repository and evidence ports

**Files:**
- Create: `src/identity/identityConsentRepository.ts`
- Create: `src/identity/identityConsentService.ts`
- Create: `src/identity/identityConsentService.test.ts`
- Modify: `src/evidence/evidenceStore.ts` only if a reusable append port already exists; otherwise keep the D-009C event sink local to the service interfaces and do not refactor unrelated evidence code.

**Interfaces:**
- Consumes: Tasks 1-3 domain types; `ProviderRegistry`; `TrustProfile`; evolved `IdentityProvider`/`ConsentProvider`.
- Produces:

```ts
export interface IdentityConsentRepository {
  saveSession(session: IdentitySession): Promise<void>;
  getSession(tenantId: string, sessionId: string): Promise<IdentitySession | undefined>;
  saveIdentityEvidence(evidence: IdentityEvidence): Promise<void>;
  getLatestIdentityEvidence(
    tenantId: string,
    requestId: string,
    participantId: string
  ): Promise<IdentityEvidence | undefined>;
  saveConsent(consent: ConsentRecord): Promise<void>;
  getLatestConsent(
    tenantId: string,
    requestId: string,
    participantId: string
  ): Promise<ConsentRecord | undefined>;
}

export interface IdentityAuditSink {
  append(input: {
    tenantId: string;
    requestId: string;
    participantId: string;
    type: string;
    payload: Record<string, unknown>;
  }): Promise<void>;
}

export type IdentityConsentServiceDependencies = {
  registry: ProviderRegistry;
  repository: IdentityConsentRepository;
  audit: IdentityAuditSink;
  now: () => Date;
  randomId: () => string;
};
```

Also export `InMemoryIdentityConsentRepository` from `identityConsentRepository.ts` for deterministic tests only.

- [ ] **Step 1: Write failing start-verification tests**

Test that `startIdentityVerification()`:
- rejects identity provider not allowed by `TrustProfile`;
- rejects identity provider not allowed by `IdentityPolicy`;
- creates a `challenge_pending` session with policy TTL/max attempts;
- stores only a digest of provider challenge data, not `FAKE-OK` or any response value;
- emits `identity.challenge.created`.

Use a fixed `now` and `randomId` in tests.

- [ ] **Step 2: Run start tests to verify RED**

```bash
pnpm vitest run src/identity/identityConsentService.test.ts -t "start identity verification"
```

Expected: FAIL because service/repository do not exist.

- [ ] **Step 3: Implement repository port/in-memory adapter and `startIdentityVerification()`**

Service signature:

```ts
async startIdentityVerification(input: {
  tenantId: string;
  requestId: string;
  participant: Participant;
  trustProfile: TrustProfile;
  identityPolicy: IdentityPolicy;
  method: AuthenticationMethod;
}): Promise<{
  sessionId: string;
  challengeId: string;
  clientData: Record<string, unknown>;
}>;
```

Resolve provider via `registry.resolve("identity", trustProfile, { level: "simple", format: "detached" })`, then apply `assertIdentityProviderAllowed(identityPolicy, provider.descriptor, input.method)` before invocation. This deliberately requires both policy layers.

Hash provider challenge continuation material with SHA-256 before storing `challengeDigest`; never persist raw client response secrets.

- [ ] **Step 4: Write failing completion tests**

Mandatory service-level tests:
- valid response creates immutable `IdentityEvidence`, marks session verified, emits `identity.verified`;
- invalid response increments attempts and emits `identity.challenge.failed`;
- expired session fails before provider completion call;
- verified session replay fails before provider completion call;
- max attempts fails before provider completion call;
- assurance below policy throws `IDENTITY_ASSURANCE_INSUFFICIENT` and creates no evidence;
- cross-tenant session lookup is rejected/not found and cannot be completed;
- provider external subject is persisted only as SHA-256 hash, never raw value.

- [ ] **Step 5: Implement `completeIdentityVerification()`**

Signature:

```ts
async completeIdentityVerification(input: {
  tenantId: string;
  requestId: string;
  participant: Participant;
  trustProfile: TrustProfile;
  identityPolicy: IdentityPolicy;
  sessionId: string;
  response: Record<string, unknown>;
}): Promise<IdentityEvidence>;
```

Order is security-sensitive:
1. load same-tenant session;
2. verify request/participant match;
3. call `assertSessionUsable()`;
4. resolve and authorize provider under both policies;
5. invoke provider;
6. on invalid response increment/store attempt before returning `IDENTITY_CHALLENGE_INVALID`;
7. on denied result transition/store `denied` and return `IDENTITY_CHALLENGE_INVALID`;
8. verify assurance;
9. create/store evidence and transition/store session `verified`;
10. emit sanitized event.

- [ ] **Step 6: Write failing consent/readiness service tests**

Test:
- consent without evidence -> `IDENTITY_REQUIRED`;
- evidence from another participant/request -> `CONSENT_IDENTITY_MISMATCH`;
- changed document -> `CONSENT_DOCUMENT_MISMATCH` when checking existing consent;
- accepted consent creates immutable record and emits `consent.accepted`;
- declined consent creates final record and emits `consent.declined` but readiness stays `awaiting_consent`/not signable;
- `evaluateParticipantReadiness()` derives current result from repository state and current hashes.

- [ ] **Step 7: Implement `recordConsent()` and `evaluateParticipantReadiness()`**

Signatures:

```ts
async recordConsent(input: {
  tenantId: string;
  requestId: string;
  participant: Participant;
  trustProfile: TrustProfile;
  identityPolicy: IdentityPolicy;
  documentSha256: string;
  statement: string;
  decision: ConsentDecision;
}): Promise<ConsentRecord>;

async evaluateParticipantReadiness(input: {
  tenantId: string;
  requestId: string;
  participant: Participant;
  identityPolicy: IdentityPolicy;
  documentSha256: string;
  statementHash: string;
}): Promise<ParticipantReadiness>;
```

Normalize consent statement for hashing as `statement.trim().replace(/\r\n/g, "\n")`, then SHA-256 UTF-8 bytes. Do not silently lower-case or collapse spaces because that would change visible legal text semantics.

Resolve/authorize consent provider through `TrustProfile` plus `IdentityPolicy.allowedProviderIds` before calling `record()`.

- [ ] **Step 8: Run service suite and static check**

```bash
pnpm vitest run src/identity/identityConsentService.test.ts
pnpm check
```

Expected: all PASS.

- [ ] **Step 9: Commit Task 4**

```bash
git add src/identity/identityConsentRepository.ts src/identity/identityConsentService.ts src/identity/identityConsentService.test.ts
git commit -m "feat: add D-009C identity consent orchestration"
```

---

### Task 5: Gate UniversalTrustService on D-009C readiness

**Files:**
- Modify: `src/signatures/universalTrustService.ts`
- Modify: `src/signatures/universalTrustService.test.ts`
- Modify: `src/fake-pki/testFactory.ts`
- Create or modify: `src/fake-pki/identityConsentTestFactory.ts` if keeping D-009C test setup separate makes `testFactory.ts` exceed one responsibility.

**Interfaces:**
- Consumes: `IdentityConsentService.evaluateParticipantReadiness`, `IdentityPolicy`.
- Produces optional integration that leaves existing callers unchanged:

```ts
export type IdentityReadinessDependency = {
  service: IdentityConsentService;
  resolvePolicy(input: {
    tenantId: string;
    requestId: string;
    participantId: string;
  }): Promise<IdentityPolicy | undefined>;
  resolveStatementHash(input: {
    tenantId: string;
    requestId: string;
    participantId: string;
  }): Promise<string>;
};

export type UniversalTrustServiceDependencies = {
  registry: ProviderRegistry;
  identityReadiness?: IdentityReadinessDependency;
};
```

- [ ] **Step 1: Write failing readiness-gate tests**

Add to `universalTrustService.test.ts`:

```ts
it("returns awaiting_identity before calling signing provider", async () => {
  const result = await service.execute(inputWithIdentityPolicy);
  expect(result.status).toBe("awaiting_identity");
  expect(fakeSigning.signCalls).toBe(0);
});

it("returns awaiting_consent after authentication before signing", async () => {
  // complete FAKE identity first, leave consent absent
  const result = await service.execute(inputWithIdentityPolicy);
  expect(result.status).toBe("awaiting_consent");
  expect(fakeSigning.signCalls).toBe(0);
});

it("signs only after identity and accepted consent satisfy current document", async () => {
  // start+complete identity, record accepted consent for current document
  const result = await service.execute(inputWithIdentityPolicy);
  expect(result.status).toBe("completed");
  expect(fakeSigning.signCalls).toBe(1);
});
```

Keep existing tests proving no D-009C dependency still reaches `completed` under D-009B behavior.

- [ ] **Step 2: Run universal service tests to verify RED**

```bash
pnpm vitest run src/signatures/universalTrustService.test.ts
```

Expected: new tests FAIL while existing D-009B tests remain green.

- [ ] **Step 3: Implement optional readiness gate**

Before resolving/calling `SigningProvider`, for each participant:
1. if no `identityReadiness` dependency, preserve current D-009B path exactly;
2. resolve policy; if `undefined`, preserve D-009B path for that participant;
3. compute readiness using the already computed `documentSha256` and resolved statement hash;
4. return `awaiting_identity` or `awaiting_consent` immediately without invoking signing;
5. only `ready_to_sign` proceeds to signing.

Do not duplicate identity/consent rules inside `UniversalTrustService`.

- [ ] **Step 4: Extend FAKE integration factory**

Provide a test factory that creates:
- fake identity provider;
- fake consent provider;
- existing fake signing/validation/timestamp providers;
- one `ProviderRegistry` containing all of them;
- in-memory identity/consent repository;
- deterministic audit sink;
- `IdentityConsentService`.

- [ ] **Step 5: Add one end-to-end service-level FAKE path**

Test sequence:

```text
execute -> awaiting_identity
startIdentityVerification
completeIdentityVerification with FAKE-OK
execute -> awaiting_consent
recordConsent accepted for current document and statement
execute -> completed
```

Then change the document bytes and prove a new `execute` returns `awaiting_consent` rather than signing with the old consent.

- [ ] **Step 6: Run universal and regression tests**

```bash
pnpm vitest run src/signatures/universalTrustService.test.ts src/fake-pki/fakePki.test.ts src/http/signatureRoutes.test.ts src/signatures/signatureService.test.ts
pnpm check
```

Expected: all PASS.

- [ ] **Step 7: Commit Task 5**

```bash
git add src/signatures src/fake-pki
git commit -m "feat: gate universal signing on identity and consent readiness"
```

---

### Task 6: Add tenant-scoped persistence and additive migration

**Files:**
- Modify: `src/db/schema.ts`
- Create: `src/db/schema.d009c.test.ts`
- Create: `src/db/identityConsentRepository.ts`
- Create: `src/db/identityConsentRepository.test.ts`
- Create: `drizzle/0002_d009c_identity_consent.sql`
- Modify: `drizzle/meta/_journal.json`

**Interfaces:**
- Consumes: `IdentityConsentRepository` port and D-009C domain records.
- Produces: `DrizzleIdentityConsentRepository` implementing the port with mandatory tenant filters.

- [ ] **Step 1: Write failing structural schema tests**

Create `src/db/schema.d009c.test.ts` and assert exported tables:

```ts
import {
  consentRecords,
  identityEvidences,
  identitySessions,
} from "./schema.js";

it("exports the three D-009C tenant-scoped tables", () => {
  expect(identitySessions).toBeDefined();
  expect(identityEvidences).toBeDefined();
  expect(consentRecords).toBeDefined();
});
```

Also read migration text in the test and assert it contains `CREATE TABLE "identity_sessions"`, `CREATE TABLE "identity_evidences"`, `CREATE TABLE "consent_records"` and does not match `/\b(DROP|TRUNCATE)\b|ALTER\s+TABLE[\s\S]*DROP/i`.

- [ ] **Step 2: Run schema test to verify RED**

```bash
pnpm vitest run src/db/schema.d009c.test.ts
```

Expected: FAIL because tables/migration do not exist.

- [ ] **Step 3: Add Drizzle table definitions**

Add tables with composite tenant-aware primary keys `[tenantId, id]` and indexes:

```text
identity_sessions_tenant_request_participant_idx
identity_evidences_tenant_request_participant_idx
consent_records_tenant_request_participant_idx
```

`identity_sessions` columns must include `challenge_digest` but MUST NOT include `otp`, `password`, `token`, `refresh_token`, `private_key`, `secret`, or raw challenge response columns.

Use `jsonb` only for sanitized provider evidence/client metadata; no opaque raw provider response dump field.

- [ ] **Step 4: Create additive SQL migration and journal entry**

Create `drizzle/0002_d009c_identity_consent.sql` manually following the established D-009B migration style because the repository currently has no committed Drizzle schema snapshot. Use only `CREATE TABLE` and `CREATE INDEX` for D-009C.

Append exactly one journal entry to `drizzle/meta/_journal.json` with:

```json
{
  "idx": 2,
  "version": "7",
  "when": 1789240000000,
  "tag": "0002_d009c_identity_consent",
  "breakpoints": true
}
```

Do not run the migration against a production or shared database.

- [ ] **Step 5: Write failing repository isolation tests**

Create `identityConsentRepository.test.ts` using the same database test strategy already used by `signatureRepository.test.ts` or a deterministic adapter fake if no DB fixture is configured. Mandatory cases:
- tenant A cannot load tenant B session by ID;
- tenant A cannot retrieve tenant B evidence/consent;
- latest evidence/consent queries filter tenant + request + participant together;
- saved provider evidence does not contain raw external subject or challenge response.

- [ ] **Step 6: Implement `DrizzleIdentityConsentRepository`**

Every query MUST include `tenantId` in its `where` clause. Mapping functions must convert database timestamps into `Date` and return domain objects without mutating persisted JSON.

Do not change `signatureRepository.ts` unless shared database typing requires an additive import.

- [ ] **Step 7: Run schema/repository tests and migration safety checks**

```bash
pnpm vitest run src/db/schema.d009c.test.ts src/db/identityConsentRepository.test.ts src/db/signatureRepository.test.ts
pnpm check
```

Expected: all PASS.

- [ ] **Step 8: Commit Task 6**

```bash
git add src/db drizzle/0002_d009c_identity_consent.sql drizzle/meta/_journal.json
git commit -m "feat: add D-009C tenant scoped persistence"
```

---

### Task 7: Add HTTP endpoints, error normalization and challenge rate limiting

**Files:**
- Create: `src/security/challengeRateLimiter.ts`
- Create: `src/security/challengeRateLimiter.test.ts`
- Create: `src/http/identityConsentRoutes.ts`
- Create: `src/http/identityConsentRoutes.test.ts`
- Modify: `src/app.ts`

**Interfaces:**
- Consumes: `IdentityConsentService`, existing `ResolveAuthIdentity`/tenant context pattern from `signatureRoutes.ts`.
- Produces:

```ts
export interface ChallengeRateLimiter {
  consume(key: string, now: Date): { allowed: true } | { allowed: false; retryAfterSeconds: number };
}

export type IdentityConsentRouteOptions = {
  service: IdentityConsentService;
  resolveAuthIdentity: ResolveAuthIdentity;
  resolveParticipant(input: {
    tenantId: string;
    requestId: string;
    participantId: string;
  }): Promise<Participant | undefined>;
  resolveTrustProfile(requestId: string): Promise<TrustProfile>;
  resolveIdentityPolicy(requestId: string, participantId: string): Promise<IdentityPolicy>;
  resolveDocumentSha256(requestId: string): Promise<string>;
  resolveConsentStatement(requestId: string, participantId: string): Promise<string>;
  rateLimiter: ChallengeRateLimiter;
};
```

- [ ] **Step 1: Write failing rate limiter tests**

Implement an in-memory fixed-window limiter with constructor:

```ts
new InMemoryChallengeRateLimiter({ limit: 5, windowSeconds: 60 })
```

Tests: first five calls for same key allowed, sixth denied with positive retryAfter; different tenant/participant key independent; calls after window reset allowed.

- [ ] **Step 2: Run limiter test to verify RED**

```bash
pnpm vitest run src/security/challengeRateLimiter.test.ts
```

Expected: FAIL because limiter does not exist.

- [ ] **Step 3: Implement the limiter**

No external dependency. Key format in routes MUST include tenant, request, participant and operation:

```text
${tenantId}:${requestId}:${participantId}:identity-start
${tenantId}:${requestId}:${participantId}:identity-complete
```

This implementation is process-local and suitable for the current single-process service foundation; README must note that production distributed rate limiting is future deployment hardening.

- [ ] **Step 4: Write failing route tests**

Create tests using Fastify injection for all four endpoints:

```text
POST /v1/signature-requests/:requestId/participants/:participantId/identity-sessions
POST /v1/signature-requests/:requestId/participants/:participantId/identity-sessions/:sessionId/complete
POST /v1/signature-requests/:requestId/participants/:participantId/consents
GET  /v1/signature-requests/:requestId/participants/:participantId/readiness
```

Mandatory assertions:
- missing/invalid auth -> same 401/403 tenant-context behavior as existing signature routes;
- body-provided `tenantId` is rejected/ignored; tenant always comes from auth context;
- invalid params/body -> 400 with stable domain error;
- rate limit -> 429 and `retryAfterSeconds`;
- cross-tenant lookup never exposes whether a foreign record exists;
- start returns only `sessionId`, `challengeId`, `clientData`;
- completion response never contains provider raw tokens/secrets;
- consent accepts `{ statement, decision }`, document hash is resolved server-side rather than trusted from request body;
- readiness returns one of the three stable readiness values.

- [ ] **Step 5: Implement schemas and normalized error mapping**

Use strict Zod objects. Map known errors without leaking provider messages:

```ts
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
```

For unknown errors return `500 { error: "IDENTITY_CONSENT_INTERNAL_ERROR" }`; do not send `error.message` from unknown/provider errors.

- [ ] **Step 6: Wire routes into `buildApp()` additively**

Extend `BuildAppOptions` with optional D-009C route options. Register identity/consent routes only when the complete D-009C option object is supplied. Existing `buildApp({ signatureService, resolveAuthIdentity })` tests must remain unchanged and green.

- [ ] **Step 7: Run HTTP and legacy regression tests**

```bash
pnpm vitest run src/security/challengeRateLimiter.test.ts src/http/identityConsentRoutes.test.ts src/http/signatureRoutes.test.ts
pnpm check
```

Expected: all PASS.

- [ ] **Step 8: Commit Task 7**

```bash
git add src/security/challengeRateLimiter.ts src/security/challengeRateLimiter.test.ts src/http/identityConsentRoutes.ts src/http/identityConsentRoutes.test.ts src/app.ts
git commit -m "feat: expose D-009C identity and consent API"
```

---

### Task 8: Security regression gate, OpenAPI/docs and full verification

**Files:**
- Modify: `scripts/security-regression-check.mjs`
- Modify: `docs/openapi.yaml`
- Modify: `README.md`
- Modify: `CHANGELOG.md`
- Modify tests only when needed to fix a verified defect; do not weaken assertions to make CI green.

**Interfaces:**
- Consumes: all D-009C delivered behavior.
- Produces: final cycle evidence suitable for PR review.

- [ ] **Step 1: Extend security regression gate with D-009C structural checks**

Add checks that fail when:
- D-009C migration contains `DROP`/`TRUNCATE`/destructive drop;
- `identity_sessions`, `identity_evidences`, `consent_records` are missing `tenant_id`;
- schema/migration introduces obvious secret-bearing columns matching `/(plain.*otp|password|refresh.*token|private.*key|totp.*secret|bearer.*token)/i`;
- fake identity/consent providers are not `trustMode: "fake"`;
- source contains a fallback path named like `fallbackFake`, `fallbackToFake`, `allowFakeInProduction`;
- `UniversalTrustService` can call signing in readiness tests before identity/consent.

Keep all existing D-009A/D-009B security checks.

- [ ] **Step 2: Run security gate to verify it catches a controlled negative fixture or current code passes only after all D-009C protections exist**

Run:

```bash
pnpm security:check
```

Expected final state: PASS with a message including D-009C tenant isolation, replay protection, fake-provider isolation and secret-persistence guard.

- [ ] **Step 3: Update OpenAPI additively**

Document the four D-009C endpoints and reusable schemas:

```text
AuthenticationMethod
IdentityAssurance
IdentitySessionStartResponse
IdentityCompletionRequest
ConsentRequest
ParticipantReadiness
DomainError
```

Descriptions MUST explicitly state:
- method availability does not imply production adapter delivery;
- authentication assurance does not determine legal signature level;
- FAKE methods are non-production only.

Do not remove or rename existing `/v1/signature-requests` paths.

- [ ] **Step 4: Update README and CHANGELOG**

README must document:
- D-009C flow and boundaries;
- FAKE identity/consent usage for dev/QA only;
- process-local rate limiter caveat;
- no real Gov.br/OIDC/WebAuthn/biometric delivery yet;
- migration is versioned but not automatically applied to production.

CHANGELOG `[Unreleased]` must list D-009C identity sessions, assurance, immutable consent, readiness gating, additive persistence/API and FAKE providers without claiming legal signature support.

- [ ] **Step 5: Run focused full FAKE journey test**

Run the exact test covering:

```text
awaiting_identity
-> challenge created
-> FAKE-OK verified
-> awaiting_consent
-> accepted consent for exact document/statement
-> ready_to_sign
-> fake signature
-> validation
-> completed
```

Then assert changed document returns to `awaiting_consent` before any new signing call.

- [ ] **Step 6: Run the complete quality suite**

```bash
pnpm security:check
pnpm check
pnpm test
pnpm build
```

Expected: all four commands PASS. Record the final Vitest file/test counts in the PR body rather than hard-coding an expected count in source documentation.

- [ ] **Step 7: Review diff for scope and secret leakage**

Run:

```bash
git diff main...HEAD --stat
git diff main...HEAD -- src/identity src/consent src/providers src/signatures src/db src/http src/security scripts drizzle docs README.md CHANGELOG.md
```

Reviewer checklist:
- no unrelated refactor;
- no real external provider credentials/configuration;
- no private keys/tokens/OTP values in committed fixtures;
- no fake fallback into sandbox/production;
- no destructive migration;
- legacy v1 route behavior preserved.

- [ ] **Step 8: Commit final docs/security closure**

```bash
git add scripts/security-regression-check.mjs docs/openapi.yaml README.md CHANGELOG.md
git commit -m "docs: complete D-009C identity consent foundation"
```

- [ ] **Step 9: Push implementation branch and open PR without auto-merge**

Use an implementation branch based on the approved design branch, recommended name:

```text
feature/d009c-identity-consent
```

PR title:

```text
feat: D-009C identity and consent foundation
```

PR body must include:
- delivered capabilities;
- FAKE-only boundaries;
- security properties;
- migration-not-applied statement;
- `security:check`, `check`, test and build evidence;
- explicit non-goals;
- final HEAD SHA.

Do not merge to `main` until explicit user approval after PR checks/review.

---

## Plan Self-Review Result

### Spec coverage

Every D-009C requirement maps to a task:

- methods/assurance/policy: Task 1;
- challenge lifecycle/replay/TTL/attempts: Tasks 1 and 4;
- provider ports and FAKE adapters: Task 2;
- consent binding/immutability/readiness: Task 3;
- orchestration/audit/provider dual-policy authorization: Task 4;
- UniversalTrustService readiness gating and complete FAKE path: Task 5;
- tenant persistence/additive migration: Task 6;
- HTTP/rate limiting/error normalization: Task 7;
- security regression, OpenAPI, README, CHANGELOG and full regression: Task 8.

### Placeholder scan

No `TBD`, `TODO`, generic “add validation/error handling”, or undefined implementation steps remain in this plan.

### Type consistency

The plan consistently uses `AuthenticationMethod`, `IdentityAssurance`, `IdentityPolicy`, `IdentitySession`, `IdentityEvidence`, `ConsentRecord`, `ParticipantReadiness`, `IdentityConsentRepository`, `IdentityAuditSink`, `IdentityConsentService`, and the two-phase `IdentityProvider` contract across all tasks.
