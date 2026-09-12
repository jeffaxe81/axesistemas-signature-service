# D-009C — Identity & Consent Design

## Status

Proposed and approved in design review on 2026-09-12. This document defines the implementation boundary for D-009C and extends the D-009B Universal Trust foundation without replacing the legacy v1 signature flow.

## 1. Context

D-009B established a universal trust foundation with independent provider contracts, trust profiles, multi-participant signature state, fail-closed provider selection, tenant-scoped persistence, FAKE PKI infrastructure, and a `UniversalTrustService` that orchestrates signing, timestamping and validation.

D-009C introduces the layer that must execute before a participant is allowed to sign when policy requires identity verification and/or explicit consent.

The central rule is that authentication, consent and document signature are different concerns:

- authentication establishes evidence about who completed an identity challenge;
- consent records what the authenticated participant accepted for a specific document;
- signing applies the cryptographic or provider-specific signature mechanism;
- validation determines whether the produced artifact satisfies the configured trust policy.

A strong login is not itself a qualified document signature. D-009C therefore does not infer legal signature level from authentication method alone.

## 2. Goals

D-009C MUST:

1. provide a provider-agnostic identity verification domain;
2. provide a provider-agnostic consent domain;
3. separate authentication assurance from signature level;
4. bind consent to the exact document hash and authenticated identity evidence;
5. prevent challenge replay and cross-tenant evidence reuse;
6. support FAKE/local providers for development, QA and homologation;
7. prepare extension points for OTP, TOTP, OIDC/SSO, WebAuthn/passkeys, biometrics and Gov.br adapters;
8. preserve D-009A/D-009B compatibility;
9. keep trust-mode enforcement fail-closed;
10. persist only evidence needed for audit and policy evaluation, not reusable secrets.

## 3. Non-goals

D-009C does NOT deliver:

- real Gov.br integration;
- a production OIDC server/provider integration;
- real email or SMS delivery;
- browser WebAuthn/passkey ceremonies;
- production biometric integration;
- production ICP-Brasil certificate issuance or validation;
- real PAdES, CAdES, XAdES or ASiC engines;
- HSM or PKCS#11 integration;
- production database migration execution;
- production deployment;
- a claim of legal validity based only on authentication method.

Those capabilities remain future adapter/provider work and MUST NOT be represented as delivered by D-009C.

## 4. Architectural approach

D-009C adopts **Policy + Ports/Adapters + Evidence Ledger**.

Identity and consent remain separate domains and are orchestrated by `IdentityConsentService`. This avoids creating a provider contract that couples identity verification, user consent and document signing into one vendor-specific action.

High-level flow:

```text
participant
  -> IdentityPolicy
  -> IdentityConsentService
      -> IdentityProvider
      -> IdentityEvidence
      -> ConsentProvider
      -> ConsentRecord
  -> readiness evaluation
  -> UniversalTrustService
      -> SigningProvider
      -> TimestampProvider (when required)
      -> ValidationProvider
```

The service MUST evaluate policy before allowing signing to start.

## 5. Domain model

### 5.1 AuthenticationMethod

The domain MUST support an extensible authentication method identifier. The initial known methods are:

- `fake`
- `email_otp`
- `sms_otp`
- `totp`
- `oidc`
- `webauthn`
- `biometric`
- `govbr`

These are capability identifiers. Their presence in the enum/model does not imply that a production adapter exists.

### 5.2 IdentityAssurance

Authentication assurance is independent from `SignatureLevel`.

D-009C defines the internal assurance scale:

- `basic`
- `strong`
- `high`

Providers MAY additionally return normalized provider metadata such as `acr`, `amr`, provider assurance level or an external assurance identifier.

A provider-specific assurance MUST be normalized before policy evaluation. The internal assurance classification is an Axesistemas policy abstraction, not an automatic legal classification.

### 5.3 IdentitySession

`IdentitySession` represents one verification attempt lifecycle.

Required logical fields:

- `tenantId`
- `id`
- `requestId`
- `participantId`
- `providerId`
- `method`
- `purpose`
- `status`
- `challengeId`
- `challengeDigest` or equivalent non-reusable verification material
- `expiresAt`
- `attemptCount`
- `maxAttempts`
- `createdAt`
- `updatedAt`
- `completedAt` when terminal

Valid states:

```text
created -> challenge_pending -> verified
                           \-> denied
                           \-> expired
                           \-> failed
```

Terminal sessions MUST NOT be reusable.

The service MUST reject replay when a completed or consumed challenge is submitted again.

### 5.4 IdentityEvidence

`IdentityEvidence` is the normalized, audit-safe result of a successful verification.

Required logical fields:

- `tenantId`
- `id`
- `requestId`
- `participantId`
- `identitySessionId`
- `providerId`
- `method`
- `assurance`
- optional normalized `acr`
- optional normalized `amr`
- optional pseudonymized external subject identifier
- `verifiedAt`
- sanitized provider evidence
- `createdAt`

Identity evidence MUST be immutable after creation, except for a future explicit revocation/supersession mechanism outside D-009C.

### 5.5 ConsentRecord

A consent is valid only for the exact content and authenticated identity to which it was bound.

Required logical fields:

- `tenantId`
- `id`
- `requestId`
- `participantId`
- `identityEvidenceId`
- `documentSha256`
- `statementHash`
- `decision`
- `status`
- `providerId`
- `acceptedAt` or `declinedAt`
- `expiresAt` when policy defines expiry
- sanitized provider evidence
- `createdAt`

Consent state:

```text
pending -> accepted
        \-> declined
        \-> expired
```

An accepted or declined consent is final and MUST NOT be silently overwritten. A corrected or updated consent requires a new record.

If either `documentSha256` or `statementHash` changes, the previous consent MUST NOT satisfy readiness for the new content.

## 6. IdentityPolicy

`TrustProfile` continues to govern trust mode, allowed providers, signature levels and formats. D-009C introduces a separate `IdentityPolicy` to avoid mixing authentication policy with cryptographic signature policy.

An `IdentityPolicy` SHOULD contain at least:

- `id`
- allowed authentication methods;
- minimum required `IdentityAssurance`;
- whether identity verification is required;
- whether explicit consent is required;
- consent statement identifier/version or hash input;
- optional identity evidence maximum age;
- optional consent maximum age;
- max challenge attempts;
- challenge TTL;
- allowed provider IDs or provider selection constraints.

Policy resolution MUST remain fail-closed. An unknown or unsupported method, assurance, provider or trust-mode combination MUST NOT downgrade to a weaker method automatically.

A provider is usable only when it satisfies **both** layers: the active `TrustProfile` MUST allow its trust mode/provider identity and the active `IdentityPolicy` MUST allow its identity/consent use. Approval by only one layer is insufficient.

## 7. Provider contracts

### 7.1 IdentityProvider

The D-009B one-shot `verify()` contract is insufficient for real challenge-based mechanisms. D-009C evolves the identity port to two phases.

Conceptual contract:

```ts
interface IdentityProvider {
  readonly descriptor: ProviderDescriptor;

  beginVerification(input: BeginIdentityVerificationInput): Promise<BeginIdentityVerificationResult>;

  completeVerification(input: CompleteIdentityVerificationInput): Promise<CompleteIdentityVerificationResult>;
}
```

`beginVerification()` MUST return only the client-facing continuation data necessary for the method, for example a challenge identifier, redirect metadata or instructions.

`completeVerification()` MUST return a normalized result containing verification success/failure, achieved assurance and sanitized provider evidence.

Provider responses MUST NOT bypass domain replay, expiration or tenant checks.

### 7.2 ConsentProvider

Consent input MUST include full context rather than only a statement hash.

Conceptual input:

```ts
type RecordConsentInput = {
  tenantId: string;
  requestId: string;
  participantId: string;
  identityEvidenceId: string;
  documentSha256: string;
  statementHash: string;
  decision: "accepted" | "declined";
};
```

The provider returns a normalized outcome and sanitized evidence. The domain remains responsible for determining whether the consent satisfies policy.

## 8. FAKE/local providers

D-009C MUST add:

- `FakeIdentityProvider`
- `FakeConsentProvider`

Both providers MUST declare `trustMode: "fake"` and MUST be rejected by sandbox or production profiles.

The FAKE identity provider MUST support deterministic provider outcomes for:

- successful verification;
- invalid response;
- denied verification;
- insufficient assurance;
- provider failure.

Expiration, replay detection and attempt exhaustion are responsibilities of `IdentitySession`/`IdentityConsentService` and MUST be tested there. The FAKE provider MUST NOT implement a shortcut that bypasses those protections.

The FAKE consent provider MUST support:

- accepted consent;
- declined consent;
- provider failure;
- evidence generation.

The FAKE implementation MUST still execute through the same state machine, policy evaluation, TTL and replay protections as a future real provider. Tests MUST NOT use a bypass path that marks a participant authenticated or consented directly.

## 9. IdentityConsentService

`IdentityConsentService` is the application-level orchestrator for the new domain.

Required operations:

- `startIdentityVerification(...)`
- `completeIdentityVerification(...)`
- `recordConsent(...)`
- `evaluateParticipantReadiness(...)`

### 9.1 Start identity verification

The service MUST:

1. resolve tenant/request/participant context;
2. resolve `IdentityPolicy`;
3. resolve an allowed identity provider using the existing fail-closed provider registry model;
4. create an `IdentitySession`;
5. generate or request the challenge;
6. store only non-reusable challenge verification material;
7. append an audit evidence event;
8. return the client-facing continuation payload.

### 9.2 Complete identity verification

The service MUST:

1. resolve the session in the same tenant/request/participant context;
2. reject terminal, expired or exhausted sessions;
3. reject replay;
4. invoke the provider completion flow;
5. normalize the result;
6. compare achieved assurance to policy;
7. create immutable `IdentityEvidence` only when policy requirements are satisfied;
8. transition participant state to `authenticated` when appropriate;
9. append an audit evidence event.

### 9.3 Record consent

The service MUST:

1. require valid identity evidence for the same tenant/request/participant;
2. verify document hash equality;
3. compute or verify `statementHash` from the exact consent statement presented;
4. invoke the allowed consent provider when configured;
5. create an immutable consent record;
6. transition participant state to `consented` only for accepted consent that satisfies policy;
7. append an audit evidence event.

### 9.4 Readiness

Readiness is a derived policy decision, not a manually persisted Boolean.

Possible readiness outcomes:

- `awaiting_identity`
- `awaiting_consent`
- `ready_to_sign`

The service MUST evaluate current document hash, active policy, participant state, identity evidence and consent records on each decision.

## 10. UniversalTrustService integration

Today D-009B can proceed directly to a `SigningProvider`. D-009C inserts readiness evaluation before signing whenever an identity policy applies.

Conceptual flow:

```text
resolve TrustProfile
resolve IdentityPolicy
for each participant:
  evaluate readiness
  if awaiting_identity -> return global awaiting_identity
  if awaiting_consent -> return global awaiting_consent
  if ready_to_sign -> continue D-009B signing flow
```

The universal signature domain MUST add `awaiting_identity` and `awaiting_consent` as explicit global states.

Existing states such as `awaiting_participants`, `partially_completed`, `validating`, `completed`, `rejected`, `expired`, `cancelled` and `failed` remain valid.

When no D-009C policy is configured, the legacy/D-009B flow MUST continue to operate without requiring identity or consent.

## 11. Persistence

D-009C adds only additive schema changes.

New tables:

### `identity_sessions`

Tenant-scoped. Stores session state, provider/method identifiers, expiration, counters and non-reusable challenge verification material.

### `identity_evidences`

Tenant-scoped. Stores normalized, immutable authentication evidence without reusable secrets.

### `consent_records`

Tenant-scoped. Stores immutable consent decisions bound to participant, identity evidence, document hash and statement hash.

Every operational table MUST include `tenant_id` and use tenant-aware keys/indexes consistent with D-009B.

The migration MUST NOT drop, truncate or destructively alter D-009A/D-009B tables.

The migration is versioned only in this cycle; applying it to a production database is outside scope.

## 12. Evidence ledger

D-009C SHOULD project important domain events into the existing signature evidence mechanism instead of creating a second audit system.

Expected event types include:

- `identity.challenge.created`
- `identity.challenge.failed`
- `identity.verified`
- `identity.denied`
- `identity.expired`
- `identity.replay.detected`
- `consent.accepted`
- `consent.declined`
- `consent.expired`

Evidence payloads MUST be sanitized and tenant-scoped.

## 13. HTTP API

The HTTP surface is additive.

Planned endpoints:

```text
POST /v1/signature-requests/{requestId}/participants/{participantId}/identity-sessions
POST /v1/signature-requests/{requestId}/participants/{participantId}/identity-sessions/{sessionId}/complete
POST /v1/signature-requests/{requestId}/participants/{participantId}/consents
GET  /v1/signature-requests/{requestId}/participants/{participantId}/readiness
```

The API MUST NOT expose reusable provider secrets, raw access tokens, raw OTPs or internal challenge material.

Provider-specific errors MUST be normalized to stable domain/API errors.

## 14. Error model

Stable D-009C errors include:

- `IDENTITY_REQUIRED`
- `CONSENT_REQUIRED`
- `IDENTITY_CHALLENGE_EXPIRED`
- `IDENTITY_CHALLENGE_INVALID`
- `IDENTITY_REPLAY_DETECTED`
- `IDENTITY_ASSURANCE_INSUFFICIENT`
- `IDENTITY_PROVIDER_UNAVAILABLE`
- `CONSENT_IDENTITY_MISMATCH`
- `CONSENT_DOCUMENT_MISMATCH`
- `CONSENT_ALREADY_FINALIZED`
- `CROSS_TENANT_ACCESS_DENIED`
- `TRUST_POLICY_VIOLATION`
- `PROVIDER_PROTOCOL_ERROR`

Implementation MAY map these to HTTP status codes, but the domain code MUST remain stable and provider-independent.

## 15. Security and privacy requirements

D-009C MUST enforce:

1. tenant isolation on every session, evidence and consent lookup;
2. single-use challenge semantics;
3. challenge expiration;
4. maximum challenge attempts;
5. no downgrade to a weaker provider/method when policy evaluation fails;
6. no fake-provider fallback from sandbox or production;
7. no persistence of plaintext OTP, TOTP secrets, passwords, private keys, bearer tokens or provider refresh tokens;
8. no raw provider response persistence when it contains unnecessary personal or secret data;
9. consent binding to exact `documentSha256` and `statementHash`;
10. identity evidence binding to exact tenant/request/participant context;
11. sanitized logs and errors;
12. endpoint-specific rate limiting for challenge creation and completion;
13. immutable accepted/declined consent records.

Security regression checks MUST include structural guards ensuring that obvious secret-bearing columns/fields are not introduced into D-009C migrations or schema.

## 16. Compatibility

D-009C MUST be backward compatible with the current `/v1/signature-requests` behavior.

Existing callers without a D-009C identity policy MUST NOT be forced into the new challenge/consent flow.

D-009C extends existing provider, participant, evidence and trust architecture rather than replacing it.

## 17. Tests

Testing is required at domain, provider, service, persistence, HTTP and security-regression levels.

Mandatory scenarios:

### Identity

- valid FAKE challenge;
- invalid response;
- expired challenge;
- replay of a consumed challenge;
- max-attempt exhaustion;
- denied verification;
- provider failure;
- assurance below policy;
- evidence from another tenant;
- evidence from another participant/request.

### Consent

- accepted consent;
- declined consent;
- consent without valid identity;
- mismatched identity evidence;
- changed document hash;
- changed statement hash;
- attempt to mutate/finalize an already final consent;
- consent from another tenant;
- provider failure.

### Orchestration

- `awaiting_identity` before verification;
- `awaiting_consent` after authentication when consent is required;
- `ready_to_sign` only after all requirements are met;
- full FAKE path: challenge -> authenticated -> consented -> signed -> validated -> completed;
- D-009B flow still completes when identity/consent are not required.

### Security regression

- fake provider rejected outside `trustMode: fake`;
- no cross-tenant reuse;
- no challenge replay;
- no plaintext/reusable secret persistence;
- migration remains additive;
- existing D-009A/D-009B checks remain green.

## 18. Planned source structure

Expected modules:

```text
src/
  identity/
    authenticationMethod.ts
    identityAssurance.ts
    identityPolicy.ts
    identitySession.ts
    identityEvidence.ts
    identityConsentService.ts
  consent/
    consentRecord.ts
  providers/
    providerContracts.ts
    fakeIdentityProvider.ts
    fakeConsentProvider.ts
  signatures/
    participant.ts
    domain.ts
    universalTrustService.ts
  db/
    schema.ts
  http/
    ...identity/consent routes...
```

Exact file names MAY be adjusted during implementation to follow existing repository conventions, but the domain boundaries described here MUST be preserved.

## 19. Acceptance criteria

D-009C is complete only when all of the following are true:

1. a participant cannot sign when required identity verification is unsatisfied;
2. a participant cannot sign when required consent is unsatisfied;
3. authentication assurance is evaluated independently from signature level;
4. challenge replay and expired challenges are rejected;
5. accepted consent becomes invalid for a different document hash or statement hash;
6. cross-tenant evidence reuse is rejected;
7. no reusable authentication secret is persisted;
8. FAKE providers are isolated to `trustMode: fake`;
9. the FAKE end-to-end identity -> consent -> sign -> validate flow reaches `completed`;
10. legacy/D-009B behavior remains compatible when identity/consent policy is absent;
11. schema migration is additive and versioned but not applied to production;
12. README, OpenAPI, CHANGELOG and security regression checks are updated;
13. all project quality gates pass before integration.

## 20. Future adapter boundary

After D-009C, future adapters can implement real mechanisms without redesigning the core domain. Candidate future work includes:

- OIDC/SSO adapter;
- WebAuthn/passkey adapter;
- OTP delivery adapters;
- biometric provider adapters;
- Gov.br adapter when eligibility and integration conditions are satisfied;
- external consent/evidence providers.

Each future adapter MUST plug into the D-009C contracts, normalize provider-specific evidence and continue to obey tenant isolation, assurance policy and trust-mode constraints.

## 21. Delivery boundary

D-009C is a foundation cycle. It delivers the universal identity/consent engine and FAKE/local homologation path, not production identity-provider integrations.

No production provider capability should be advertised until that provider has its own implementation, security review, tests and explicit integration cycle.