# Axesistemas Signature Service

Serviço independente de confiança documental e assinatura eletrônica/digital, com núcleo agnóstico de fornecedor.

## Estado

- `v0.1.0 / D-009A`: checkpoint estável do fluxo legado `/v1/signature-requests`.
- `D-009B`: fundação universal de confiança documental, preservada como base do Core.
- `D-009C`: fundação de identidade e consentimento em validação na branch `feature/d009c-identity-consent`.

A D-009C adiciona política de autenticação e assurance, lifecycle de challenges, consentimento imutável vinculado à identidade e ao hash do documento, readiness antes da assinatura, persistência tenant-scoped, API HTTP e providers FAKE para desenvolvimento/QA.

## Fluxo D-009C

O fluxo de assinatura universal pode exigir, por participante:

```text
awaiting_identity
-> challenge de identidade
-> identidade verificada
-> awaiting_consent
-> consentimento aceito para documento + declaração exatos
-> ready_to_sign
-> assinatura/validação
-> completed
```

O `UniversalTrustService` consulta readiness antes de chamar o provider de assinatura. Alteração dos bytes do documento ou da declaração invalida o consentimento anterior para fins de readiness.

## Identidade e consentimento FAKE

Os providers `fake-identity` e `fake-consent` existem exclusivamente para desenvolvimento, testes automatizados, demonstrações controladas e homologação técnica interna.

- ambos usam `trustMode: "fake"`;
- o challenge FAKE aceita `FAKE-OK` somente em cenários de teste;
- o subject externo retornado pelo provider é persistido somente como SHA-256;
- respostas de challenge não são persistidas; a sessão armazena digest e identificadores de correlação;
- replay, expiração e limite de tentativas são tratados pelo Core;
- `production-standard` não aceita providers FAKE e não existe fallback automático real → fake.

A presença de métodos como `oidc`, `webauthn`, `govbr` ou `biometric` no modelo de capacidades **não significa que adapters produtivos estejam entregues**. WebAuthn/autenticação também não determina, isoladamente, o nível jurídico da assinatura do documento.

## API D-009C

A API expõe, quando configurada:

- `POST /v1/signature-requests/:requestId/participants/:participantId/identity-sessions`
- `POST /v1/signature-requests/:requestId/participants/:participantId/identity-sessions/:sessionId/complete`
- `POST /v1/signature-requests/:requestId/participants/:participantId/consents`
- `GET /v1/signature-requests/:requestId/participants/:participantId/readiness`

O tenant é derivado exclusivamente da credencial autenticada. Hash do documento, política, participante e declaração canônica de consentimento são resolvidos no servidor; o cliente não possui autoridade para substituir esses valores.

## Rate limiting

A D-009C inclui um limiter fixed-window em memória para criação e conclusão de challenges. Ele é adequado à fundação atual single-process e aos testes, mas **não substitui rate limiting distribuído** em produção. Em implantação horizontal/multi-instância, o limiter deve usar armazenamento compartilhado/infraestrutura apropriada.

## PKI FAKE

A PKI FAKE da D-009B continua exclusiva de desenvolvimento, testes e homologação técnica interna.

- certificados e timestamps são marcados com `trustMode: "fake"`;
- a raiz é `AXESISTEMAS FAKE DEV ROOT`;
- chaves privadas fake existem somente em memória durante o processo;
- certificados/timestamps FAKE não possuem confiança pública nem validade jurídica por si mesmos.

## Persistência e migrations

As migrations `0001_d009b_universal_trust.sql` e `0002_d009c_identity_consent.sql` são aditivas e versionadas no journal. O projeto **não aplica migrations automaticamente em ambiente produtivo**; aplicação em banco real continua sendo um gate separado de implantação.

As tabelas D-009C são tenant-scoped:

- `identity_sessions`;
- `identity_evidences`;
- `consent_records`.

Não são persistidos senha, OTP em claro, bearer token, refresh token, segredo TOTP ou chave privada pelo modelo D-009C.

## Princípios

- arquitetura agnóstica de fornecedor;
- isolamento multi-tenant fail-closed;
- nenhuma chave privada de certificado persistida pelo Core;
- autenticação, consentimento, assinatura, validação e timestamp separados por contratos;
- readiness derivado do estado atual, sem Boolean persistido de “pronto para assinar”;
- TDD e gates de qualidade antes de merge;
- deploy, aplicação de migration real e credenciais produtivas são gates separados.

## Desenvolvimento

```bash
corepack enable
pnpm install
pnpm security:check
pnpm check
pnpm test
pnpm build
```

## Compatibilidade

Os endpoints legados `/v1/signature-requests` permanecem compatíveis com a v0.1.0. As rotas D-009C são registradas de forma aditiva somente quando suas dependências completas são fornecidas ao `buildApp()`.

## Health check

`GET /health` deve responder `200` com `{ "status": "ok" }`.

## Limites e próximas evoluções

A D-009C não declara entrega produtiva de Gov.br, OIDC, WebAuthn/passkeys, biometria ou OTP SMS/e-mail. Também não declara suporte produtivo a ICP-Brasil, PAdES, CAdES, XAdES, HSM/PKCS#11 ou providers comerciais. Essas integrações exigem adapters específicos, credenciais/ambientes próprios, validação de segurança e revisão de licenciamento/compliance.
