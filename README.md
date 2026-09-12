# Axesistemas Signature Service

Serviço independente de confiança documental e assinatura eletrônica/digital, com núcleo agnóstico de fornecedor.

## Estado

- `v0.1.0 / D-009A`: encerrada e preservada como checkpoint estável.
- `D-009B`: fundação universal de confiança documental em evolução na branch `feature/d009b-universal-trust`.

A D-009B adiciona modelo de capacidades, perfis de confiança, domínio multi-participante, contratos separados de providers, registry fail-closed, persistência aditiva e uma PKI FAKE para desenvolvimento e testes.

## PKI FAKE

A PKI FAKE existe exclusivamente para desenvolvimento, testes automatizados, demonstrações controladas e homologação técnica interna.

- certificados e timestamps são marcados com `trustMode: "fake"`;
- a raiz é `AXESISTEMAS FAKE DEV ROOT`;
- chaves privadas fake existem somente em memória durante o processo;
- `production-standard` rejeita providers fake;
- não existe fallback automático de provider real para fake;
- certificados emitidos nesta etapa não possuem validade jurídica nem confiança pública.

## Princípios

- arquitetura agnóstica de fornecedor;
- isolamento multi-tenant fail-closed;
- nenhuma chave privada de certificado persistida pelo Core;
- autenticação, consentimento, assinatura, validação e timestamp separados por contratos;
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

Os endpoints `/v1/signature-requests` permanecem compatíveis com a v0.1.0 durante a D-009B. O novo `UniversalTrustService` é uma fundação interna e não substitui o fluxo legado nesta etapa.

## Health check

`GET /health` deve responder `200` com `{ "status": "ok" }`.

## Próximas evoluções

A D-009B não declara suporte produtivo a ICP-Brasil, PAdES, CAdES, XAdES, HSM/PKCS#11 ou providers comerciais. Essas integrações serão adicionadas por adapters específicos nas histórias posteriores D-009D a D-009H, após validação técnica, segurança e licenciamento.
