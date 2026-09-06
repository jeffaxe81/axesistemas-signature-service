# Axesistemas Signature Service

Serviço independente do épico D-009 para assinatura digital/ICP-Brasil.

## Estado

D-009A em desenvolvimento via `feature/d009a-core`.

## Princípios

- arquitetura agnóstica de fornecedor;
- isolamento multi-tenant fail-closed;
- nenhuma chave privada de certificado armazenada;
- primeiro provider fake/contratual;
- TDD e gates de qualidade antes de merge;
- deploy, migration real e credenciais são gates separados.

## Desenvolvimento

```bash
corepack enable
pnpm install
pnpm check
pnpm test
pnpm build
```

## Health check

`GET /health` deve responder `200` com `{ "status": "ok" }`.
