# D-009A — Relatório de Verificação

Data: 2026-09-06

## Repositório

`jeffaxe81/axesistemas-signature-service`

Projeto independente do módulo D-009 — Assinatura Digital / ICP-Brasil. O `dispatch` não contém a implementação funcional deste serviço.

## Candidato validado antes deste relatório

SHA: `5c675e3285a49586e951b8174125c48188b27b62`

GitHub Actions — Qualidade #86: GREEN.

Gates aprovados no mesmo candidato:

- `pnpm security:check` — GREEN;
- `pnpm check` — GREEN;
- `pnpm test` — GREEN: 11/11 arquivos, 25/25 testes;
- `pnpm build` — GREEN.

## Escopo verificado

- bootstrap Node.js 24 + TypeScript + Fastify;
- health check `/health`;
- contexto de tenant server-side com resolução fail-closed;
- máquina de estados explícita de assinatura;
- SHA-256 para integridade documental;
- contrato de armazenamento desacoplado;
- `SignatureProvider` agnóstico de fornecedor;
- `FakeSignatureProvider` determinístico, sem I/O externo;
- repositório com tenant obrigatório em todas as operações;
- schema PostgreSQL/Drizzle com chaves compostas por tenant;
- orquestração `draft -> pending` com evidência auditável;
- webhook com HMAC SHA-256, `timingSafeEqual`, janela temporal e idempotência;
- validação de integridade da evidência assinada;
- API HTTP autenticada `/v1/signature-requests`;
- OpenAPI 3.1;
- security regression gate automatizado.

## Migração de banco

O arquivo `drizzle/0000_d009a_signature_service.sql` e seu journal foram versionados como representação equivalente ao schema atual.

A migration **não foi aplicada em banco real**. O ambiente local desta sessão não conseguiu acessar registry/GitHub para executar uma geração independente via `drizzle-kit`, portanto este relatório não afirma que o SQL foi gerado automaticamente pelo Drizzle. Antes de qualquer aplicação produtiva, deverá haver comparação/generação em ambiente de desenvolvimento com dependências disponíveis e aprovação específica do gate de migration.

## Segurança preservada

O gate de regressão verifica automaticamente:

- tenant do payload não possui autoridade;
- não existe `findById(id)` sem tenant no contrato de repositório;
- webhook usa HMAC e comparação timing-safe;
- webhook mantém idempotência por evento e vínculo com `providerRequestId`;
- não existe campo/material de chave privada nos artefatos verificados;
- migration e journal permanecem correspondentes;
- chave primária das solicitações inclui `tenant_id`;
- configuração Drizzle permanece sem credenciais/conexão de banco.

## Limites desta entrega

Esta entrega **não** inclui ou autoriza:

- provider ICP-Brasil real;
- certificado A1/A3, token ou chave privada;
- armazenamento de chave privada;
- credenciais externas;
- deploy;
- aplicação de migration em banco real;
- grants de banco;
- integração funcional com `jeffaxe81/dispatch`;
- merge automático do PR.

A integração com Dispatch será tratada em PR separado somente após o serviço independente ser aprovado e seu contrato HTTP estar congelado.

## Itens de backlog não bloqueantes

- atualizar actions GitHub quando versões nativas de Node 24 estiverem disponíveis;
- revisar dependências transitivas marcadas como deprecated pelo pnpm;
- estabelecer política explícita para scripts de build de dependências (`pnpm approve-builds`), se necessária;
- validar o SQL de migration por geração/diff independente antes de qualquer ambiente real;
- definir semântica de cancelamento antes de expor `cancelSignatureRequest` (o estado `cancelled` não faz parte da máquina de estados aprovada do D-009A).
