# Changelog

## [0.1.0] — 2026-09-06

Primeira versão funcional do serviço independente de assinatura digital D-009A.

### Entregue
- contexto de tenant fail-closed;
- máquina de estados de assinatura;
- hash SHA-256 de documentos;
- contrato agnóstico `SignatureProvider` e fake provider determinístico;
- persistência tenant-scoped;
- schema PostgreSQL/Drizzle e migration apenas versionada, sem aplicação produtiva;
- orquestração de solicitações de assinatura;
- webhook HMAC com janela temporal e idempotência;
- validação de evidência por hash;
- API `/v1/signature-requests` e OpenAPI;
- security regression gate automatizado;
- Docker e CI de qualidade.

### Evidência de qualidade
- security:check GREEN;
- TypeScript GREEN;
- 11/11 arquivos de teste GREEN;
- 25/25 testes GREEN;
- build GREEN.

### Fora do escopo desta versão
- seleção de provider ICP-Brasil real;
- armazenamento de chave privada;
- assinatura A3/token diretamente no backend;
- deploy produtivo;
- aplicação de migration em banco real;
- credenciais produtivas;
- integração com Dispatch/CRM.

### Evoluções externas planejadas
Providers reais devem permanecer desacoplados do núcleo. Caso exijam runtime ou ciclo de vida próprios, devem nascer em repositório separado. Candidatos levantados: Demoiselle Signer (self-hosted/open source), SignDocs Brasil (API/SaaS) e LibreSign (integração opcional/Nextcloud).
