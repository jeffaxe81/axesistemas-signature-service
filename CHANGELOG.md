# Changelog

## [Unreleased] — D-009C Identity & Consent Foundation

### Entregue na fundação
- modelo de métodos de autenticação e níveis de assurance independentes do nível jurídico da assinatura;
- `IdentityPolicy` com métodos/providers permitidos, assurance mínima, TTL e limite de tentativas;
- lifecycle de sessão de identidade com proteção de expiração, replay e max attempts;
- providers FAKE de identidade e consentimento para dev/QA, ambos com `trustMode: "fake"`;
- external subject persistido somente como SHA-256;
- consentimento imutável vinculado ao tenant, request, participante, identidade verificada, hash do documento e hash da declaração;
- readiness derivado em `awaiting_identity`, `awaiting_consent` ou `ready_to_sign`;
- `UniversalTrustService` bloqueando a assinatura antes de identidade/consentimento quando a política D-009C é aplicável;
- fluxo FAKE integrado `awaiting_identity -> awaiting_consent -> ready_to_sign -> completed`;
- alteração do documento invalida o consentimento anterior para readiness sem nova chamada de assinatura;
- tabelas tenant-scoped `identity_sessions`, `identity_evidences` e `consent_records`;
- adapter Drizzle com filtros explícitos de tenant;
- migration aditiva `0002_d009c_identity_consent.sql` e journal correspondente;
- API HTTP para iniciar/completar identidade, registrar consentimento e consultar readiness;
- rate limiter fixed-window process-local para operações de challenge;
- normalização de erros sem expor mensagens desconhecidas de providers;
- security regression gate ampliado para isolamento tenant, replay, providers FAKE, secret-persistence guard e readiness antes da assinatura.

### Limites desta etapa
- `fake-identity`, `fake-consent` e `FAKE-OK` são exclusivos de desenvolvimento, QA e homologação técnica;
- nenhum adapter real Gov.br, OIDC, WebAuthn/passkey, biometria, SMS OTP ou e-mail OTP foi entregue nesta etapa;
- autenticação forte não determina por si só o enquadramento jurídico da assinatura do documento;
- o rate limiter atual é process-local e deverá ser substituído/estendido por mecanismo distribuído em implantação horizontal;
- nenhuma migration D-009C foi aplicada automaticamente em banco produtivo ou compartilhado;
- nenhuma credencial produtiva ou segredo de provider foi adicionado ao repositório.

## D-009B — Universal Trust Capability Model

### Entregue na fundação
- modelo de capacidades para providers de identidade, consentimento, assinatura, validação e timestamp;
- perfis `fake-dev`, `sandbox` e `production-standard`;
- bloqueio fail-closed de provider FAKE em produção;
- registry de providers sem fallback automático entre modos de confiança;
- contratos independentes com adapter de compatibilidade para o `SignatureProvider` v0.1.0;
- domínio multi-participante e máquina de estados universal sem remoção do domínio legado;
- PKI/certificação FAKE baseada em Ed25519 para validação técnica do produto;
- cenários FAKE de certificado válido, expirado, revogado e desconhecido;
- detecção de assinatura adulterada e hash divergente;
- timestamp FAKE com verificação de integridade;
- chaves privadas FAKE restritas à memória do processo;
- schema PostgreSQL/Drizzle aditivo para participantes, bindings, artefatos, validações e trust profiles;
- `UniversalTrustService` para orquestração interna hash → assinatura → timestamp quando exigido → validação;
- preservação dos endpoints `/v1/signature-requests` e do provider fake legado;
- security regression gate ampliado para políticas de confiança e PKI FAKE.

### Limites desta etapa
- nenhum certificado FAKE possui validade jurídica ou confiança pública;
- nenhum provider ICP-Brasil produtivo foi ativado;
- PAdES, CAdES, XAdES, XMLDSig, ASiC e JAdES estão modelados como capacidades, mas não são declarados como engines criptográficas entregues nesta etapa;
- nenhum HSM, PKCS#11, certificado A1/A3 real ou credencial produtiva foi ativado;
- migration permanece apenas versionada, sem aplicação em banco produtivo.

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
