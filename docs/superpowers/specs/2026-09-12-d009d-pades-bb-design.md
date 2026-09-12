# D-009D — PAdES-B-B real com engine DSS

Data: 2026-09-12
Status: design aprovado em chat; aguardando revisão formal da spec
Base: `main` após D-009C

## 1. Objetivo

Entregar a primeira assinatura documental criptográfica real do Axesistemas Signature Service, usando PAdES-B-B sobre PDF, sem acoplar o core TypeScript a uma implementação específica de PDF/criptografia e mantendo a arquitetura pronta para evolução posterior para PAdES-B-T, PAdES-B-LT, PAdES-B-LTA, CAdES, XAdES e ASiC.

O ciclo D-009D introduz uma engine criptográfica isolada em Java, baseada em DSS, acessada pelo core por contrato interno estável. O core continua responsável por tenant, políticas, identidade, consentimento, autorização de credencial, artefatos, auditoria e estado do workflow. O sidecar DSS fica responsável por operações criptográficas e de formato documental.

## 2. Escopo aprovado

### 2.1 Entregas deste ciclo

- arquitetura universal de formatos, com PAdES como primeiro adapter real;
- PAdES-B-B real sobre `application/pdf`;
- DSS/Java como engine criptográfica isolada em sidecar;
- assinatura com certificado FAKE/dev para homologação;
- assinatura com PKCS#12/PFX real carregado como segredo operacional no sidecar;
- múltiplas credenciais por `tenantId + credentialRef`;
- seleção de `credentialRef` por requisição, obrigatoriamente validada contra allowlist do tenant;
- envio do PDF do core para o sidecar por binário/stream, sem acesso direto do sidecar ao storage neste ciclo;
- validação criptográfica obrigatória do PAdES gerado antes do estado `completed`;
- persistência imutável de artefatos, validações e evidências sanitizadas;
- aparência visual opcional da assinatura;
- Docker Compose com core + sidecar DSS;
- testes automatizados do core e do sidecar;
- documentação operacional, OpenAPI e security regression gate atualizados.

### 2.2 Fora do escopo

- PAdES-B-T;
- PAdES-B-LT;
- PAdES-B-LTA;
- TSA RFC 3161 produtiva;
- CAdES;
- XAdES;
- ASiC;
- JAdES/CB-AdES;
- HSM/PKCS#11;
- seleção automática de credencial por regra;
- sidecar acessando object storage diretamente;
- rate limiting distribuído;
- integração ICP-Brasil específica;
- alegação de que certificado FAKE/dev possui validade pública ou jurídica;
- deploy produtivo ou aplicação automática de migrations.

## 3. Princípios arquiteturais

1. O core TypeScript não conhece detalhes internos do DSS.
2. O sidecar DSS não decide autorização de tenant ou regra de negócio.
3. Chave privada, senha de PFX e bytes do keystore nunca transitam pelo core e nunca são persistidos no banco da aplicação.
4. O documento original é imutável.
5. Cada assinatura gera um novo artefato derivado do artefato anterior.
6. A geração de um PDF assinado não é suficiente: o artefato deve passar por validação criptográfica antes de ser promovido a assinatura concluída.
7. Falhas criptográficas, de política, hash, credencial ou disponibilidade são fail-closed.
8. O modelo deve continuar multi-tenant e sem fallback entre credenciais, tenants ou trust modes.
9. FAKE/dev permanece isolado de produção.
10. O nível de autenticação/assurance continua separado do nível jurídico/criptográfico da assinatura.

## 4. Arquitetura

Fluxo lógico:

```text
Cliente/API
  -> Axesistemas Signature Service (TypeScript)
  -> autorização tenant + TrustProfile + readiness + credentialRef
  -> CryptoFormatEngine
  -> DSS Sidecar (Java)
  -> PAdES-B-B
  -> validação PAdES
  -> novo artefato assinado
  -> persistência de validação/evidência
  -> completed
```

### 4.1 Core TypeScript

Responsabilidades:

- autenticar e resolver `tenantId`;
- carregar assinatura/request/participante;
- verificar readiness de identidade e consentimento;
- validar TrustProfile, provider e formato;
- validar allowlist de `credentialRef` para o tenant;
- carregar o artefato de entrada do storage;
- calcular SHA-256 de entrada;
- chamar o adapter `CryptoFormatEngine`;
- verificar SHA-256 e resposta do sidecar;
- solicitar validação PAdES;
- persistir novo artefato, validação e evidências;
- atualizar estado somente após validação positiva.

O core nunca recebe material secreto da credencial.

### 4.2 CryptoFormatEngine

Nova fronteira interna, independente do DSS. O contrato inicial deve suportar pelo menos:

- `signPades(input)`;
- `validatePades(input)`.

A interface deve usar conceitos do domínio do produto, não classes ou DTOs específicos do DSS.

Entradas esperadas para assinatura:

- `tenantId`;
- `requestId`;
- `participantId`;
- `credentialRef`;
- `format: "pades"`;
- `baseline: "B-B"`;
- `documentSha256`;
- PDF binário/stream;
- configuração opcional de aparência visual.

Saída esperada:

- PDF assinado;
- hash do PDF assinado;
- metadados sanitizados da assinatura;
- metadados sanitizados do certificado;
- identificador lógico da operação no engine;
- versão do engine;
- `trustMode`.

### 4.3 DSS Sidecar

O sidecar será um serviço Java isolado, preferencialmente stateless em relação ao workflow da aplicação.

Responsabilidades:

- receber PDF e metadados mínimos;
- resolver internamente `tenantId + credentialRef` para uma credencial configurada;
- acessar PFX/PKCS#12 e senha por secret local;
- executar a assinatura PAdES-B-B;
- validar assinatura PAdES;
- devolver somente evidências e metadados sanitizados;
- nunca exportar chave privada, senha ou bytes de keystore.

O sidecar não poderá:

- acessar arbitrariamente o storage da aplicação;
- aceitar caminho de arquivo fornecido pelo cliente externo;
- aceitar URL arbitrária;
- autorizar credencial fora de seu catálogo configurado;
- substituir automaticamente uma credencial ausente por outra;
- efetuar fallback de `production` para `fake`.

## 5. Credenciais

### 5.1 Modos suportados

#### FAKE/dev

- destinado exclusivamente a desenvolvimento, testes e homologação;
- trust mode `fake`;
- pode ser gerado/armazenado somente dentro do ambiente do sidecar;
- não pode ser usado para alegar confiança pública ou ICP-Brasil.

#### PKCS#12/PFX

- arquivo montado como secret no sidecar;
- senha fornecida separadamente por secret/configuração protegida;
- nenhuma persistência no banco da aplicação;
- nenhuma passagem pelo core TypeScript;
- nenhum conteúdo bruto em logs, evidências ou APIs.

### 5.2 Catálogo multi-credencial

A resolução é sempre:

```text
tenantId + credentialRef -> credential config -> PFX/PKCS#12 + secret
```

Metadados seguros permitidos no catálogo/observabilidade:

- `credentialRef`;
- alias lógico;
- subject sanitizado;
- issuer sanitizado;
- serial;
- fingerprint;
- algoritmo;
- início/fim da validade;
- status de disponibilidade.

### 5.3 Seleção por requisição

A requisição de assinatura pode indicar `credentialRef`, mas o core deve validá-lo contra a allowlist configurada para o tenant/TrustProfile antes de chamar o sidecar.

Falha de autorização não permite fallback.

## 6. Transporte core -> sidecar

O PDF será enviado diretamente do core para o sidecar.

Contrato recomendado: `multipart/form-data` interno com:

- parte JSON de metadados;
- parte binária `application/pdf`.

Motivos:

- evita Base64;
- reduz overhead de memória e tamanho;
- mantém binário separado de metadados;
- facilita aplicação de limites de payload.

A resposta de assinatura deve conter:

- PDF PAdES assinado em binário;
- evidência JSON sanitizada.

O contrato deve impor:

- `content-type` correto;
- limite configurável de tamanho;
- timeout;
- SHA-256 esperado;
- validação do hash no core e no sidecar;
- rejeição de conteúdo não-PDF neste endpoint.

## 7. Segurança entre serviços

O sidecar não deve ser publicado diretamente na Internet.

Ambientes iniciais podem usar segredo interno configurado para autenticação de serviço, mas a arquitetura deve suportar mTLS para ambientes reais.

Requisitos mínimos:

- autenticação service-to-service;
- rede interna;
- sem segredo em URL;
- sem stack trace bruto em resposta;
- sem logging de corpo binário do PDF, PFX, senha, chave privada ou token sensível;
- correlação por IDs não secretos;
- fail-closed em erro de autenticação do sidecar.

## 8. Modelo de artefatos

O modelo existente deve ser evoluído de forma aditiva, sem criar um domínio paralelo.

Fluxo de múltiplos participantes:

```text
PDF original
  -> assinatura participante 1
  -> PDF PAdES #1
  -> assinatura participante 2
  -> PDF PAdES #2
  -> ...
```

Cada assinatura gera um novo artefato. Nenhum arquivo anterior é sobrescrito.

### 8.1 `signature_artifacts`

A evolução deve permitir associar pelo menos:

- `sourceArtifactId`;
- `format = pades`;
- `baseline = B-B`;
- `credentialRef`;
- `inputSha256`;
- `sha256` de saída;
- certificate fingerprint;
- certificate serial;
- algoritmo de assinatura;
- engine `DSS`;
- versão do engine;
- `trustMode`;
- timestamp da operação.

O artefato assinado deve continuar tenant-scoped.

### 8.2 `validation_results`

Deve apontar explicitamente para o `signatureArtifactId` validado.

Deve persistir apenas resultado e evidência sanitizada necessária ao produto, não o relatório bruto completo do DSS.

### 8.3 `signature_evidence`

Continua como ledger append-only para eventos, incluindo:

- `PADES_SIGNING_STARTED`;
- `PADES_SIGNED`;
- `PADES_VALIDATED`;
- `PADES_SIGNING_FAILED`.

As evidências podem registrar IDs, hashes, provider/engine, `credentialRef`, códigos de erro sanitizados e timestamps. Nunca devem conter segredo reutilizável.

## 9. Persistência e migration

A migration D-009D deve ser estritamente aditiva.

Não remover ou renomear colunas existentes durante este ciclo.

Não aplicar a migration automaticamente em banco produtivo ou compartilhado.

O design deve preservar compatibilidade com dados D-009A/B/C.

## 10. Aparência visual

A aparência visual é separada da validade criptográfica.

Modos iniciais:

- `visualSignature: none` — padrão;
- `visualSignature: standard` — opcional.

`standard` pode incluir:

- nome do signatário;
- data/hora;
- identificador da assinatura;
- indicação textual de assinatura eletrônica.

A ausência do bloco visual não torna o PAdES inválido.

O posicionamento avançado, templates complexos, QR code e editor visual ficam fora deste ciclo.

## 11. Validação obrigatória pós-assinatura

Sequência obrigatória:

```text
autorização
  -> readiness
  -> carregar artefato de entrada
  -> SHA-256 de entrada
  -> DSS sign
  -> SHA-256 de saída
  -> DSS validate
  -> persistir artefato
  -> persistir validação/evidência
  -> completed
```

Se a validação falhar:

- a requisição não vira `completed`;
- o artefato inválido não é promovido como documento assinado;
- preferencialmente o binário inválido não é mantido em storage permanente;
- ficam somente hash, código sanitizado e auditoria necessária para diagnóstico.

## 12. Contrato de erros

Códigos de domínio estáveis devem ser usados entre adapter e core, sem vazar exceções DSS/Java.

Códigos iniciais:

- `CREDENTIAL_NOT_ALLOWED`;
- `CREDENTIAL_NOT_FOUND`;
- `CREDENTIAL_UNAVAILABLE`;
- `CERTIFICATE_EXPIRED`;
- `CERTIFICATE_NOT_YET_VALID`;
- `PDF_INVALID`;
- `PDF_TOO_LARGE`;
- `DOCUMENT_HASH_MISMATCH`;
- `UNSUPPORTED_SIGNATURE_FORMAT`;
- `UNSUPPORTED_BASELINE`;
- `CRYPTO_ENGINE_TIMEOUT`;
- `CRYPTO_ENGINE_UNAVAILABLE`;
- `SIGNATURE_GENERATION_FAILED`;
- `SIGNATURE_VALIDATION_FAILED`.

Logs internos podem conter contexto técnico sanitizado, mas respostas HTTP públicas não devem conter stack trace, path de secrets ou detalhes internos do keystore.

## 13. TrustProfile e isolamento

O TrustProfile continua autoridade de trust mode e providers permitidos.

Regras obrigatórias:

- provider `fake` não pode operar sob profile `production`;
- `credentialRef` precisa estar autorizado para o tenant;
- sidecar não recebe autoridade para mudar tenant;
- todas as leituras/escritas continuam tenant-scoped;
- cross-tenant deve falhar de forma fechada;
- inexistência e não autorização devem evitar vazamento de existência de credenciais de outro tenant.

## 14. Testes

### 14.1 Core TypeScript

Cobrir pelo menos:

- readiness pendente bloqueia assinatura;
- readiness válido permite chamar engine;
- `credentialRef` não autorizado bloqueia antes do sidecar;
- tenant A não usa credencial do tenant B;
- hash divergente bloqueia;
- timeout/indisponibilidade do sidecar falha fechado;
- validação negativa impede `completed`;
- artefato anterior nunca é sobrescrito;
- múltiplos participantes encadeiam artefatos corretamente;
- FAKE não é aceito em production;
- evidências não contêm segredo.

### 14.2 Sidecar DSS

Cobrir pelo menos:

- PAdES-B-B válido com credencial FAKE/dev;
- PAdES-B-B válido com PFX de teste;
- PDF corrompido;
- payload acima do limite;
- hash divergente;
- credencial ausente;
- senha/keystore inválido;
- certificado expirado ou ainda não válido;
- validação de PDF alterado após assinatura;
- retorno sanitizado sem chave privada/senha;
- `visualSignature: none`;
- `visualSignature: standard`.

### 14.3 Integração

Subir core + sidecar por Docker Compose e executar uma jornada real:

1. criar request;
2. satisfazer identidade/consentimento quando exigidos;
3. assinar PDF via PAdES-B-B;
4. validar o PAdES;
5. persistir artefato/evidência;
6. concluir request;
7. confirmar alteração posterior detectada como inválida.

## 15. Critérios de aceite

D-009D só é considerado concluído quando:

- gera PDF real `application/pdf` com assinatura PAdES-B-B;
- o PAdES é validado antes do estado `completed`;
- suporta FAKE/dev e PKCS#12/PFX por `credentialRef`;
- implementa isolamento `tenantId + credentialRef`;
- chave privada e senha nunca entram no core ou banco;
- documento original é preservado;
- novo artefato é vinculado ao artefato de origem;
- validação e evidências são imutáveis/append-only;
- aparência visual é opcional;
- testes do core, sidecar e integração estão verdes;
- Docker Compose documentado funciona para o fluxo de homologação;
- OpenAPI, README/operacional, CHANGELOG e security regression gate são atualizados;
- nenhum item de backlog é apresentado como implementado.

## 16. Backlog posterior

### PAdES

1. PAdES-B-T com TSA RFC 3161;
2. PAdES-B-LT com material de validação e revogação;
3. PAdES-B-LTA com preservação de longo prazo.

### Outros formatos

4. CAdES;
5. XAdES;
6. ASiC;
7. JAdES/CB-AdES conforme necessidade de produto.

### Infraestrutura criptográfica

8. HSM/PKCS#11;
9. integração com providers/certificadoras externas;
10. políticas automáticas de seleção de credencial;
11. acesso direto e controlado do sidecar ao object storage para cenários de escala;
12. rate limiting distribuído;
13. mTLS obrigatório em perfis de produção;
14. rotação operacional de credenciais;
15. observabilidade e métricas específicas da engine criptográfica.

## 17. Compatibilidade

D-009D deve ser aditivo sobre D-009A/B/C.

O fluxo legado e o provider FAKE detached existente permanecem disponíveis apenas nos contextos previamente autorizados. O novo PAdES não deve alterar silenciosamente semântica de requests antigos nem migrar artefatos existentes.

A arquitetura universal deve permitir que CAdES/XAdES/ASiC sejam adicionados futuramente por novos adapters/estratégias de formato sem reescrever o domínio de identidade, consentimento, tenant, artefatos ou trust profiles.

## 18. Decisões finais aprovadas

- escopo A: arquitetura universal + PAdES real primeiro;
- PAdES-B-B neste ciclo; B-T/B-LT/B-LTA em backlog;
- DSS/Java como engine criptográfica open source isolada;
- FAKE/dev + PKCS#12/PFX;
- múltiplas credenciais por `credentialRef`;
- `credentialRef` informado por requisição e validado por allowlist do tenant;
- PDF enviado em binário/stream ao sidecar;
- sidecar sem acesso direto ao storage neste ciclo;
- validação PAdES obrigatória antes de `completed`;
- aparência visual opcional;
- migration somente aditiva;
- nenhum deploy produtivo como parte desta história.
