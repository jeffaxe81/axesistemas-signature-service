# D-009B — Universal Trust Capability Model

Data: 2026-09-12  
Status: Design aprovado para especificação; implementação pendente de plano  
Base: Axesistemas Signature Service v0.1.0 / D-009 encerrado

## 1. Objetivo

Evoluir o `axesistemas-signature-service` de um núcleo inicial de solicitação de assinatura para um serviço universal de confiança documental, extensível por capacidades e desacoplado de fornecedor.

O serviço deve suportar, progressivamente, diferentes formas de autenticação de signatário, consentimento, assinatura eletrônica, assinatura digital criptográfica, validação, carimbo do tempo, evidências e integrações com soluções open source e de mercado, sem exigir remodelagem do núcleo para cada novo provider.

Esta especificação não declara suporte imediato a todos os padrões ou provedores. Ela define as fronteiras arquiteturais necessárias para que novos métodos possam ser adicionados por adapters versionados e testáveis.

## 2. Princípios

1. **Core agnóstico de fornecedor** — nenhuma biblioteca, autoridade certificadora ou SaaS define o domínio central.
2. **Multi-tenant fail-closed** — toda operação permanece isolada pelo tenant autenticado.
3. **Chave privada fora do Core** — o serviço central não armazena chave privada de signatário.
4. **Capacidades explícitas** — cada provider declara o que sabe autenticar, assinar, validar ou carimbar.
5. **Evidência como dado de primeira classe** — autenticação, consentimento, assinatura, validação e timestamp geram evidências imutáveis.
6. **Compatibilidade progressiva** — o provider fake existente continua funcionando durante a migração.
7. **Extensibilidade por contrato** — integrações simples podem residir no mesmo runtime; integrações com HSM, PKCS#11, Java ou requisitos próprios podem operar como serviços externos/sidecars.
8. **Segurança por padrão** — algoritmos, políticas de confiança e formatos aceitos são configurados por perfil, não por entrada arbitrária do cliente.
9. **Sem falsa confiança** — qualquer mecanismo FAKE deve ser inequivocamente marcado como não confiável e nunca confundido com ICP-Brasil ou cadeia pública real.

## 3. Escopo da D-009B

A D-009B entrega apenas a fundação do modelo universal. Não inclui provider ICP-Brasil produtivo, uso de certificado real, HSM produtivo, integração Gov.br produtiva, credenciais de terceiros ou deploy produtivo.

Inclui:

- modelo de capacidades;
- separação entre identidade, consentimento, assinatura, validação e timestamp;
- perfis de confiança;
- níveis de assinatura `simple`, `advanced` e `qualified`;
- formatos de assinatura e contêineres extensíveis;
- múltiplos signatários;
- ordem de assinatura sequencial ou paralela;
- coassinatura e contrassinação como capacidades futuras modeláveis;
- artefatos assinados e resultados de validação;
- provider/PKI FAKE para validação inicial do produto;
- compatibilidade com o provider fake atual;
- testes contratuais de providers;
- evolução da OpenAPI sem quebrar consumidores v1 existentes durante a transição.

## 4. Arquitetura recomendada

### 4.1 Core de confiança documental

O domínio passa a orquestrar capacidades independentes em vez de depender de um único `SignatureProvider` monolítico.

Interfaces principais:

- `IdentityProvider` — autentica ou atesta identidade do signatário;
- `ConsentProvider` — registra aceite/consentimento quando aplicável;
- `SigningProvider` — cria ou executa a assinatura;
- `ValidationProvider` — valida assinatura, certificado, cadeia e integridade;
- `TimestampProvider` — emite ou valida carimbo do tempo;
- `TrustPolicyProvider` — resolve política, algoritmos, cadeia confiável e requisitos mínimos;
- `EvidenceStore` / `EvidenceService` — registra a trilha de evidências;
- `DocumentArtifactStore` — persiste documento original e artefatos derivados.

Essas interfaces podem ser implementadas por um mesmo adapter quando uma plataforma externa oferece várias funções, mas permanecem separadas no Core.

### 4.2 Registro de capacidades

Cada adapter deve declarar metadados semelhantes a:

- identificador e versão;
- tipo de provider;
- métodos de autenticação suportados;
- níveis de assinatura suportados;
- formatos e contêineres suportados;
- algoritmos suportados;
- timestamp disponível ou obrigatório;
- validação disponível;
- modo `fake`, `development`, `sandbox` ou `production`;
- requisitos externos, como HSM, PKCS#11, Java, API remota ou agente local.

O Core selecionará providers por política e capacidade, nunca por condicionais específicas espalhadas pelo domínio.

## 5. Modelo de domínio

### 5.1 Solicitação documental

`SignatureRequest` deixa de representar um único signatário como estrutura central e passa a representar um processo documental.

Campos conceituais:

- `id`;
- `tenantId`;
- `status`;
- `documentSha256`;
- `documentArtifactId`;
- `trustProfileId`;
- `signatureLevel`;
- `signatureFormat`;
- `signingMode` (`parallel` ou `sequential`);
- `participants[]`;
- `providerBindings[]`;
- `resultArtifacts[]`;
- timestamps de criação e conclusão.

### 5.2 Participante

Cada signatário recebe identidade e ciclo próprios:

- `participantId`;
- nome e identificadores conhecidos;
- papel (`signer`, `approver`, `witness`, `seal` ou extensível);
- ordem quando sequencial;
- requisitos de autenticação;
- estado de autenticação;
- estado de consentimento;
- estado de assinatura;
- provider bindings;
- evidências relacionadas.

### 5.3 Estados

Estado global sugerido:

`draft -> awaiting_participants -> partially_completed -> validating -> completed`

Estados terminais adicionais:

- `rejected`;
- `expired`;
- `cancelled`;
- `failed`.

Cada participante possui máquina de estados independente, evitando que uma assinatura parcial seja confundida com conclusão do documento.

## 6. Níveis e formatos

### 6.1 Níveis

O Core deve modelar pelo menos:

- `simple`;
- `advanced`;
- `qualified`.

O nível representa a política/requisito de confiança, não uma biblioteca específica.

### 6.2 Formatos e contêineres

O modelo deve ser extensível e começar com identificadores para:

- PAdES;
- CAdES/CMS;
- XAdES;
- XMLDSig;
- detached signature;
- ASiC;
- JAdES como extensão futura;
- assinatura proprietária via provider, desde que marcada como tal.

O suporte real a cada formato será entregue por adapters específicos em histórias posteriores.

## 7. Autenticação do signatário

Autenticação não é sinônimo de assinatura documental.

O modelo deve aceitar métodos combináveis, como:

- e-mail;
- OTP por e-mail;
- OTP por SMS;
- TOTP;
- OIDC/OAuth2/SSO;
- WebAuthn/passkeys;
- autenticação via provider externo;
- certificado digital;
- biometria fornecida por integração autorizada;
- autenticação governamental quando houver integração elegível;
- mecanismos futuros registrados por capability.

Cada autenticação gera evidência contendo método, instante, provider, resultado, correlação e metadados mínimos permitidos pela política de privacidade.

## 8. Certificação e PKI FAKE

### 8.1 Finalidade

A D-009B terá uma PKI/certificação FAKE oficial para validação inicial do produto. Ela será usada exclusivamente em desenvolvimento, testes automatizados, demonstrações controladas e homologação técnica interna.

Ela deve permitir validar ponta a ponta:

- emissão de certificado fake;
- cadeia fake raiz/intermediária;
- assinatura de documento com identidade simulada;
- validação da cadeia;
- certificado válido;
- certificado expirado;
- certificado revogado;
- cadeia desconhecida;
- assinatura inválida;
- hash divergente;
- timestamp fake válido e inválido;
- múltiplos signatários;
- rotação de certificado;
- falhas de provider.

### 8.2 Regras obrigatórias de segurança

A PKI FAKE deve seguir estas regras:

- CA raiz própria e exclusiva de desenvolvimento;
- nomes contendo `FAKE`, `DEV` ou `TEST` de forma visível;
- trust profile `fake-dev` separado dos perfis reais;
- certificados fake nunca entram em trust store de produção;
- chaves fake nunca são usadas como fallback quando um provider real falhar;
- API e evidências expõem `trustMode: fake`;
- documentos assinados em modo fake recebem metadado inequívoco de ambiente não produtivo;
- configuração produtiva deve rejeitar provider/certificado fake por padrão;
- CI deve possuir teste que prove que o profile de produção rejeita a cadeia fake.

### 8.3 Componentes

A primeira implementação deverá conter:

- `FakeCertificateAuthority`;
- `FakeCertificateProvider`;
- `FakeSigningProvider`;
- `FakeValidationProvider`;
- `FakeTimestampProvider`;
- fixtures determinísticas para testes;
- cenários de revogação/expiração simulados.

A emissão fake poderá ser determinística em testes, mas nenhuma chave privada fake deverá ser persistida em banco de aplicação como se fosse credencial de usuário real.

## 9. Perfis de confiança

Introduzir `TrustProfile` para impedir configurações ad hoc perigosas.

Perfis iniciais:

- `fake-dev` — aceita exclusivamente cadeia e providers fake;
- `sandbox` — reservado para providers externos de teste;
- `production-standard` — inicialmente sem providers habilitados até configuração explícita;
- perfis regulatórios futuros, incluindo ICP-Brasil, devem ser adicionados como configuração/versionamento separado.

Um perfil define:

- nível mínimo;
- métodos de autenticação permitidos;
- formatos aceitos;
- providers permitidos;
- algoritmos permitidos;
- timestamp exigido ou opcional;
- política de revogação;
- requisitos de validação;
- retenção de evidências.

## 10. Providers open source e comerciais

A arquitetura deverá permitir adapters para engines open source ou comerciais sem dependência direta do Core.

Candidatos open source já mapeados para avaliação posterior incluem:

- Demoiselle Signer;
- DSS / Digital Signature Services;
- pyHanko;
- LibreSign;
- SignServer Community;
- Documenso/OpenSign quando aplicável ao fluxo documental.

Cada integração deverá passar por análise técnica, segurança, manutenção e licença antes de incorporação.

Adapters com runtime incompatível com o serviço Node.js podem rodar como serviço separado com contrato HTTP/eventos e autenticação mútua.

## 11. Compatibilidade com v0.1.0

O `SignatureProvider` atual não será removido abruptamente.

Será criado um adapter de compatibilidade que converte o contrato legado em uma implementação limitada do novo `SigningProvider`.

Durante a transição:

- endpoints v1 atuais continuam funcionais;
- solicitações v1 podem ser convertidas internamente para um participante único;
- `providerRequestId` legado permanece disponível enquanto necessário;
- novas capacidades entram em endpoint/DTO versionado ou por campos opcionais compatíveis;
- remoção do contrato legado exige depreciação explícita em versão posterior.

## 12. Persistência

A evolução do schema deverá separar entidades para evitar JSONs monolíticos.

Entidades previstas:

- `signature_requests`;
- `signature_participants`;
- `provider_bindings`;
- `document_artifacts`;
- `signature_artifacts`;
- `validation_results`;
- `trust_profiles`;
- `signature_evidence`.

A migração deve ser aditiva na primeira fase e preservar os dados v0.1.0.

## 13. Evidências e auditoria

Eventos mínimos previstos:

- `signature.requested`;
- `identity.challenge.created`;
- `identity.verified`;
- `consent.recorded`;
- `signature.started`;
- `signature.completed`;
- `signature.failed`;
- `timestamp.applied`;
- `validation.completed`;
- `certificate.status.checked`;
- `participant.rejected`;
- `request.completed`;
- `request.cancelled`.

Cada evidência deve possuir tenant, request, participante quando aplicável, instante, provider, correlação, hash e payload mínimo suficiente para auditoria sem armazenar segredos.

## 14. Fluxo de dados

1. Cliente autenticado cria processo documental.
2. Core calcula hash e persiste artefato original.
3. `TrustProfile` resolve requisitos.
4. Core cria participantes e bindings necessários.
5. `IdentityProvider` executa autenticação exigida.
6. Consentimento é registrado quando aplicável.
7. `SigningProvider` executa ou encaminha assinatura.
8. Artefato assinado é armazenado e hasheado.
9. `TimestampProvider` é executado conforme política.
10. `ValidationProvider` valida assinatura, integridade e confiança.
11. Evidências são registradas em cada etapa.
12. O processo só chega a `completed` se a política de confiança for satisfeita.

## 15. Tratamento de erros

Erros devem ser classificados por domínio, sem vazar detalhes internos do provider:

- `UNSUPPORTED_CAPABILITY`;
- `TRUST_POLICY_VIOLATION`;
- `IDENTITY_VERIFICATION_FAILED`;
- `SIGNING_PROVIDER_UNAVAILABLE`;
- `SIGNATURE_REJECTED`;
- `SIGNATURE_INVALID`;
- `CERTIFICATE_EXPIRED`;
- `CERTIFICATE_REVOKED`;
- `CERTIFICATE_UNTRUSTED`;
- `TIMESTAMP_INVALID`;
- `DOCUMENT_HASH_MISMATCH`;
- `PROVIDER_PROTOCOL_ERROR`.

Falha de provider real nunca deve causar fallback automático para provider fake.

## 16. Testes

A D-009B deverá manter TDD e ampliar os gates existentes.

Categorias:

- testes unitários de domínio;
- testes de máquina de estados global e por participante;
- testes contratuais compartilhados para providers;
- testes do capability registry;
- testes de isolamento multi-tenant;
- testes de política de confiança;
- testes completos com PKI FAKE;
- testes de expiração/revogação fake;
- testes que impeçam uso fake em `production-standard`;
- compatibilidade regressiva de endpoints v1;
- `security:check`, TypeScript, testes e build obrigatórios antes de merge.

## 17. Sequência de evolução

- **D-009B** — Universal Trust Capability Model + PKI FAKE;
- **D-009C** — Identity & Consent;
- **D-009D** — Cryptographic Signing / adapters de formatos;
- **D-009E** — Validation, revocation, LTV e timestamp;
- **D-009F** — Open Source Adapters;
- **D-009G** — Market/Cloud Providers;
- **D-009H** — HSM/PKCS#11/remote signing e hardening produtivo, quando necessário.

Cada etapa deve ser dividida em microentregas e preservar os gates de qualidade já adotados no D-009.

## 18. Fora do escopo desta especificação

- escolher um fornecedor comercial definitivo;
- emitir certificados legalmente válidos;
- declarar conformidade ICP-Brasil sem homologação específica;
- armazenar chave privada de usuário no banco;
- implementar biometria própria;
- aplicar migration em ambiente produtivo;
- ativar credenciais reais;
- substituir o fluxo atual sem camada de compatibilidade.

## 19. Critérios de aceite da D-009B

A D-009B estará pronta para implementação quando o plano contemplar:

1. capability registry independente de provider;
2. contratos separados de identidade, assinatura, validação e timestamp;
3. modelo multi-participante;
4. trust profiles;
5. PKI/certificação FAKE isolada;
6. casos fake de válido, expirado, revogado, cadeia desconhecida e assinatura inválida;
7. impossibilidade comprovada de provider fake ser usado por profile produtivo;
8. compatibilidade com o provider fake e endpoint v1 existentes;
9. migração aditiva;
10. testes contratuais e security gate GREEN.

## 20. Decisão arquitetural

A arquitetura oficial será híbrida:

- Core TypeScript/Fastify orientado a capacidades;
- adapters locais quando simples e seguros;
- adapters externos/sidecars quando exigirem runtime ou ciclo de vida próprio;
- PKI FAKE como infraestrutura de teste, nunca como mecanismo produtivo;
- evolução incremental e versionada, preservando a v0.1.0 como checkpoint estável.
