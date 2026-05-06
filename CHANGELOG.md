# Changelog

All notable changes to pgsigchain are documented here. The format follows
[Keep a Changelog](https://keepachangelog.com/en/1.1.0/) and the project follows
[Semantic Versioning](https://semver.org/spec/v2.0.0.html).

## [0.3.0] - 2026-05-05

### Added

- Captura de actor no trigger: cada entrada de `chain_log` agora grava `actor_user`, `actor_app`, `actor_addr`, `actor_pid` capturados via `current_user`, `current_setting('application_name')`, `inet_client_addr()`, `pg_backend_pid()`. O actor entra no `row_hash`, então adulteração das colunas de actor é detectada por `verify_data`.
- `pgsigchain.export_manifest()` retorna um JSONB com a lista completa de tabelas protegidas, suas chain heads, contagens e pubkeys — pensado para ancoragem externa do *conjunto* (resolve meta-tampering em `pgsigchain.protected_tables`).
- Trigger `BEFORE TRUNCATE` instalado nos dois modos. `TRUNCATE` numa tabela protegida agora levanta `pgsigchain: TRUNCATE not allowed on protected table "X"` em vez de apagar tudo silenciosamente.
- `pgsigchain.truncate_trigger()` registrada como função C interna.
- `pgsigchain.find_tampered_rows(table)` — SRF forense. Quando `verify_data` retorna `f`, esta função devolve cada row em conflito com `row_pk`, `chain_log_id`, `expected_hash`, `actual_hash`, `recorded_actor` e `recorded_at`. Também detecta rows órfãs (insert que bypassou trigger via `DISABLE TRIGGER`).
- `pgsigchain.check_all()` — roda `audit_check` em todas as tabelas protegidas e devolve `(table_name, check_name, passed, details)`. Helper para monitoramento agregado em uma chamada.
- `pgsigchain.check_all_and_notify(channel TEXT DEFAULT 'pgsigchain_alert')` — roda `check_all`; se houver alguma falha, dispara `pg_notify(channel, json_payload)` com `{detected_at, failures: [...]}` e retorna `false`. Pensado pra ser chamado por cron / `pg_cron` com listener na aplicação.

### Changed

- Tagline definida como "Tamper-evident append-only audit log for PostgreSQL — signed hash chain". Deixa claro que não é blockchain (sem descentralização, consenso ou trustlessness) e enfatiza a primitiva (cadeia de hashes assinada).
- README ganhou seção "O que pgsigchain não é" para alinhar expectativas (não é descentralizado, não impede superuser, não prova ausência, não tem time confiável).
- `pgsigchain_compute_row_hash` mudou de saída textual (`OidOutputFunctionCall`) para saída binária (`OidSendFunctionCall`). Hashes agora são estáveis através de mudanças em `datestyle`, `extra_float_digits`, `timezone`, locale, e mais resistentes a mudanças de formatação default entre versões do Postgres.

### Fixed

- `verify_data` agora também busca os campos de actor de `chain_log` ao recomputar o hash. Sem isso, a inclusão do actor no hash teria quebrado a verificação.

### Security

- `TRUNCATE` deixou de ser um bypass silencioso da chain — antes apagava todas as rows da tabela protegida sem touch em `chain_log`, fazendo `verify_data` retornar `true` (zero rows = zero mismatches).
- Sem `actor_user` registrado, era impossível atribuir uma entrada a um responsável. Agora o "quem" está no log e no hash; alterar quem retroativamente é detectável.

## [0.2.0] - 2026-04-26

Redesenho amplo: modos de protecao, blocos imutaveis, assinaturas Ed25519 sem
persistir privada, ancoragem externa e encoding canonico de hash.

### Added

- Modo `audit` em `pgsigchain.protect(table, mode)` que loga `INSERT`/`UPDATE`/`DELETE` em vez de bloquear.
- Parametro `auto_finalize INT` em `pgsigchain.protect` para selar um bloco a cada N entradas.
- Blocos imutaveis: `pgsigchain.finalize_block`, `pgsigchain.block_info`, `pgsigchain.verify_blocks` e tabela `pgsigchain.blocks` com Merkle tree e `prev_block_hash` por bloco.
- Tabela `pgsigchain.merkle_nodes` persistindo a Merkle tree completa por bloco.
- Assinaturas digitais Ed25519: `pgsigchain.generate_keypair`, `pgsigchain.set_signing_key` (so pubkey), `pgsigchain.sign_chain_entry` (privada nunca persistida), `pgsigchain.verify_signature`, `pgsigchain.get_public_key`.
- Tabela `pgsigchain.signing_keys` com pubkey por tabela protegida.
- `pgsigchain.verify_data(table)` recomputa o hash de cada row viva e compara contra o `row_hash` mais recente em `chain_log` (detecta tampering pos-trigger).
- Ancoragem externa: tabela `pgsigchain.anchors` mais `pgsigchain.export_block`, `pgsigchain.record_anchor`, `pgsigchain.verify_anchor`, `pgsigchain.anchor_status`.
- Helper `pgsigchain.encode_pk(VARIADIC text[])` para computar a forma canonica hex da PK fora do trigger.
- `pgsigchain.audit_check(table)` em PL/pgSQL agregando `verify_chain`, `verify_data`, `verify_blocks` e `verify_anchors` num relatorio.
- Coluna `operation` (`INSERT`/`UPDATE`/`DELETE`) e `new_row_hash` em `pgsigchain.chain_log` para suportar o modo audit.
- `pg_extension_config_dump` em todas as tabelas internas e suas sequences para que `pg_dump` preserve a trilha completa.

### Changed

- `pgsigchain.protect` agora aceita `mode TEXT DEFAULT 'immutable'` (`'immutable'` ou `'audit'`) e `auto_finalize INT DEFAULT NULL`.
- `pgsigchain.unprotect` agora aceita `force BOOLEAN DEFAULT false` e recusa por padrao quando ha entradas em `chain_log` ou `blocks`.
- `chain_log.row_pk` mudou para encoding canonico length-prefixed em hex; `verify_row` e `merkle_proof` agora exigem `pgsigchain.encode_pk(...)` ao consultar.
- Trigger `chain_trigger` mudou de `BEFORE INSERT` para `AFTER INSERT` para enxergar colunas `GENERATED ALWAYS AS`.
- Trigger `audit_trigger` instalado como `AFTER INSERT OR UPDATE OR DELETE` pelo mesmo motivo.
- `pgsigchain.set_signing_key` agora aceita pubkey (64 hex / 32 bytes) em vez de privkey; o banco nao armazena mais a chave privada.
- Schema de `pgsigchain.signing_keys`: coluna `private_key` removida; restou apenas `public_key` mais `key_algorithm`.
- FK `chain_log.block_id` e FK `anchors.block_id` agora tem `ON DELETE CASCADE`.

### Fixed

- Hash de row deixou de ser colidivel: encoding canonico com length-prefix (1 byte tag NULL/non-NULL + 4 bytes BE de tamanho + bytes do campo). Antes, `('ab','c')` e `('a','bc')` produziam o mesmo hash.
- Race entre transacoes concorrentes que liam o mesmo `prev_hash` e bifurcavam a chain: triggers agora chamam `pg_advisory_xact_lock(table_oid)` antes de ler/escrever.
- PK composto contendo virgula em algum valor (ex.: `('foo,bar','baz')`) deixava `verify_row` ambiguo. Resolvido junto com o encoding canonico length-prefixed.

### Security

- Chave privada Ed25519 nunca mais e persistida no banco. O operador passa a privkey por chamada para `pgsigchain.sign_chain_entry`; a funcao deriva a pubkey, confirma que bate com a registrada em `pgsigchain.signing_keys` e atualiza apenas a coluna `signature`.
- `pgsigchain.unprotect` deixou de ser uma porta de saida silenciosa para apagar a trilha de auditoria — exige `force => true` explicito quando ha `chain_log` ou `blocks`.
- Ancoragem externa via `pgsigchain.record_anchor` permite registrar um ponteiro para evidencia off-DB (S3 com Object Lock, OpenTimestamps, transparency log, etc.); `pgsigchain.verify_anchor` detecta reescrita posterior do bloco. Sem isso, o dono do banco continua podendo reescrever a chain inteira sem deixar rastro.

## [0.1.0] - sem release publico

Prototipo original, nunca tagueado para distribuicao. Apenas modo immutable, sem
blocos, sem assinaturas, sem ancoras e com hashing por concatenacao simples
(suscetivel a colisoes entre rows distintas).
