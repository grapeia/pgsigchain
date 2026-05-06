# pgsigchain — PostgreSQL Ledger

> [English](README.md) · **Português**

Extensão PostgreSQL que adiciona um **ledger tamper-evident append-only** a tabelas existentes. Cada INSERT é encadeado por hash (SHA-256), agrupado em blocos imutáveis, opcionalmente assinado (Ed25519) e ancorável externamente (S3 Object Lock, OpenTimestamps, etc.) — para que reescritas posteriores do log sejam detectáveis mesmo por quem desconfia do dono do banco.

Não é uma blockchain: não há descentralização, consenso ou trustlessness. É um log de auditoria com integridade criptográfica que pode ser commitado externamente.

## O que pgsigchain não é

- Não substitui um sistema de auditoria distribuído (Merkle trees, Ethereum, etc.).
- Não impede um superuser de desabilitar triggers e adulterar a chain — só torna isso *detectável* via `verify_chain` + `verify_data` + ancoragem externa.
- Não protege a *ausência* de eventos — só pode logar o que passa pelos triggers.
- Tempo absoluto (`created_at`) não é confiável — ordem é. Para "quando" confiável, depende dos anchors externos.

## Requisitos

- Docker e Docker Compose

## Quick Start

```bash
# Build e start
docker compose up -d

# Conectar
psql -h localhost -p 5433 -U postgres -d pgsigchain_test
# senha: pgsigchain
```

A extensao ja vem criada automaticamente no banco `pgsigchain_test`.

## Build sem Docker

```bash
# Dependencias (Debian/Ubuntu)
sudo apt install postgresql-server-dev-16 libssl-dev build-essential

# Compilar e instalar
make && sudo make install

# No PostgreSQL
CREATE EXTENSION pgsigchain;
```

## Uso

### Proteger uma tabela

```sql
CREATE TABLE ledger (
    id SERIAL PRIMARY KEY,
    amount INT NOT NULL,
    description TEXT
);

-- Modo padrao: immutable, sem auto-finalizacao
SELECT pgsigchain.protect('ledger');
```

A tabela precisa ter uma **primary key**. Assinatura completa:

```sql
pgsigchain.protect(table_name TEXT, mode TEXT DEFAULT 'immutable', auto_finalize INT DEFAULT NULL)
```

- `mode = 'immutable'` (padrao) — bloqueia UPDATE/DELETE, registra so INSERT
- `mode = 'audit'` — permite e registra INSERT/UPDATE/DELETE
- `auto_finalize = N` — finaliza automaticamente um bloco a cada N entradas

### Inserir dados

```sql
INSERT INTO ledger (amount, description) VALUES (100, 'deposit');
INSERT INTO ledger (amount, description) VALUES (-50, 'withdrawal');
INSERT INTO ledger (amount, description) VALUES (200, 'bonus');
```

Cada operacao gera uma entrada no `pgsigchain.chain_log` com:

| Campo | Descricao |
|---|---|
| `row_pk` | encoding canonico length-prefixed da PK, hex (ver `encode_pk`) |
| `row_hash` | SHA-256 das colunas com encoding canonico length-prefixed |
| `prev_hash` | `chain_hash` da entrada anterior (ou `0` para a primeira) |
| `chain_hash` | SHA-256(`prev_hash` \|\| `row_hash`) |
| `operation` | `INSERT`, `UPDATE` ou `DELETE` |
| `new_row_hash` | apenas em `UPDATE` (modo audit), hash do estado novo |

### Modos: immutable vs audit

```sql
-- Modo immutable (padrao)
SELECT pgsigchain.protect('ledger', 'immutable');
UPDATE ledger SET amount = 999 WHERE id = 1;
-- ERROR: pgsigchain: UPDATE not allowed on protected table "ledger"

-- Modo audit
CREATE TABLE events (id SERIAL PRIMARY KEY, payload JSONB);
SELECT pgsigchain.protect('events', 'audit');

INSERT INTO events (payload) VALUES ('{"type":"login"}');
UPDATE events SET payload = '{"type":"login","ip":"1.2.3.4"}' WHERE id = 1;
DELETE FROM events WHERE id = 1;
-- todas as operacoes aparecem em pgsigchain.chain_log com a coluna `operation`
```

### Verificacao

```sql
-- Toda a chain (recalcula cada chain_hash)
SELECT pgsigchain.verify_chain('ledger');

-- Uma row especifica — usa row_pk codificado
SELECT pgsigchain.verify_row('ledger', pgsigchain.encode_pk('1'));

-- Compara o estado atual da tabela contra o ultimo hash registrado
-- Detecta tampering que tenha contornado os triggers (ex.: superuser)
SELECT pgsigchain.verify_data('ledger');
```

`verify_data` recalcula o hash de cada row viva na tabela e compara com o `row_hash` mais recente em `chain_log`. Util para detectar `UPDATE` direto via `pg_class` ou writes que tenham desabilitado triggers.

### Merkle tree

A Merkle tree e construida sobre as entradas de um bloco finalizado.

```sql
SELECT pgsigchain.build_merkle('ledger');
-- b76cffe87fa05aadc84f3e8e921ec8cdde0100c88728f9dba095d3d2f85aa443

SELECT pgsigchain.merkle_root('ledger');

-- Proof de uma row (precisa do row_pk codificado)
SELECT pgsigchain.merkle_proof('ledger', pgsigchain.encode_pk('1'));
-- {R:eb8e4572...,R:eb0a852f...}
```

O proof retorna hashes prefixados por direcao (`L` / `R`). Com proof + row_hash da pra recalcular o root.

### Blocos

Entradas do `chain_log` sao seladas em blocos imutaveis. Cada bloco tem sua propria Merkle tree e `prev_block_hash` formando uma chain de segundo nivel.

```sql
-- Finaliza manualmente: agrupa entradas pendentes em um novo bloco
SELECT pgsigchain.finalize_block('ledger');
-- 1   (block_number)

-- Lista todos os blocos
SELECT * FROM pgsigchain.block_info('ledger');
```

| block_number | block_hash | prev_block_hash | entries_count | merkle_root | created_at |
|---|---|---|---|---|---|
| 1 | a1b2... | 0 | 3 | b76c... | 2026-04-26 ... |

```sql
-- Verifica que cada block_hash bate com merkle_root + prev_block_hash
SELECT pgsigchain.verify_blocks('ledger');
```

Para finalizacao automatica, passe `auto_finalize` no `protect`:

```sql
SELECT pgsigchain.protect('ledger', 'immutable', 100);
-- finaliza um bloco a cada 100 entradas
```

### Assinaturas digitais (Ed25519)

A chave privada **nunca e armazenada no banco**. O fluxo e operator-driven: a app gera o par, registra so a publica, e injeta a privada apenas no momento de assinar.

```sql
-- 1. Gerar par (idealmente do lado do cliente)
SELECT * FROM pgsigchain.generate_keypair();
--  public_key                     | private_key
-- --------------------------------+---------------------------------
--  MCowBQYDK2VwAyEA...             | MC4CAQAwBQYDK2VwBCIEI...

-- 2. Registrar APENAS a publica para a tabela
SELECT pgsigchain.set_signing_key('ledger', 'MCowBQYDK2VwAyEA...');

SELECT pgsigchain.get_public_key('ledger');

-- 3. Assinar uma entrada do chain_log (a privada vive so na chamada)
SELECT pgsigchain.sign_chain_entry('ledger', 1, 'MC4CAQAwBQYDK2VwBCIEI...');

-- 4. Verificar
SELECT pgsigchain.verify_signature('ledger', 1);
-- true
```

O trigger de chain **nao assina automaticamente**. Assinatura e sempre uma acao explicita do operador. A assinatura cobre o `chain_hash` da entrada e e armazenada na coluna `signature` do `chain_log`.

### Status

```sql
SELECT * FROM pgsigchain.status();
```

| schema_name | table_name | mode | protected_at | chain_length | block_count |
|---|---|---|---|---|---|
| public | ledger | immutable | 2026-04-26 ... | 3 | 1 |

### Quem fez (actor capture)

Cada entrada de `chain_log` registra automaticamente quem realizou a operação:

| Coluna | Origem |
|---|---|
| `actor_user` | `current_user` |
| `actor_app`  | `current_setting('application_name')` |
| `actor_addr` | `inet_client_addr()` (NULL para conexões locais) |
| `actor_pid`  | `pg_backend_pid()` |

Os 4 campos entram no `row_hash`, então alterar uma coluna de actor depois (via UPDATE direto em `pgsigchain.chain_log`) é detectável por `verify_data`.

### Manifesto pra ancoragem do conjunto

`pgsigchain.export_manifest()` retorna um JSONB com a lista completa de tabelas protegidas e suas chain heads atuais. Útil pra ancorar externamente o **conjunto** (não só blocos individuais), o que protege contra meta-tampering em `pgsigchain.protected_tables`:

```sql
SELECT pgsigchain.export_manifest();
```

```json
{
  "generated_at": "2026-04-26T...",
  "extension_version": "0.3.0",
  "tables": [
    {
      "schema": "public", "name": "ledger", "mode": "immutable",
      "protected_at": "...", "chain_length": 3,
      "last_chain_hash": "...", "block_count": 1,
      "last_block_hash": "...", "public_key": null
    }
  ]
}
```

### Desproteger

```sql
-- Recusa por padrao se houver dados de auditoria
SELECT pgsigchain.unprotect('ledger');
-- ERROR: pgsigchain: refusing to delete audit data; pass force => true

-- Forcar limpeza de chain_log + blocks + merkle_nodes + signing_keys
SELECT pgsigchain.unprotect('ledger', force => true);
```

## Casos de uso

Perguntas operacionais reais e o fluxo SQL pra responder — ver [`CASES.pt-BR.md`](CASES.pt-BR.md).

## Referencia da API

| Funcao | Retorno | Descricao |
|---|---|---|
| `pgsigchain.protect(table_name, mode, auto_finalize)` | void | Protege uma tabela. `mode`: `immutable`/`audit`. `auto_finalize`: N entradas por bloco. |
| `pgsigchain.unprotect(table_name, force)` | void | Remove protecao. Recusa apagar audit data sem `force => true`. |
| `pgsigchain.sha256(data bytea)` | text | SHA-256 de dados arbitrarios |
| `pgsigchain.encode_pk(VARIADIC parts text[])` | text | Encoding canonico length-prefixed da PK (hex) |
| `pgsigchain.verify_chain(table_name)` | boolean | Valida toda a hash chain |
| `pgsigchain.verify_row(table_name, row_pk)` | boolean | Valida uma row do chain_log (use `encode_pk` na PK) |
| `pgsigchain.verify_data(table_name)` | boolean | Compara estado atual da tabela vs ultimo hash registrado |
| `pgsigchain.find_tampered_rows(table_name)` | setof record | Lista as rows alteradas + hash esperado/atual + actor original |
| `pgsigchain.build_merkle(table_name)` | text | Constroi Merkle tree, retorna root |
| `pgsigchain.merkle_root(table_name)` | text | Retorna root hash armazenado |
| `pgsigchain.merkle_proof(table_name, row_pk)` | text[] | Merkle proof da row (use `encode_pk`) |
| `pgsigchain.finalize_block(table_name)` | bigint | Sela entradas pendentes num novo bloco; retorna block_number |
| `pgsigchain.block_info(table_name)` | setof record | Lista blocos (number, hash, prev_hash, entries, merkle_root, created_at) |
| `pgsigchain.verify_blocks(table_name)` | boolean | Verifica integridade da chain de blocos |
| `pgsigchain.generate_keypair()` | (text, text) | Gera par Ed25519 `(public_key, private_key)` |
| `pgsigchain.set_signing_key(table_name, public_key)` | void | Registra a chave publica da tabela |
| `pgsigchain.get_public_key(table_name)` | text | Retorna a chave publica registrada |
| `pgsigchain.sign_chain_entry(table_name, chain_log_id, private_key)` | void | Assina uma entrada (privada nao e persistida) |
| `pgsigchain.verify_signature(table_name, chain_log_id)` | boolean | Verifica assinatura de uma entrada |
| `pgsigchain.status()` | setof record | Lista tabelas protegidas com chain_length e block_count |
| `pgsigchain.export_manifest()` | jsonb | Snapshot portátil do conjunto protegido (pra ancorar externamente) |
| `pgsigchain.audit_check(table_name)` | setof record | Roda verify_chain + verify_data + verify_blocks + verify_anchor |
| `pgsigchain.check_all()` | setof record | `audit_check` em todas as tabelas protegidas |
| `pgsigchain.check_all_and_notify(channel)` | boolean | Roda check_all; se houver falha, dispara `pg_notify(channel, json)` e retorna false |
| `pgsigchain.export_block(table_name, block_number)` | jsonb | Exporta um bloco em JSON pra ancoragem externa |
| `pgsigchain.record_anchor(table, block_number, type, ref, notes)` | bigint | Registra ponteiro pra evidência off-DB |
| `pgsigchain.verify_anchor(anchor_id)` | boolean | Confirma que o bloco ainda bate com o anchor |
| `pgsigchain.anchor_status(table_name)` | setof record | Por bloco: anchor_count, all_valid, last_anchored |

## Tabelas internas

Todas no schema `pgsigchain`. Marcadas com `pg_extension_config_dump`, entao `pg_dump` preserva o conteudo.

- **`pgsigchain.protected_tables`** — registro de tabelas (oid, schema, nome, mode, auto_finalize_threshold)
- **`pgsigchain.chain_log`** — log encadeado (row_pk, row_hash, prev_hash, chain_hash, operation, new_row_hash, block_id, signature, actor_user, actor_app, actor_addr, actor_pid)
- **`pgsigchain.blocks`** — blocos finalizados (block_number, prev_block_hash, block_hash, entries_count, merkle_root)
- **`pgsigchain.merkle_nodes`** — nos das Merkle trees por bloco (level, position, hash, left_child, right_child, block_id)
- **`pgsigchain.signing_keys`** — chave publica por tabela (Ed25519). Privadas nunca sao armazenadas.
- **`pgsigchain.anchors`** — registros de ancoragem externa (block_id, anchor_type, anchor_ref, block_hash_at_anchor, notes)

`TRUNCATE` numa tabela protegida é bloqueado nos dois modes — sem isso, seria um bypass silencioso (apagaria todas as rows sem touch em `chain_log`).

## Como funciona

```
INSERT/UPDATE/DELETE row
    |
    v
[chain_trigger | audit_trigger]
    |
    +---> row_pk = encode_pk(pk1, pk2, ...)         (length-prefixed, hex)
    +---> row_hash = SHA-256(canonical(col1,...,colN))  (length-prefixed)
    +---> prev_hash = chain_hash da ultima entrada (ou "0")
    +---> chain_hash = SHA-256(prev_hash || row_hash)
    +---> INSERT INTO pgsigchain.chain_log
    +---> se auto_finalize atingido -> finalize_block()


UPDATE/DELETE em modo immutable
    |
    v
[immutable_trigger]  ->  ERROR: not allowed


finalize_block
    |
    v
entradas pendentes -> Merkle tree -> merkle_root
    |
    +---> block_hash = SHA-256(prev_block_hash || merkle_root || entries_count)
    +---> INSERT INTO pgsigchain.blocks
    +---> chain_log.block_id = novo bloco
```

O encoding canonico length-prefixed (`len(c1)||c1||len(c2)||c2||...`) elimina ambiguidades de concatenacao simples (ex.: `"ab"+"c"` vs `"a"+"bc"`), evitando colisoes de hash entre rows distintas.

## Estrutura do projeto

```
pgsigchain/
├── Makefile              # Build PGXS
├── pgsigchain.control          # Metadata da extensao
├── Dockerfile            # Build em container
├── docker-compose.yml
├── sql/
│   └── pgsigchain--0.3.0.sql   # Schema e declaracao das funcoes
├── src/
│   ├── pgsigchain.c            # Entry point
│   ├── hash.c            # SHA-256 (OpenSSL EVP)
│   ├── chain.c           # Chain trigger (immutable + audit)
│   ├── immutable.c       # Bloqueia UPDATE/DELETE
│   ├── merkle.c          # Merkle tree
│   ├── blocks.c          # finalize_block, block_info, verify_blocks
│   ├── sign.c            # Ed25519 keypair, sign, verify
│   ├── protect.c         # protect/unprotect, encode_pk
│   └── verify.c          # verify_chain/row/data + status
├── src/include/          # Headers
└── test/                 # Regression tests
```

## Licenca

PostgreSQL License — ver [`LICENSE`](LICENSE).
