# pgsigchain — Casos de uso

> [English](CASES.md) · **Português**
>
> Voltar para o [README](README.pt-BR.md).

Perguntas operacionais e o fluxo SQL para responder — ordenadas pela jornada típica do usuário, de "acabei de proteger uma tabela" passando por threat models avançados até monitoramento em produção.

## "Quais tabelas estão protegidas e em que estado?"

```sql
-- Visão rápida:
SELECT * FROM pgsigchain.status();

-- Snapshot portátil pra ancorar o conjunto inteiro:
SELECT pgsigchain.export_manifest();
```

`status()` retorna cada tabela protegida com `chain_length` e `block_count`. `export_manifest()` retorna um JSONB com a última `chain_hash`, `block_hash` e pubkey de cada tabela — útil pra ancorar o **conjunto** externamente, o que protege contra meta-tampering em `pgsigchain.protected_tables`.

## "Algo foi alterado?"

A pergunta básica: o dado divergiu do que foi registrado originalmente?

```sql
SELECT pgsigchain.verify_data('contas');
-- t = todas as rows vivas ainda batem com o hash registrado
-- f = algo mudou sem passar pelo trigger
```

`verify_data` lê cada row da tabela viva, recomputa o hash com o mesmo encoding canônico, e compara com o `row_hash` mais recente em `chain_log`. Não importa por onde a alteração entrou — `ALTER TABLE ... DISABLE TRIGGER`, `UPDATE` direto em catálogos do sistema, qualquer coisa — se mudou e o log não foi atualizado, dá `f`.

Se retornar `f`, veja a próxima seção pra investigar.

## "Detectei tampering — o que mudou e quem fez a versão legítima?"

`verify_data` te diz **se** algo mudou. `find_tampered_rows` te diz **o que**:

```sql
SELECT * FROM pgsigchain.find_tampered_rows('contas');
--   row_pk    | chain_log_id | expected_hash | actual_hash | recorded_actor | recorded_at
-- -----------+--------------+---------------+-------------+----------------+-------------
--  04...0a   | 142          | 8f3a...        | bd11...      | alice          | 2026-04-12 ...
--  04...0c   |              |                | (no chain_log entry — orphan row) |  |
```

Cada row em conflito vira uma linha. Você vê:

- `row_pk` — qual row está alterada (hex canônico; decode com a tabela viva pelo PK)
- `expected_hash` vs `actual_hash` — confirma que mudou
- `recorded_actor` + `recorded_at` — quem fez o último INSERT/UPDATE *legítimo* da row (não quem tampered — a alteração ilícita não passou por trigger, então não tem actor próprio)
- `chain_log_id IS NULL` — row órfã (foi inserida bypassing trigger, ex: `DISABLE TRIGGER`)

Fluxo forense típico:

```sql
-- 1. Localiza
SELECT * FROM pgsigchain.find_tampered_rows('contas');

-- 2. Compara com backup/replica pra ver o que mudou
--    (pgsigchain só guarda hash, não o valor original — o conteúdo histórico
--    tem que vir de fora)

-- 3. Confronta com auditoria de sessão do PG
--    (pg_audit, log_statement=all, pg_stat_activity, etc.) pra ver
--    qual sessão fez o ALTER TRIGGER + UPDATE no horário em questão.

-- 4. Se o tampering aconteceu APÓS um anchor externo, o anchor
--    invalidado prova que a reescrita ocorreu depois do commit:
SELECT * FROM pgsigchain.audit_check('contas');
--   verify_data    | f       (rows alteradas)
--   verify_anchors | t/f     (se f, foi depois do anchor)
```

**O que pgsigchain te dá:** *o que mudou* (rows e hashes), *desde quando o último estado válido era esse* (via anchor ou último `verify_data` de cron), *quem fez a versão legítima anterior* (actor original).

**O que pgsigchain NÃO te dá:** *o conteúdo anterior* (só o hash), *quem fez o tamper* (a alteração ilícita não passou pelo trigger), *o exato momento do tamper* (só "entre meu último anchor e agora"). Pra essas três você precisa de backups/replicas + audit log do Postgres + monitoramento periódico.

## "Quem registrou essa entrada — e a atribuição pode ser forjada?"

Cada INSERT/UPDATE/DELETE numa tabela protegida captura automaticamente `current_user`, `application_name`, IP do cliente e pid do backend:

```sql
SELECT operation, created_at,
       actor_user, actor_app, actor_addr, actor_pid
  FROM pgsigchain.chain_log
 WHERE table_oid = 'contas'::regclass
   AND row_pk = pgsigchain.encode_pk('1234')
 ORDER BY id;
```

Os 4 campos de actor entram no `row_hash`, então reescrita retroativa é detectável:

```sql
-- Atacante com SQL direto faz:
UPDATE pgsigchain.chain_log SET actor_user = 'alice'
 WHERE id = 42;

-- Você roda:
SELECT pgsigchain.verify_data('contas');
-- f
```

Mexer em qualquer campo de actor depois do fato quebra a verificação.

## "TRUNCATE é detectado?"

Sim — `TRUNCATE` é bloqueado direto em tabelas protegidas:

```sql
TRUNCATE contas;
-- ERROR: pgsigchain: TRUNCATE not allowed on protected table "contas"
```

Um trigger `BEFORE TRUNCATE` aborta a operação. Sem ele, `TRUNCATE` passaria por baixo dos triggers per-row e `verify_data` retornaria `t` enganosamente (zero rows = zero mismatches).

## "Como provo a um terceiro que esse registro existe e nunca mudou?"

```sql
-- 1. Sela um bloco
SELECT pgsigchain.finalize_block('contas');  -- → block_number

-- 2. (uma vez) registra a chave pública pra terceiros conhecerem
SELECT pgsigchain.set_signing_key('contas', '<pubkey hex>');

-- 3. Assina a entrada com a privkey (privkey só vive na chamada)
SELECT pgsigchain.sign_chain_entry('contas', <chain_log_id>, '<privkey hex>');

-- 4. Exporta o bloco e a Merkle proof do registro
SELECT pgsigchain.export_block('contas', 1);
SELECT pgsigchain.merkle_proof('contas', pgsigchain.encode_pk('1234'));

-- 5. Ancora o bloco em algo imutável e guarda o ref
SELECT pgsigchain.record_anchor(
    'contas', 1,
    'opentimestamps', 'https://ots.example/proof/abc',
    'commit do bloco 1'
);
```

O terceiro verifica três coisas: (a) Merkle proof bate com o `merkle_root` do bloco, (b) bloco está assinado pela pubkey conhecida, (c) anchor externo aponta pro mesmo `block_hash`.

## "O DBA pode reescrever toda a chain sem eu notar?"

Cenário pior: superuser tem acesso completo e refaz `pgsigchain.chain_log` do zero. Sem anchors externos isso é indetectável de dentro do banco — a chain reescrita vai estar internamente consistente.

```sql
-- Antes (em ponto controlado): ancora externamente
SELECT pgsigchain.finalize_block('contas');
SELECT pgsigchain.record_anchor(
    'contas', 1,
    's3-versionid', 's3://audit/manifest.json#v=abc',
    NULL
);

-- Mais tarde, audita:
SELECT * FROM pgsigchain.audit_check('contas');
--    check_name    | passed
-- -----------------+--------
--  verify_chain    | t       (chain reescrita ainda é internamente consistente)
--  verify_data     | t       (dados batem com a chain reescrita)
--  verify_blocks   | f       (block_hash recomputado não bate com o gravado)
--  verify_anchors  | f       (anchor externo aponta pra hash diferente)
```

Com um anchor registrado fora do banco antes da reescrita, qualquer mexida no bloco invalida o anchor — e como o anchor está fora do banco, o atacante não consegue alterar.

## "Como monitoro isso em produção?"

pgsigchain é **pull-based**: nada notifica sozinho. Alguém — cron, app, scheduler interno — precisa chamar `verify_*` periodicamente. Os helpers para isso são:

```sql
-- Roda audit_check em TODAS as tabelas protegidas
SELECT * FROM pgsigchain.check_all();
--    table_name    |   check_name   | passed |       details
-- -----------------+----------------+--------+---------------------
--  public.contas   | verify_chain   | t      |
--  public.contas   | verify_data    | t      |
--  public.contas   | verify_blocks  | t      | 3 block(s)
--  public.contas   | verify_anchors | t      | 2 anchor(s), 0 invalid
--  public.eventos  | verify_chain   | t      |
--  ...

-- Mesma coisa, mas: retorna false se algo falhou e dispara NOTIFY com payload JSON
SELECT pgsigchain.check_all_and_notify('pgsigchain_alert');
-- false  → o NOTIFY 'pgsigchain_alert' carrega {"detected_at":"...","failures":[...]}
-- true   → tudo limpo, nenhum NOTIFY enviado
```

Três jeitos comuns de wirar isso em produção:

### 1. Cron externo + alertas (mais simples)

`/etc/cron.d/pgsigchain-monitor`:

```cron
* * * * * postgres psql -tA -d app -c "SELECT NOT pgsigchain.check_all_and_notify();" \
    | grep -q t && curl -X POST -d "pgsigchain tampering detected" $SLACK_WEBHOOK_URL
```

A cada minuto roda `check_all_and_notify`. Se voltar `t` (= teve falha), dispara webhook do Slack/PagerDuty. Simples, sem dependência extra.

### 2. pg_cron + LISTEN dentro da aplicação

Schedule no Postgres (`pg_cron`):

```sql
SELECT cron.schedule('pgsigchain-monitor', '* * * * *',
    $$SELECT pgsigchain.check_all_and_notify('pgsigchain_alert')$$);
```

Listener Node.js (qualquer driver com pub/sub Postgres serve):

```js
const client = new pg.Client(...);
await client.connect();
await client.query('LISTEN pgsigchain_alert');
client.on('notification', msg => {
    const payload = JSON.parse(msg.payload);
    alertOnCall(payload);  // PagerDuty, Sentry, etc.
});
```

Cron *dentro* do banco, alertas via canal nativo, latência sub-segundo entre detecção e alerta.

### 3. Sidecar / app-side (para verificações pontuais)

Se a aplicação já tem rotas administrativas, expose um endpoint que chama `check_all`:

```python
@app.route('/admin/integrity')
def integrity():
    rows = db.execute("SELECT * FROM pgsigchain.check_all()").fetchall()
    failures = [r for r in rows if not r.passed]
    return {'ok': not failures, 'failures': failures}, 503 if failures else 200
```

Plug isso num healthcheck do Kubernetes/load balancer, no dashboard interno, ou num runbook do oncall.

### Quando rodar

Não tem regra única — depende do volume e da criticidade. Padrões comuns:

- **A cada minuto** — sistemas financeiros / compliance estrito. `verify_data` em tabela com 100k rows demora ~1s; em 10M rows pode passar de 10s. Combine com `verify_chain` (rápido, só lê o log) na frequência alta + `verify_data` (caro, escaneia a tabela) numa frequência menor.
- **A cada hora** — auditoria normal. Suficiente para detectar tampering antes do próximo ciclo de backup.
- **A cada deploy / mudança de schema** — gate no pipeline: se `check_all` falhar, bloqueia o deploy.
- **Antes/depois de cada anchor externo** — garante que o que você está ancorando ainda está íntegro.

### Custo de cada check

| Check | Custo aproximado | Quando rodar com mais frequência |
|---|---|---|
| `verify_chain` | O(N) sequencial no `chain_log` da tabela; rápido (cabe em segundos pra milhões de entradas) | Sim, é leve |
| `verify_data` | O(M) varredura da tabela viva + 1 lookup em `chain_log` por row | Não — caro em tabelas grandes |
| `verify_blocks` | O(B) linhas em `pgsigchain.blocks`; muito rápido | Sim |
| `verify_anchor` | O(1) por anchor | Sim, é trivial |

Estratégia comum: `verify_chain` + `verify_blocks` + `verify_anchors` a cada minuto; `verify_data` a cada hora ou a cada anchor; `find_tampered_rows` só sob demanda quando algo já falhou.
