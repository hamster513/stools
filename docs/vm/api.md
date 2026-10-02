# API модуля Vulnerability Management

Все ручки под `/api/vm`, требуют сессию платформы (cookie `stools_session`).
Ошибки — `{"detail": "текст по-русски"}`. Дизайн — `docs/superpowers/specs/2026-09-09-vm-module-design.md`.

## Уязвимости

```
GET /vulns     q, host, cve, criticality, zone, os, level, exploits, msf,
               cvss_source, host_id, status, assignee, overdue, risk_expiring,
               sort, limit≤1000 (200), offset
               → {total, items[], facets|null}    фасеты только при offset=0
GET /vulns/{host_id}/{cve_id}   карточка расчёта: host, cve, risk{множители
                                с source и substituted}, refs_loaded_at
GET /hosts/{host_id}            хост и его пары (до 500, по риску)
GET /export    те же фильтры → text/csv, BOM, «;», потоково; последние
               колонки — Статус, Исполнитель, Срок
GET /overview  счётчики, distribution, findings, top_cves, top_hosts, data{…}
```

`sort`: `risk_desc` (по умолчанию; при равном балле — по сырому риску),
`risk_asc`, `cvss_desc`, `epss_desc`, `exploits_desc`, `host_asc`, `cve_asc`.
`level`: `low | medium | high | critical` (0–19, 20–39, 40–69, 70–100).

### Статусы пар

У пары хост × CVE — общий статус находки платформы (`/api/findings/*`,
`module = "vm"`, `scope_id = 0`), ключ — `hostname|ip|cve` из `vm_host` как
есть (без приведения регистра). Хост с новым IP — новые пары: статус не
переносится.

- Список: `status` — коды через запятую или `all`, по умолчанию открытые
  (`new, in_work, fixed, reopened`; с `risk_expiring` — принятые);
  `assignee` — `me | none | <логин>`; `overdue`, `risk_expiring` — `true`.
  Строка: `key, status, status_title, assignee, assignee_name, due_date,
  overdue, risk_until, first_seen_at`. Возраста у пар нет: VM не хранит,
  в каком импорте пара появилась (`first_seen_at` — `null`).
- Фасеты первой страницы дополнены `status` (без своего фильтра),
  `assignee` (`none` и логины), `flags{overdue, risk_expiring}` — как у AD.
- После импорта — сверка: пара с решением, которой нет в новом импорте,
  становится `resolved` (принятый риск и ложное срабатывание не меняются,
  `present = false`); вернувшаяся — `reopened`. Пара, о которой ничего не
  решали, исчезает без следа: строк для неё не заводится, истории
  «устранена» у неё нет.
- `POST /api/findings/bulk` с `keys` (≤ 5000) — сразу `{changed}`; с
  `filter` (те же параметры, что у `/vulns`, без `sort`, `limit`, `offset`)
  — 202 `{job_id}`: задача `vm_job` `kind = bulk_status` меняет пары
  кусками по 1000 с общим `bulk_id`, прогресс и отмена — `/jobs/{id}`;
  сделанное до отмены остаётся. Ошибка фильтра или смены (нет обоснования,
  исполнителя нет в справочнике) — 422 до запуска задачи.
- `/overview`: `pairs`, `distribution`, `above_threshold` и слой ATT&CK
  считают пары с учитываемым статусом (настройка `counted`, по умолчанию без
  «Принят риск», «Ложное срабатывание», «Устранена»); `pairs_all` — все
  пары; `findings` — сводка статусов (`by_status`, `overdue`,
  `risk_expiring`, `unassigned`). Топы CVE и хостов — по всем парам.

## Данные

```
POST /import/vm                 {job_id} | 400 не настроено | 409 уже идёт
POST /import/file  multipart file=<csv|json>   {job_id} | 409
GET  /import                    {last: vm_import|null, active: job|null}
GET  /refs                      [{name, title, url, loaded_at, source, records, detail, stale, active_job_id}]
POST /refs/{name}/download      {years?} (nvd)  → {job_id} | 409
POST /refs/{name}/upload        multipart files=…  → {job_id}
POST /recalculate               {job_id} | 409
```

`name`: `epss | nvd | exploitdb | msf | attack` (CVE → ATT&CK, CTID).

## Настройки

```
GET  /settings   {connection{host, username, verify_tls, os_exclude, pdql_extra,
                  limit, password_set, client_secret_set, configured},
                  weights, threshold, attack_min_risk,
                  defaults{weights, threshold, attack_min_risk}}
PUT  /settings   {connection{…, password, client_secret}, weights, threshold,
                  attack_min_risk}
                 пустой пароль/секрет — оставить прежние
POST /settings/test-vm   {ok, message}   токен и PDQL limit(1)
GET  /zones      [{name, internet_access, confidential_data, marked, hosts}]
PUT  /zones      [{name, internet_access, confidential_data}] → 204
```

## Задачи

```
GET  /jobs?limit        идущие сверху, затем последние
GET  /jobs/{id}         {id, kind, stage, status, progress, processed, total,
                         message, error, cancel_requested, started_at,
                         finished_at, started_by}
POST /jobs/{id}/cancel  204 | 409 уже завершена
```

`kind`: `import_vm | import_file | ref_epss | ref_nvd | ref_exploitdb | ref_msf |
ref_attack | recalculate | bulk_status`.
Стадии импорта: `fetching → parsing → writing → enriching → scoring → done`;
отмена принимается до `writing`.
