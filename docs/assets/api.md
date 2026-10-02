# API модуля Assets

Все ручки под `/api/assets`, требуют сессию платформы. Чтение — любой роли,
запись (POST, PUT, PATCH, DELETE) — аналитику и администратору, аудитору 403.
Ошибки — `{"detail": "…"}`; 422 от схемы — списком `[{loc, msg, …}]`. Время —
ISO 8601 в UTC; окна расписаний — `HH:MM` в поясе `STOOLS_TZ`.

## Обзор

```
GET  /overview                         {assets_total, by_zone, by_source, codes, networks, last_scans,
                                        last_dns, sync}
                                        by_zone: {зона: n, "": n} — "" — актив без сети или в сети без зоны
                                        by_source: {vm, ksc, ad, scan, dns: n} — источник видит актив сейчас
                                        codes: {код: n, any: n} — активов с этим расхождением (коды ниже);
                                        any — хотя бы с одним (ссылка в список с code=any)
                                        networks: {total, scanned, no_network_assets} — сетей описано,
                                        сканировалось хоть раз, активов вне описанных сетей
                                        last_scans: [{network_id, cidr, title, last_scan_at, last_scan_alive}]
                                        last_dns: [{dns_id, title, last_run_at}] — по 10, новые сверху
                                        sync: {last_sync_at, running_job_id}
```

Счётчики — те же фасеты, что у списка без фильтров: активы без
`merged_into`, расхождения на момент запроса.

## Активы

```
GET   /assets                          q, source_has, source_missing, code, network_id, zone, port,
                                       tag, criticality (Critical|High|Medium|Low|none), limit≤500 (200),
                                       offset → {total, items, facets|null}
                                       items: [{id, name, fqdn, domain, ip, os, network: {id, cidr, title,
                                       zone}|null, first_seen, last_seen, criticality, tags, pinned,
                                       sources: [{source, live, fresh, seen_at}], discrepancy_count, codes}]
                                       facets: {source, code, zone, criticality} — только при offset=0;
                                       code.any — активов хотя бы с одним расхождением
                                       code: код ниже или any — хотя бы одно расхождение
                                       неизвестное значение source_*/code/criticality — 422
GET   /assets/{id}                     + network_manual, note, merged_into, created_at, updated_at,
                                       observations: [{id, source, source_key, name, fqdn, domain, ip, ips,
                                       os, seen_at, gone_at, extra, marks: {поле: stale|conflict}}],
                                       discrepancies: [{code, source, field, value, current, text}],
                                       links: {ad_finding_count, ad_domain_id, ad_query, ksc_host_id,
                                       ksc_server_id, vm_host_id, vm_cve_count}
PATCH /assets/{id}  {criticality?, tags?, note?, network_id?, network_manual?}   → карточка
                                       только ручные поля; network_id без network_manual — сеть ручная;
                                       network_id: null, network_manual: false — вернуть расчёт по адресу
GET   /assets/ids                      те же фильтры, без limit/offset → {total, ids} — выбор «всех по
                                       фильтру» для массового изменения (не больше 50 000)
POST  /assets/bulk  {ids, criticality?, tags_add?, tags_remove?}   → {updated}
                                       критичность и теги у многих активов: теги добавляются и снимаются,
                                       а не заменяются; несуществующие и объединённые id пропускаются;
                                       422 — менять нечего или ids пуст
POST  /assets/{id}/pin    {field: name|fqdn|domain|ip|os, pinned}   → карточка
POST  /assets/{id}/merge  {other_id}   → карточка первого; 409 — уже объединён, идёт синхронизация
                                       или запись результатов скана/DNS («идёт запись результатов
                                       задачи — повторите позже»)
POST  /observations/{id}/detach        → карточка нового актива; 409 — у актива одно наблюдение,
                                       идёт синхронизация или запись результатов скана/DNS
GET   /lookup?source=&key=[&server_id=]   {asset_id} | 404 — хост модуля не сопоставлен
```

`q` ищет подстроку в имени, FQDN, IP и ОС актива и его наблюдений (старые
адреса тоже находятся). `source_has`/`source_missing` смотрят на живые
наблюдения (без `gone_at`). Значок источника `fresh` — видит сейчас и видел
моложе `stale_days`.

`lookup` — ссылка «в Assets» у хоста модуля: актив по ключу наблюдения
`(source, source_key)`. Ключи: KSC — `server_id:host_id` (или `key=host_id`
и `server_id` отдельно), VM — `hostname|ip` как в `vm_host`, AD — SID
компьютера (DN, если SID нет), `scan` — IP, `dns` — FQDN или IP. После
объединения наблюдение живёт у первого актива — ссылка ведёт к нему.

### Коды расхождений

Считаются при чтении, находок и вердиктов нет — это фильтры списка и
подсветка карточки. Сравниваются имя, FQDN и IP; ОС и домен источники пишут
по-разному, их отличие не расхождение.

| Код | Условие | Текст |
|---|---|---|
| `stale` | значение наблюдения ≠ каноническому, наблюдение старше опорного на ≥ `stale_days` | «в VM IP 192.168.6.53 от 12.09, актуальный 192.168.2.23 (DNS, 01.10) — данные VM устарели» |
| `conflict` | значение ≠ каноническому, разница меньше `stale_days` | «источники расходятся: IP в VM … (12.09), актуальный … (KSC, 01.10)» |
| `no_av` | нет живого `ksc`, есть живой `scan`, `dns` или `vm` либо включённый компьютер AD с входом не старше `inactive_days` | «нет агента антивируса» |
| `ad_inactive` | включённый компьютер AD без входа и без других источников дольше `inactive_days` | «неактивный компьютер AD: последний вход 03.06» |
| `unreachable` | IP из `ksc`/`vm`/`dns` в сети, которую сканировали, и последний скан его не нашёл | «не отвечает по известному адресу 10.10.0.11» |
| `unknown_host` | только наблюдения `scan` (и PTR из DNS) | «найдено сканером, нигде не описано» |
| `dns_orphan` | только запись зоны DNS, адрес в сканируемой сети не ответил | «запись DNS без живого хоста» |
| `no_network` | у актива есть IP, но он не входит ни в одну описанную сеть | «сеть не описана: адрес … не входит ни в одну сеть» |

Каноническое значение поля — из самого свежего по `seen_at` живого
наблюдения, где оно заполнено (при равенстве: `dns` > `scan` > `ksc` > `ad` >
`vm`); закреплённое (`pin`) не пересчитывается.

## Синхронизация с модулями

```
POST /sync                             {job_id} 202 | 409 идёт синхронизация
GET  /sync/status                      {last_sync_at, last_job_id, running_job_id,
                                        sources: {vm|ksc|ad: {live, gone, seen_at}}}
GET    /sync/schedule                  {id, interval_hours, …, tz} | null — как у сетей
PUT    /sync/schedule  {interval_hours 1–720, window_from?, window_to?, enabled}   422 — окно не HH:MM
DELETE /sync/schedule                  204
```

Читает `vm_host`, хосты последнего снапшота каждого сервера KSC и компьютеры
последней выгрузки каждого домена AD. `seen_at`: VM — время последнего
импорта, KSC и AD — `collected_at` снапшота. Модули после успешного импорта
вызывают `request_sync(db, source)`: при `sync_after_import` синхронизация
запускается сама; если уже идёт — пройдёт ещё раз после текущей. Расписание
синхронизации одно на модуль (`platform_schedule`: `assets/sync`,
`target_id = 0`); пока идёт другая синхронизация, запуск откладывается на
следующий тик. Синхронизация делит блокировку с записью результатов скана и
DNS: если блокировку держит такая запись, задача ждёт её окончания (стадия
`pending`); отказывается («синхронизация уже идёт») только когда идёт другая
синхронизация, заведённая раньше. Скан и DNS между собой не блокируются.

## Сети

```
GET    /networks                       [{id, cidr, title, description, zone, site, owner, vlan, tags,
                                        scan_enabled, ports, exclude, concurrency, icmp_timeout_ms,
                                        tcp_timeout_ms, rate_per_s, estimated_seconds, schedule_id,
                                        last_scan_at, last_scan_alive, last_scan_icmp, created_at, updated_at,
                                        stats: {assets, alive_last_scan, unknown_hosts}, schedule|null}]
POST   /networks                       201 | 409 такой CIDR уже есть | 422
GET    /networks/{id}  PUT /networks/{id}  DELETE /networks/{id}   204
```

`cidr` нормализуется (`10.10.0.7/24` → `10.10.0.0/24`); IPv4 шире /16 — 422
«сеть шире /16 не принимается — разбейте на несколько». Пересечения
разрешены: актив привязывается к самой узкой сети, содержащей его IP (если
сеть не задана вручную). PUT меняет только переданные поля; смена `cidr`
пересчитывает привязку активов. Удаление — активы без сети, расписание
удаляется. Поля по умолчанию: `ports` `[22, 80, 135, 139, 443, 445, 3389]`
(≤ 64), `concurrency` 64 (1–256), `icmp_timeout_ms` 1000 (50–10000),
`tcp_timeout_ms` 2000 (50–30000), `rate_per_s` 500 (10–5000 новых сокетов в
секунду), `vlan` 1–4094, `exclude` — IP и CIDR. `estimated_seconds` — секунд
на скан, если никто не ответит: адресов (CIDR минус служебные и исключения,
считается арифметикой) × (таймаут ICMP + таймаут TCP) / `concurrency`, но не
меньше адресов × (1 + портов) / `rate_per_s`; `null` — сеть сканеру не по
силам. `last_scan_icmp` — `false`, если последний скан шёл в режиме «только
порты», `null` — сеть не сканировали.

## Скан и расписание

```
POST   /networks/{id}/scan             {job_id, icmp} 202 | 409 идёт скан или сканирование сети выключено
GET    /networks/{id}/schedule         {id, interval_hours, window_from, window_to, enabled, next_run_at,
                                        last_run_at, last_job_id, tz} | null
PUT    /networks/{id}/schedule  {interval_hours 1–720, window_from?, window_to?, enabled}
                                       422 — сканирование сети выключено, окно не HH:MM
DELETE /networks/{id}/schedule         204
```

`icmp: false` — ICMP-сокет в контейнере не открывается, скан идёт в режиме
«только порты» (`extra.icmp = null` у наблюдений). Одновременно идёт один
скан. Скан: ICMP echo, затем TCP connect по `ports` (соединение закрывается
сразу, данных не отправляется), PTR живых. Окно расписания — в поясе
`STOOLS_TZ`, конец окна не включается; окно через полночь допускается.

## DNS

```
GET    /dns                            [{id, title, mode, server, ad_connection_id, zones, forward, reverse,
                                        zone_read, rate_per_s, timeout_ms, enabled, schedule_id,
                                        last_run_at, schedule|null}]
POST   /dns  PUT /dns/{id}  DELETE /dns/{id}   201 / 200 / 204
POST   /dns/{id}/run                   {job_id} 202 | 409 идёт обновление DNS или сервер выключен
PUT    /dns/{id}/schedule  DELETE /dns/{id}/schedule   как у сетей
```

`mode: direct` — прямые (A/AAAA по известным FQDN) и обратные (PTR по
известным IP) запросы к `server` (пусто — системный резолвер); включён хотя
бы один из `forward`, `reverse`. `mode: ad` — чтение зон `zones` из
AD-integrated DNS через подключение модуля AD `ad_connection_id`
(`zone_read: true`, хотя бы одна зона); записи `@` и `_`-служб пропускаются.
`rate_per_s` 1–1000 (50) — запросов в секунду: на имя уходят A и AAAA (два
запроса; AAAA не спрашивается, если имени нет), на адрес — PTR. Стадии
задачи пишут оценку «~N запросов при R/с ≈ T мин» (минуты вверх, без учёта
таймаутов). `timeout_ms` 100–30000 (3000). Выключенный сервер по расписанию
не запускается: строка в лог, повтор на следующем тике.

## Зоны сетей

```
GET    /zones                          [{name, title, description, networks}]
POST   /zones  {name, title, description}   201 | 409 такая зона есть
DELETE /zones/{name}                   204 | 404 | 409 зона задана у сетей
```

Предустановлены `DMZ`, `Internal`, `Guest`, `Management`, `Industrial`.

## Настройки и задачи

```
GET  /settings                         {inactive_days, stale_days, sync_after_import}
PUT  /settings  {inactive_days ≥ 1, stale_days ≥ 0, sync_after_import}   все три поля обязательны
GET  /jobs?limit≤200  GET /jobs/{id}  POST /jobs/{id}/cancel
```

| Поле | По умолчанию | Смысл |
|---|---|---|
| `inactive_days` | 30 | компьютер AD без входа и без других источников дольше — `ad_inactive`; с входом не старше — нужен агент (`no_av`) |
| `stale_days` | 30 | порог `stale` против `conflict`; 0 — любое отличие считается устаревшим |
| `sync_after_import` | `true` | синхронизация сама после импорта VM, KSC и AD |

Пороги действуют сразу: расхождения считаются при чтении. `kind` задач:
`scan | dns | sync`; в `message` задачи скана — сеть, DNS — сервер,
синхронизации — что её запустило и сколько наблюдений дал каждый источник.
