# API модуля Assets

Все ручки под `/api/assets`, требуют сессию платформы. Чтение — любой роли,
запись (POST, PUT, PATCH, DELETE) — аналитику и администратору, аудитору 403.
Ошибки — `{"detail": "…"}`; 422 от схемы — списком `[{loc, msg, …}]`. Время —
ISO 8601 в UTC; окна расписаний — `HH:MM` в поясе `STOOLS_TZ`.

## Обзор

```
GET  /overview                         {assets_total, by_zone, by_source, codes, networks, last_dns, sync}
                                        by_zone: {зона: n, "": n} — "" — актив без сети или в сети без зоны
                                        by_source: {vm, ksc, ad, dns, rt: n} — источник видит актив сейчас
                                        codes: {код: n, any: n} — активов с этим расхождением (коды ниже)
                                        с учитываемым статусом (`counted`); any — хотя бы с одним
                                        (ссылка в список с code=any)
                                        networks: {total, no_network_assets} — сетей описано,
                                        активов вне описанных сетей
                                        last_dns: [{dns_id, title, last_run_at}] — по 10, новые сверху
                                        sync: {last_sync_at, running_job_id}
```

Счётчики — те же фасеты, что у списка без фильтров: активы без
`merged_into`, расхождения на момент запроса с учитываемым статусом.
Решённые людьми (принят риск, ложное срабатывание) — в сводке статусов
платформы `GET /api/findings/summary?module=assets&scope_id=0`; обзор в
интерфейсе показывает её строкой «принято рисков: N, в работе: N».

## Активы

```
GET   /assets                          q, source_has, source_missing, code, network_id, zone,
                                       placement (internal|dmz|external|- — по группе сети актива),
                                       tag, criticality (Critical|High|Medium|Low|none), laps (yes|no),
                                       cluster (cluster|role|node — вид кластера Windows по наблюдению AD),
                                       disc_status, assignee, overdue, ad_snapshot + ad_cell, limit≤500 (200), offset
                                       → {total, items, facets|null, ad_cell?}
                                       items: [{id, cluster: cluster|role|node|null, name, fqdn, domain, ip, os, network: {id, cidr, title,
                                       zone, zone_title, placement, internet_facing, confidential}|null, first_seen, last_seen, criticality, tags, pinned,
                                       sources: [{source, live, fresh, seen_at}], discrepancy_count, codes}]
                                       discrepancy_count, codes — только расхождения с учитываемым статусом
                                       facets: {source, code, zone, placement: {internal, dmz, external, ""}, criticality,
                                       laps: {yes, no}, cluster: {cluster, role, node},
                                       disc_status, disc_overdue}; laps, cluster — только активы с наблюдением AD
                                       — только при offset=0; code.any — активов хотя бы с одним
                                       расхождением; code считает расхождения под статусами фильтра
                                       (без disc_status — учитываемые)
                                       code: код ниже или any — хотя бы одно расхождение
                                       неизвестное значение source_*/code/criticality/placement/laps/cluster/disc_status — 422
                                       ad_snapshot + ad_cell — компьютеры ячейки сводки AD (ниже)
GET   /assets/{id}                     + network_manual, note, merged_into, created_at, updated_at,
                                       observations: [{id, source, source_key, name, fqdn, domain, ip, ips,
                                       os, seen_at, gone_at, extra, marks: {поле: stale|conflict}}],
                                       discrepancies: [{code, source, field, value, current, text, key,
                                       status, status_title, assignee, due_date, overdue, risk_until,
                                       counted}] — все, и с неучитываемым статусом (counted: false),
                                       links: {ad_finding_count, ad_domain_id, ad_query, ksc_host_id,
                                       ksc_server_id, vm_host_id, vm_cve_count},
                                       users: [{user_id, sam, display_name, domain, local, kind: session|owner|local_group,
                                       active, seen_at, gone}] | null — пользователи хоста (раздел «Пользователи»);
                                       null — не собраны (нет живых наблюдений KSC или хоть у одного нет users_collected);
                                       session_groups: [{sid, sam, active}] | null — группы с сеансом из KSC (только показ);
                                       owner_unresolved — владелец задан в KSC, но пользователем хоста не стал ({owner_id}
                                       вне списка, группа, служебная учётка)
PATCH /assets/{id}  {criticality?, tags?, note?, network_id?, network_manual?}   → карточка
                                       только ручные поля; network_id без network_manual — сеть ручная;
                                       network_id: null, network_manual: false — вернуть расчёт по адресу
GET   /assets/ids                      те же фильтры, без limit/offset → {total, ids} — выбор «всех по
                                       фильтру» для массового изменения (не больше 50 000)
GET   /assets/export                   format=csv|xlsx (csv) и те же фильтры, без limit/offset → файл
DELETE /assets/{id}                    204; 404 — нет; 409 — идёт синхронизация или запись задачи.
                                       Актив удаляется с наблюдениями; если источник его ещё видит,
                                       следующая синхронизация создаст его заново
POST  /assets/bulk-delete  {ids}       → {deleted}; несуществующие id пропускаются
POST  /assets/bulk  {ids, criticality?, tags_add?, tags_remove?}   → {updated}
                                       критичность и теги у многих активов: теги добавляются и снимаются,
                                       а не заменяются; несуществующие и объединённые id пропускаются;
                                       422 — менять нечего или ids пуст
POST  /assets/discrepancies/bulk  {ids (≤ 50 000), code, change: {status?, assignee?, due_date?,
                                       risk_until?, comment?}}   → {changed}
                                       статус, исполнитель, срок расхождения code у этих активов — одним
                                       массовым действием (bulk_id); ключи — расхождения, которые у
                                       активов есть сейчас (stale/conflict — все ключи кода у актива);
                                       change — как у /api/findings/bulk; принять риск — по
                                       risk_accept_role (403); без обоснования для risk_accepted и
                                       false_positive — 422
POST  /assets/{id}/pin    {field: name|fqdn|domain|ip|os, pinned}   → карточка
POST  /assets/{id}/merge  {other_id}   → карточка первого; 409 — уже объединён, идёт синхронизация
                                       или запись результатов DNS/RackTables («идёт запись результатов
                                       задачи — повторите позже»)
POST  /observations/{id}/detach        → карточка нового актива; 409 — у актива одно наблюдение,
                                       идёт синхронизация или запись результатов DNS/RackTables
GET   /racktables                      подключения к JSON API RackTables: [{id, title, url, username,
                                       password_set, verify_tls, rate_per_s, timeout_ms, enabled,
                                       schedule_id, last_run_at, schedule}]
POST  /racktables  {title?, url, username?, password?, verify_tls?, rate_per_s?, timeout_ms?, enabled?}
PUT   /racktables/{id}                 то же; пустой password — оставить прежний
DELETE /racktables/{id}                204; расписание удаляется вместе с подключением
POST  /racktables/{id}/check           {version} — getAPIVersion сохранёнными учётными данными; 502 — ошибка API
POST  /racktables/{id}/run             202 {job_id}; 409 — идёт другой проход или подключение выключено
PUT/DELETE /racktables/{id}/schedule   расписание проходов (вид assets/rt)
GET   /lookup?source=&key=[&server_id=]   {asset_id} | 404 — хост модуля не сопоставлен
```

`q` ищет подстроку в имени, FQDN, IP и ОС актива и его наблюдений (старые
адреса тоже находятся). `disc_status` (коды статусов повторением ключа или
через запятую, или `all`), `assignee` (`me`, `none`, логины) и `overdue=true` — про расхождения:
актив подходит, если у него есть расхождение под всеми ими сразу, а если
задан `code` — расхождение этого кода. Без `disc_status` фильтр по
расхождениям (и `code`) видит только учитываемые статусы — как до статусов.
Фасет `disc_status` — расхождения по статусам без фильтра статуса,
`disc_overdue` — просроченные без фильтра статуса и срока; оба — по активам
под фильтрами по данным. `source_has`/`source_missing` смотрят на живые
наблюдения (без `gone_at`). Значок источника `fresh` — видит сейчас и видел
моложе `stale_days`.

Многозначные фасеты — `code`, `source_has`, `source_missing`, `criticality`,
`zone`, `placement`, `network_id` (числа), `assignee`, `disc_status`: несколько значений
повторением ключа (`?zone=DMZ&zone=-&code=no_av&code=stale`), значение по
запятой не делится; внутри фасета — «или», между фасетами — «и». `zone=-` —
активы без зоны (`-` — общий маркер «не задано»), `placement=-` — вне сети, в сети без группы
или в группе без расположения; у критичности «не задана» —
`none`; `all` — фильтр не задан. Через запятую принимается только
`disc_status` (старая форма `disc_status=new,in_work`).

Выгрузка `/assets/export` — все активы под фильтрами списка в его порядке,
любой роли; колонки «Имя, IP, Сеть, Зона, ОС, Источники, Виден,
Расхождения». CSV — UTF-8 с BOM, `;`, CRLF, потоком; XLSX — не больше
100 000 строк и строка «Выгружены первые 100 000 строк — сузьте фильтры».
Общие правила формата — `docs/api-contract.md`.

`lookup` — ссылка «в Assets» у хоста модуля: актив по ключу наблюдения
`(source, source_key)`. Ключи: KSC — `server_id:host_id` (или `key=host_id`
и `server_id` отдельно), VM — `hostname|ip` как в `vm_host`, AD — SID
компьютера (DN, если SID нет), `dns` — FQDN или IP, `rt` — IP. После
объединения наблюдение живёт у первого актива — ссылка ведёт к нему.

### Коды расхождений

Считаются при чтении, сами не хранятся — это фильтры списка и подсветка
карточки. Решения людей по ним — статусы находок платформы
([docs/platform/findings.md](../platform/findings.md)): модуль `assets`,
`scope_id = 0`, ключ `asset_id|code`, у `stale`/`conflict` —
`asset_id|code|source|field`. Сравниваются имя, FQDN и IP; ОС и домен источники пишут
по-разному, их отличие не расхождение.

| Код | Условие | Текст |
|---|---|---|
| `stale` | значение наблюдения ≠ каноническому, наблюдение старше опорного на ≥ `stale_days` | «в VM IP 192.168.6.53 от 12.09, актуальный 192.168.2.23 (DNS, 01.10) — данные VM устарели» |
| `conflict` | значение ≠ каноническому, разница меньше `stale_days` | «источники расходятся: IP в VM … (12.09), актуальный … (KSC, 01.10)» |
| `no_av` | нет живого `ksc`, есть живой `dns` или `vm` либо включённый компьютер AD с входом не старше `inactive_days` | «нет агента антивируса» |
| `ad_inactive` | включённый компьютер AD без входа и без других источников дольше `inactive_days` | «неактивный компьютер AD: последний вход 03.06» |
| `no_network` | у актива есть IP, но он не входит ни в одну описанную сеть (контейнеры шире IPv4 /16 и IPv6 /48 не в счёт, см. «Сети») | «сеть не описана: адрес … не входит ни в одну сеть» |

Каноническое значение поля — из самого свежего по `seen_at` живого
наблюдения, где оно заполнено (при равенстве: `dns` > `ksc` > `ad` > `vm` >
`rt`); закреплённое (`pin`) не пересчитывается.

## Пользователи

```
GET   /users                           q, source (ad|ksc), state (enabled|disabled|unknown),
                                       session (active|past|none), local (yes|no), privileged (yes|no),
                                       code (код ниже или any), host_id (числа), ad_snapshot + ad_cell,
                                       limit≤500 (200), offset
                                       → {total, items, facets|null, ad_cell?}
                                       items: [{id, sam, upn, display_name, domain, local, enabled: bool|null,
                                       privileged, sources: [{source, live, fresh, seen_at}], hosts_active,
                                       hosts_total, last_seen, codes}]
                                       facets: {source, state, session, local, privileged, code: {…, any}}
                                       — только при offset=0
                                       неизвестное значение фильтра — 422
                                       ad_snapshot + ad_cell — учётки ячейки сводки AD (ниже)
GET   /users/{id}                      {id, sid, name_key, sam, upn, display_name, domain, local, enabled,
                                       privileged, first_seen, last_seen, merged_into, note, tags, created_at,
                                       updated_at, sources, hosts_active, hosts_total, codes,
                                       observations: [{id, source, source_key, seen_at, gone_at, data}],
                                       groups: [{sid, name, direct, source, group_id|null}] — прямые, затем
                                       вложенные, по имени; group_id — доменная группа /groups (ниже),
                                       group_notes: [текст] — оговорки домена AD учётки,
                                       devices: [{asset_id, name, ip, os, kind: session|owner|local_group, active,
                                       seen_at, gone_at, users_collected, stale}] — живые сначала,
                                       discrepancies: [{code, host_asset_id|null, text}]}
                                       404 — нет; слитый отдаётся как есть, с merged_into
PATCH /users/{id}  {note?, tags? (≤ 50, каждый ≤ 100 символов)}   → карточка; только ручные поля,
                                       синхронизация их не трогает; 409 — пользователь слит (merged_into)
GET   /users/export                    format=csv|xlsx (csv) и те же фильтры, без limit/offset → файл
```

Пользователь — отдельный вид актива (спека «Пользователи как активы»):
учётки из AD и сеансы, владельцы устройств из KSC, связанные с активами-хостами.
Данные — из последней синхронизации, ни AD, ни KSC при просмотре не
спрашиваются. Слитые (`merged_into`) в список не попадают.

`q` (до 200 символов) ищет подстроку в sam, UPN, отображаемом имени и SID без учёта
регистра; `%` и `_` — буквально.
`source` — источник видит учётку сейчас (живое наблюдение). `state` —
включённость по AD, `unknown` — AD учётку не видел (KSC-only, локальная,
домен без выгрузки). `session`: `active` — хоть один живой сеанс «в системе
на момент сбора» на хосте, где пользователи собраны; `past` — живые сеансы
есть, но все прошлые («заходил раньше»); `none` — сеансов нет (например,
только владелец). `host_id` — пользователи со связью с этими активами, и
пропавшей тоже (как блок `users` карточки хоста). Многозначные — повтором
ключа, внутри оси «или», между осями «и»; фасет оси считается по
пользователям под всеми фильтрами, кроме фильтра этой оси. `hosts_active` —
хостов, где учётка в системе на момент сбора, `hosts_total` — хостов с
живыми связями любого вида (и устаревшими, см. ниже).

«Собраны» у хоста — как в синхронизации: есть живые наблюдения KSC, и у
всех `users_collected` (сборщик ≥ 1.4 и запрос по хосту ответил); хоть один
хост KSC актива (другой сервер) не собран — не собран и актив. У устройства
в карточке `users_collected: false` — сеанс считается прошлым; `stale: true`
— живая связь на таком хосте старше `stale_days`: в расхождениях не
участвует (иначе «заходил раньше» на хосте, снятом с агента, висело бы
вечно), но показывается в карточке и считается в `session` (как прошлый
сеанс) и в `hosts_total`.

Выгрузка `/users/export` — все пользователи под фильтрами списка в его
порядке, любой роли; колонки «Учётка, Имя, UPN, Домен, Локальная,
Состояние, Привилегированная, Источники, В системе, Хостов, Виден,
Расхождения» (состояние — включена | отключена | неизвестно, расхождения —
подписями через запятую).

### Ячейка сводки AD

`ad_snapshot=<id снапшота AD>&ad_cell=<ячейка>` — пара, её ставят ссылки со
страницы «Сводка» модуля AD: `/users` ограничивается учётками ячейки (по SID),
`/assets` — активами с наблюдением AD этих компьютеров. Фильтр складывается
(И) с остальными, фасеты считаются внутри него; доходит до выгрузок `/export`
и до `/assets/ids` («все по фильтру» не выходят за ячейку). Задан один из пары
— 422; нет снапшота или ячейки — 404; файл выгрузки снапшота не читается — 409
«файл выгрузки снапшота недоступен».

При фильтре и offset=0 ответ списка несёт `ad_cell: {label, collected_at,
domain, in_summary, found, not_managed, other, summary_n}`: `label` — подпись ячейки,
`collected_at` и `domain` — снапшота; `in_summary` — участников ячейки этого
вида; `summary_n` — число ячейки на странице сводки AD (оба вида вместе; `null`
— числа нет): у сводки без сохранённых настроек состав считается по текущим
настройкам AD, и `in_summary + other` может с ним разойтись — плашка это
называет; `found` — сколько из них есть в «Активах» без учёта
прочих фильтров (число строк списка может отличаться — фильтры, слияния);
`not_managed` — учётки, которые «Активы» не заводят (без SID или доверия —
`sam` на `$`; у `/assets` всегда 0); `other` — участники другого вида (компьютеры на
`/users`, пользователи на `/assets`).

### Коды расхождений пользователей

Считаются при чтении и пока не становятся находками платформы (статусов нет).
Сеанс — живая связь `session`, в системе или заходил раньше.

| Код | Условие | Текст |
|---|---|---|
| `disabled_session` | сеанс учётки, отключённой в AD | «учётка отключена в AD, сеанс на WS01: заходил раньше» |
| `not_in_ad` | сеансы есть, учётка не локальная, живого наблюдения AD нет, а выгрузка её домена прочитана | «учётки нет в AD corp.local, сеансы на WS01 (заходил раньше)» |
| `privileged_on_workstation` | привилегированная (admin_rids, privileged_rids, privileged_groups настроек AD или RID 500) с сеансом на рабочей станции (ОС Windows/macOS без «server») | «привилегированная учётка на рабочей станции WS01: в системе на момент сбора» |
| `owner_without_session` | владелец устройства по KSC без сеанса на нём; хост, где пользователи не собраны, не судится | «владелец WS02 по KSC, но сеансов на нём нет» |

## Группы

```
GET   /groups                          q, kind (local|domain), source (ad|vm), state (live|gone; не задан —
                                       live, all — все), members (some|none), domain (домен или имя хоста),
                                       host_id (числа), limit≤500 (200), offset
                                       → {total, items, facets|null}
                                       items: [{id, name, domain_label, host_asset_id|null, local,
                                       os_family: ''|windows|linux, sid, description, sources: [ad|vm],
                                       members_direct, in_ad, gone}]
                                       facets: {kind, source, state, members} — только при offset=0
                                       неизвестное значение фильтра — 422
GET   /groups/{id}                     поля списка + host_name ('' у доменной),
                                       first_seen|null, last_seen|null, gone_at|null,
                                       vm_snapshot_at|null (у локальной),
                                       members: [{kind: group|user|computer|well_known|unknown, id|null, name,
                                       domain, sid, primary, source: ad|vm, text}] — не больше 1000,
                                       members_total — всего,
                                       member_of: [{id, name, domain, direct}],
                                       local_member_of: [{group_id, name, host_asset_id, host_name,
                                       via: [{id, name}]}] — по имени хоста, не больше 1000,
                                       local_member_of_total — всего,
                                       rights: {fact: [{local_group, local_group_sid, via: [{id, name}],
                                       hosts_total, hosts: [{group_id, host_asset_id, host_name}]
                                       (первые 50 по имени хоста)}],
                                       policy: [{local_group, via: restricted_groups|gpp, action, gpo_name,
                                       filtered, hosts_total, hosts: [{name, asset_id|null}],
                                       through: {id, name}|null}],
                                       notes: [{domain, links_known, files_known, notes: [текст]}]}
                                       404 — нет
GET   /groups/{id}/expanded            limit≤500 (200), offset
                                       → {total, items: [{kind: user|computer, id|null, name, domain, sid,
                                       via: [{id, name}], paths}],
                                       well_known: [{sid, name, text, via, paths}],
                                       dead_ends: [{kind: group|unknown, id|null, name, domain, sid, via, paths,
                                       reason}] — не больше 500, dead_ends_total — всего,
                                       notes: [текст]}
                                       404 — нет
GET   /groups/export                   format=csv|xlsx (csv) и те же фильтры, без limit/offset → файл
```

Группа — отдельный вид актива (спека «Группы как активы»): доменные из AD
(и доменные, которые VM видит участниками локальных групп, — `in_ad: false`,
если в выгрузках AD их нет), локальные — группы хостов из MaxPatrol VM.
Данные — из последней синхронизации, ни AD, ни VM при просмотре не
спрашиваются.

`q` (до 200 символов) ищет подстроку в имени и SID без учёта регистра;
`%` и `_` — буквально. `domain` — DNS-домен доменной группы или имя
хоста (короткое или FQDN) локальной; `host_id` — локальные группы этих
активов. `members`: `some` — есть прямые участники, `none` — нет.
Многозначные — повтором ключа, внутри оси «или», между осями «и»; фасет
оси считается по группам под всеми фильтрами, кроме фильтра этой оси
(`q`, `domain`, `host_id` сужают и фасеты). `domain_label` — домен у
доменной, имя хоста у локальной. Порядок — по имени, затем по
`domain_label`. `os_family` — семейство ОС локальной группы по снимку VM
(`windows`, `linux`), у доменной пусто.

Карточка. `first_seen`, `last_seen`, `gone_at` — даты группы (ISO);
`vm_snapshot_at` — у локальной время последнего снимка групп VM, где её
семейство записано полностью (запрос прошёл, выгрузка того формата, без
лимита подключения), у доменной и без такого снимка — `null`. `members.id` — по виду: пользователь (`user_id`), группа
(`group_id`), компьютер (актив-хост); `text` — пояснение встроенного
субъекта («все прошедшие проверку пользователи и компьютеры»), у прочих
пусто. `member_of` — доменные группы, куда группа входит, `direct: false`
— через вложенность. `local_member_of` — локальные группы хостов, где
прямо состоит сама группа или её доменный предок (выше локальной группы
подъём не идёт: локальная группа Windows не вкладывается в локальную);
`via` — группы цепочки от группы до участника (без самой группы,
кратчайшая), `[]` — прямо. `rights.fact` («по факту», VM) — те же
вхождения сводом: строка на локальную группу (по SID, без SID — по имени
без учёта регистра) и цепочку `via`, с числом хостов и первыми 50 по имени
хоста; порядок — по числу хостов (больше — выше), затем по имени. У Domain
Users и Domain Admins это локальные группы почти каждого хоста, поэтому
список по хостам ограничен 1000, а свод — 50 хостами на строку. `rights.policy` («по политике», GPO): у
доменной — записи прав GPO с SID группы или её доменного предка (`through`
— предок, `null` — сама группа; SID `S-1-5-21-*` сравнивается сам по себе,
прочие — ещё и с доменом GPO); у локальной — записи, которые назначают
участников этой локальной группе (по SID; у записи без SID цели — по
имени), где её хост есть среди хостов GPO. `hosts` — как записала
синхронизация (не больше 1000, полное число — `hosts_total`), `asset_id` —
живой актив по FQDN или короткому имени, только однозначный. `notes` —
оговорки разбора GPO домена группы, её предков и найденных записей
(`links_known: false` — ссылки GPO не известны, `files_known: false` —
файлы GPO не прочитаны) — показываются как есть.

Полный состав — обход вниз от группы по прямому составу, каждая группа
раскрывается один раз (циклы и ромбы конечны). `items` — пользователи и
компьютеры постранично (`total` — их число), у каждого кратчайший путь
`via` (группы между корнем и участником) и число путей `paths`.
`well_known` — встроенные субъекты целиком, в `total` не входят.
`dead_ends` — тупики: `unknown` («неизвестный участник»), участник-группа
без записи («группа без записи»), группа без участников («нет в AD» у
доменной с `in_ad: false`, иначе «пустая»). `notes` — оговорки AD
«список участников мог быть обрезан» доменов пройденных групп.

Выгрузка `/groups/export` — все группы под фильтрами списка в его порядке,
любой роли; колонки «Имя, Домен / компьютер, Вид, Участников, Источники,
SID, Описание» (вид — локальная | доменная).

В карточке пользователя `groups[].group_id` — доменная группа с тем же
SID в домене пользователя; SID `S-1-5-21-*` уникален между доменами и
ищется сам по себе; не нашлась — `null` (встроенная `S-1-5-32-*` чужого
домена — тоже `null`).

## Синхронизация с модулями

```
POST /sync                             {job_id} 202 | 409 идёт синхронизация
GET  /sync/status                      {last_sync_at, last_job_id, running_job_id,
                                        sources: {vm|ksc|ad: {live, gone, seen_at}}}
GET    /sync/schedule                  {id, interval_hours, …, tz} | null — см. «Расписания задач»
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
следующий тик. Синхронизация делит блокировку с записью результатов DNS и
RackTables: если блокировку держит такая запись, задача ждёт её окончания (стадия
`pending`); отказывается («синхронизация уже идёт») только когда идёт другая
синхронизация, заведённая раньше.

## Сети

```
GET    /networks                       q (≤ 200), zone, placement (internal|dmz|external), zone_source
                                       (manual|rule|racktables), origin (racktables; пусто — описана вручную),
                                       limit≤500 (200), offset
                                       → {total, items, facets|null}
                                       items: [{id, cidr, title, zone|null, zone_title|null, placement,
                                       internet_facing, zone_source, vlan|null, site, tags, implicit_tags,
                                       origin, assets}]
                                       facets: {zone, placement, zone_source, origin} — только при offset=0
                                       неизвестное значение placement, zone_source, origin — 422
POST   /networks  {cidr, title?, description?, zone?|null, zone_mode?: manual|rules|null, site?, owner?,
                vlan?|null, tags?}
                                       → карточка, 201 | 409 такой CIDR уже есть | 422
GET    /networks/{id}                  поля списка + description, owner, confidential, zone_rule_id|null,
                                       zone_rule: {id, match, value, position}|null, origin_key,
                                       origin_seen_at|null, parents: [{id, cidr, title}],
                                       children_count, children: [{id, cidr, title}] (до 100),
                                       created_at, updated_at;  404 — нет
PUT    /networks/{id}  поля POST, все необязательны   → карточка | 404 | 409 | 422
DELETE /networks/{id}                  204
GET    /networks/export?format=csv|xlsx   фильтры списка (без limit/offset), его порядок; любой роли
```

Список — по адресу (`cidr` как `inet`: 10.9.0.0/24 раньше 10.10.0.0/16, IPv4 раньше IPv6).
`q` — IP-адрес: сети, его содержащие, от узкой к широкой; иначе подстрока (без учёта регистра,
`%` и `_` — буквально) CIDR, названия, описания, явного или унаследованного тега; число 1–4094 —
ещё и VLAN равенством. Зона интерфейса у адреса (`fe80::1%eth0`) отбрасывается. Многозначные фильтры — повтором ключа, `-` — не задано (сеть без группы,
группа без расположения, группа не назначена, сеть описана вручную). Фасет считается под всеми
фильтрами, кроме своего; у `zone` — только встречающиеся группы и `""`, у остальных — все
значения, в том числе нулевые. `placement`, `internet_facing`, `zone_title`, `confidential` —
признаки группы сети (без группы — `""`, false, null, false). `assets` — активов в сети без
слитых. `parents` — объемлющие сети от узкой к широкой, `children` — вложенные (любой глубины)
по адресу. Выгрузка: CIDR, Название, Группа, Расположение (внутренняя | DMZ | внешняя), VLAN,
Площадка, Теги (явные и унаследованные через запятую), Активов.

`cidr` нормализуется (`10.10.0.7/24` → `10.10.0.0/24`); ширина не ограничена —
сеть-контейнер служит объемлющей. Пересечения разрешены: актив привязывается к
самой узкой сети, содержащей его IP (если сеть не задана вручную), но только к сети
не шире IPv4 /16 и IPv6 /48. Сеть шире (контейнер, например 10.0.0.0/8 из RackTables)
остаётся сетью — ищется, имеет группу, стоит в `parents` у вложенных, — но активы к ней сами
не привязываются: хост вне описанных подсетей остаётся без сети с расхождением `no_network`,
а не получает группу контейнера; её `assets` считает только активы, привязанные руками
(`PATCH /assets/{id}` с `network_id` контейнера разрешён). PUT меняет
только переданные поля; смена `cidr` пересчитывает привязку активов. Удаление —
активы без сети.

Группа сети. `zone_source`: `manual` — выбрана человеком, правила её не трогают;
`rule` — назначена правилом `zone_rule_id`; `racktables` — запасная External публичной сети
из RackTables (ни одно правило не подошло); `""` — не назначена. При создании указанная
`zone` — выбор человека (`manual`), без неё группу назначают правила. `zone_mode`: `rules` —
вернуть сеть под правила (`zone` из тела не берётся, группа пересчитывается сразу);
`manual` — закрепить группу из тела или текущую. В PUT `zone`, отличная от текущей, —
выбор человека; та же группа, присланная повторно (форма шлёт все поля), выбором не считается. `vlan` 1–4094. Сканирования сети в модуле нет (удалено 24.10
по решению владельца 23.10: данных скана не было, только синтетика).

## Расписания задач

```
GET    /sync/schedule                  {id, interval_hours, window_from, window_to, enabled, next_run_at,
                                        last_run_at, last_job_id, tz} | null
PUT    /dns/{id}/schedule  /racktables/{id}/schedule  /sync/schedule
               {interval_hours 1–720, window_from?, window_to?, enabled}   → то же; 422 — окно не HH:MM
DELETE /dns/{id}/schedule  /racktables/{id}/schedule  /sync/schedule   204
```

Расписание DNS-сервера и подключения RackTables отдельной ручкой не читается: оно приходит полем
`schedule` в `GET /dns` и `GET /racktables`.

Окно расписания — в поясе `STOOLS_TZ`, конец окна не включается; окно через
полночь допускается.

## DNS

```
GET    /dns                            [{id, title, mode, server, ad_connection_id, zones, forward, reverse,
                                        zone_read, rate_per_s, timeout_ms, enabled, schedule_id,
                                        last_run_at, schedule|null}]
POST   /dns  PUT /dns/{id}  DELETE /dns/{id}   201 / 200 / 204
POST   /dns/{id}/run                   {job_id} 202 | 409 идёт обновление DNS или сервер выключен
PUT    /dns/{id}/schedule  DELETE /dns/{id}/schedule   см. «Расписания задач»
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

## Группы сетей (зоны)

```
GET    /zones                          [{name, title, description, placement, internet_facing,
                                        confidential, networks}]
POST   /zones  {name, title?, description?, placement?, internet_facing?, confidential?}
                                       → зона, 201 | 409 такая зона есть | 422
PATCH  /zones/{name}  {title?, description?, placement?, internet_facing?, confidential?}
                                       → зона | 404 | 422 (null у поля, неизвестный placement)
DELETE /zones/{name}                   204 | 404 | 409 зона задана у сетей или в правилах
```

В интерфейсе зона называется группой сетей. `placement` — расположение: `internal`, `dmz`,
`external` или `""` (не задано); `internet_facing` — сети группы смотрят в интернет;
`confidential` — в сетях группы конфиденциальные данные. Признаки группы показываются у сетей
и активов (расположение хоста — по группе его сети). `networks` — сколько сетей ссылается на
зону. `name` не пустой и без `/`. Отказ удалить зону, заданную у сетей, перечисляет не больше
10 CIDR по адресу и «и ещё N»; заданную в правилах — номера правил.

Предустановлены `DMZ`, `Internal`, `Guest`, `Management`, `Industrial`, `External`.

### Правила групп сетей

```
GET    /networks/zone-rules            [{id, position, enabled, zone, match, value, note, networks,
                                        created_at, updated_at}]  — по position
POST   /networks/zone-rules  {match, value, zone, enabled? (true), note?}
                                       → правило, 201 (в конец списка) | 422
PUT    /networks/zone-rules/{id}  то же тело   → правило | 404 | 422
DELETE /networks/zone-rules/{id}       204 | 404; номера оставшихся — снова подряд
PUT    /networks/zone-rules/order  [id, …]   → список; все правила, каждое по разу, иначе 422
POST   /networks/zone-rules/preview  {match, value, zone, position?}
                                       → {count, sample: [{id, cidr, title, zone_before|null}]} (до 20)
POST   /networks/zone-rules/apply      → {changed}
```

`match`: `name_prefix` (название начинается с), `name_contains` (содержит), `name_regex`
(регулярное выражение ищется в любом месте названия), `tag` (явный или унаследованный тег
равен), `cidr` (сеть внутри указанной или равна ей; значение хранится адресом сети). Названия
и теги сравниваются без учёта регистра. `value` не пустой, до 500 символов; `zone` — из
справочника, иначе 422. `networks` — сколько сетей сейчас в группе по правилу.

Правила проверяются по `position`, срабатывает первое включённое подошедшее; ни одно не
подошло — публичная сеть из RackTables получает External (`zone_source: racktables`), остальные
остаются без группы. Сети с ручной группой (`manual`) правила не трогают. Любое создание,
правка, удаление и перестановка пересчитывают группы всех не ручных сетей в той же
транзакции; `apply` — пересчитать вручную (например, после правки базы), `changed` — у скольких
сетей сменилась группа. `preview` ничего не записывает: сколько не ручных сетей забрало бы
правило на месте `position` (не указан — в конце) с учётом правил выше; правило с тем же
номером встаёт перед существующим — так проверяется и правка.

Ограничения `name_regex` (защита от катастрофического перебора; иначе 422 с русским текстом):
не длиннее 200 символов; без вложенных повторов (`(\w+)+`); без повтора над альтернативой
(`(a|aa)+`, `(DMZ|WEB){2}`; альтернатива вне повтора, как в `^APP_(DMZ|WEB)_\d+`, допустима);
не больше двух неограниченных повторов (`*`, `+`, `{n,}`) во всём шаблоне; слишком большое
число повторов (`a{99999999999}`) — 422, а не 500. Имя сравнивается не дальше 255 символов.
Правило, записанное в базу в обход проверки и не компилирующееся, не срабатывает.

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
`dns | rt | sync`; в `message` задачи DNS — сервер, RackTables — подключение,
синхронизации — что её запустило и сколько наблюдений дал каждый источник.
