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
                                        codes: {код: n, any: n} — активов с этим расхождением (коды ниже)
                                        с учитываемым статусом (`counted`); any — хотя бы с одним
                                        (ссылка в список с code=any)
                                        networks: {total, scanned, no_network_assets} — сетей описано,
                                        сканировалось хоть раз, активов вне описанных сетей
                                        last_scans: [{network_id, cidr, title, last_scan_at, last_scan_alive}]
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
GET   /assets                          q, source_has, source_missing, code, network_id, zone, port,
                                       tag, criticality (Critical|High|Medium|Low|none), laps (yes|no),
                                       cluster (cluster|role|node — вид кластера Windows по наблюдению AD),
                                       disc_status, assignee, overdue, limit≤500 (200), offset
                                       → {total, items, facets|null}
                                       items: [{id, cluster: cluster|role|node|null, name, fqdn, domain, ip, os, network: {id, cidr, title,
                                       zone}|null, first_seen, last_seen, criticality, tags, pinned,
                                       sources: [{source, live, fresh, seen_at}], discrepancy_count, codes}]
                                       discrepancy_count, codes — только расхождения с учитываемым статусом
                                       facets: {source, code, zone, criticality, laps: {yes, no}, cluster: {cluster, role, node},
                                       disc_status, disc_overdue}; laps, cluster — только активы с наблюдением AD
                                       — только при offset=0; code.any — активов хотя бы с одним
                                       расхождением; code считает расхождения под статусами фильтра
                                       (без disc_status — учитываемые)
                                       code: код ниже или any — хотя бы одно расхождение
                                       неизвестное значение source_*/code/criticality/laps/cluster/disc_status — 422
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
                                       или запись результатов скана/DNS («идёт запись результатов
                                       задачи — повторите позже»)
POST  /observations/{id}/detach        → карточка нового актива; 409 — у актива одно наблюдение,
                                       идёт синхронизация или запись результатов скана/DNS
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
`zone`, `network_id` (числа), `assignee`, `disc_status`: несколько значений
повторением ключа (`?zone=DMZ&zone=-&code=no_av&code=stale`), значение по
запятой не делится; внутри фасета — «или», между фасетами — «и». `zone=-` —
активы без зоны (`-` — общий маркер «не задано»), у критичности «не задана» —
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
компьютера (DN, если SID нет), `scan` — IP, `dns` — FQDN или IP. После
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
| `no_av` | нет живого `ksc`, есть живой `scan`, `dns` или `vm` либо включённый компьютер AD с входом не старше `inactive_days` | «нет агента антивируса» |
| `ad_inactive` | включённый компьютер AD без входа и без других источников дольше `inactive_days` | «неактивный компьютер AD: последний вход 03.06» |
| `unreachable` | IP из `ksc`/`vm`/`dns` в сети, которую сканировали, и последний скан его не нашёл | «не отвечает по известному адресу 10.10.0.11» |
| `unknown_host` | только наблюдения `scan` (и PTR из DNS) | «найдено сканером, нигде не описано» |
| `dns_orphan` | только запись зоны DNS, адрес в сканируемой сети не ответил | «запись DNS без живого хоста» |
| `no_network` | у актива есть IP, но он не входит ни в одну описанную сеть | «сеть не описана: адрес … не входит ни в одну сеть» |

Каноническое значение поля — из самого свежего по `seen_at` живого
наблюдения, где оно заполнено (при равенстве: `dns` > `scan` > `ksc` > `ad` >
`vm`); закреплённое (`pin`) не пересчитывается.

## Пользователи

```
GET   /users                           q, source (ad|ksc), state (enabled|disabled|unknown),
                                       session (active|past|none), local (yes|no), privileged (yes|no),
                                       code (код ниже или any), host_id (числа), limit≤500 (200), offset
                                       → {total, items, facets|null}
                                       items: [{id, sam, upn, display_name, domain, local, enabled: bool|null,
                                       privileged, sources: [{source, live, fresh, seen_at}], hosts_active,
                                       hosts_total, last_seen, codes}]
                                       facets: {source, state, session, local, privileged, code: {…, any}}
                                       — только при offset=0
                                       неизвестное значение фильтра — 422
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
                                       items: [{id, name, domain_label, host_asset_id|null, local, sid,
                                       description, sources: [ad|vm], members_direct, in_ad, gone}]
                                       facets: {kind, source, state, members} — только при offset=0
                                       неизвестное значение фильтра — 422
GET   /groups/{id}                     поля списка + host_name ('' у доменной),
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
`domain_label`.

Карточка. `members.id` — по виду: пользователь (`user_id`), группа
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
GET    /networks/export?format=csv|xlsx   все сети в порядке таблицы (фильтров у списка нет), любой роли
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
