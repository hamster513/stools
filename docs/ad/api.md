# API модуля Active Directory

Все ручки под `/api/ad`, требуют сессию платформы. Ошибки — `{"detail": "…"}`.

## Домены и снапшоты

```
GET  /domains                          [{id, sid, dns_root, netbios, dn, snapshots, last_snapshot_id, last_snapshot_at}]
GET  /domains/{id}/overview            {domain, snapshot|null, compared_to,
                                        counted: {total, by_severity, statuses[]},
                                        summary: {by_status, overdue, risk_expiring, unassigned},
                                        checks: [{code, title, description, total, all, open, new, resolved,
                                                  by_severity, unchecked}],
                                        score: {total, categories: {<категория>: {title, score,
                                                checks: [{code, severity, points}]}}},
                                        score_history: [{snapshot_id, collected_at, total}]}
                                        snapshot: {id, collected_at, source, collector, objects, findings,
                                        by_severity, analyzer_version, stale_analysis}
                                        unchecked: null | причина — в выгрузке не было данных для проверки
                                        (SYSVOL не прочитан, нет дат входа, нет шаблонов); это не «без находок».
                                        Бывает и при total > 0: проверка проверена частично
                                        (у ADCS_CA и ADCS_MAPPING — нет разделов данных ЦС или
                                        сборщик прочитал ЦС и контроллер не целиком: причина называет,
                                        какие ESC не проверены). В домене без AD CS (нет ни шаблонов,
                                        ни ЦС) причин про данные ЦС нет: проверять нечего.
                                        stale_analysis: снапшот посчитан прежней версией анализатора
                                        (analyzer_version не текущая) — у каждой проверки без находок
                                        и без своей причины unchecked «снапшот посчитан прежней
                                        версией анализатора (<версия>) — пересчитайте»
GET  /domains/{id}/dc-links            [{name, asset_id, ips, in_ad_subnet, vm: {critical, exploitable} | null,
                                        ksc_agent}] — контроллеры сводки последнего снапшота со
                                        связками (ниже); нет снапшота или сводки — []; 404 — нет домена
GET  /snapshots?domain_id              [{id, domain_id, collected_at, imported_at, source, collector, filename,
                                        objects, findings, by_severity, new, fixed, previous_id}]
GET  /snapshots/{id}
GET  /snapshots/{id}/summary           сводка домена (ниже) | 409 «сводка не посчитана: пересчитайте снапшот»
POST /snapshots/file  multipart file   {job_id} | 409 идёт задача
POST /snapshots/{id}/reanalyze         {job_id}   — проверки заново по сохранённой выгрузке
DELETE /snapshots/{id}                 204        — удаляет находки и файл; статусы находок остаются
```

Обзор — по последнему снапшоту. `counted` и у проверки `total`, `by_severity` —
находки со статусами, которые велено учитывать (`counted.statuses`, настройка
платформы); список с тем же числом — `findings?severity=…&status=<код>&status=<код>…` (статус повторением ключа).
У проверки `all` — все её находки, `open` — открытые, `new` — появились в
этом снапшоте, `resolved` — пропали с предыдущего. `summary` — счётчики
статусов домена (вместе с отсутствующими в последнем снапшоте).

`score` — живая оценка домена (формула — `checks.md`, «Оценка домена») по
находкам последнего снапшота вне allowlist и в учитываемых статусах; категории в
порядке реестра, у каждой — название, оценка и вклад проверок (`checks`, по
убыванию баллов). `score_history` — «сырая» оценка, записанная при анализе
(`ad_snapshot.score_json`: все находки вне allowlist, статусы не учитываются), по
последним 30 снапшотам домена, старые первыми; снапшоты, посчитанные до
появления оценки, пропускаются. У домена без снапшотов обоих полей нет.

Сводка считается при анализе (импорт и пересчёт) из той же выгрузки и хранится
в снапшоте; у снапшота, посчитанного до её появления (анализатор до версии 9), —
409, нужен пересчёт.

```
{version: 1,
 accounts: {users: COUNTS, computers: COUNTS},
 password_age: {all: BUCKETS, admins: BUCKETS}, last_logon: {all: BUCKETS, admins: BUCKETS},
 os:   [{name, build, total, enabled, active}]                         по убыванию total
 dcs:  [{name, dn, dns, os, build, rodc, last_logon_days, pwd_age_days, owner}]
 groups: [{name, sid, members, enabled, inactive, pwd_never_expires, delegable, protected_users}]
 trusts: [{partner, flat_name, direction, type, within_forest, changed}]
 password_policies: [{name, min_length, lockout_threshold, complexity, reversible, precedence}]
 gpos: [{name, dn, machine_disabled, user_disabled, links: [{dn, enforced, disabled}] | null}]
 subnets: [{name, site}],
 clusters: {clusters: [{name, dn, enabled, roles: [{name, enabled}], roles_disabled}],
            orphan_roles: [{name, enabled}], nodes: [{name, dns, os}]}}
COUNTS:  total, enabled, disabled, active, inactive, pwd_never_expires, pwd_not_required,
         no_preauth, sid_history, delegation, laps (у пользователей 0)
BUCKETS: [{le: 30, n}, {le: 90, n}, {le: 180, n}, {le: 365, n}, {le: 730, n}, {le: 1095, n}, {le: null, n}]
```

`active` — включённые, входившие за `user_inactivity_days` / `computer_inactivity_days`
настроек; `inactive` — остальные включённые. Флаги (`pwd_never_expires` … `laps`)
считаются среди включённых; штатная неограниченная делегация контроллеров в `delegation`
не входит (ограниченная входит). Корзины — включённые пользователи, `admins` — включённые
админы (`admin_rids` и RID 500); вход и пароль неизвестны (не входил, пароль не задан) —
в корзине `le: null`. В группах `members` — все рекурсивные участники (пользователи и
компьютеры), остальные счётчики — по включённым пользователям-участникам; `delegable` —
без «учётная запись важна и не может быть делегирована». `owner` контроллера — владелец
объекта, `""` — дескриптор не прочитан. Первая строка `password_policies` — политика
домена (`precedence: null`), если сборщик её прочитал, за ней PSO по приоритету.
`links: null` — привязка GPO неизвестна (сборщик не читал gPLink); в `links` и выключенные
ссылки. `site` подсети — имя сайта. `clusters` — кластеры Windows по тем же правилам, что
находки Clusters (вид по SPN компьютера): роль привязана к кластеру по `creatorSid` его
учётки, роли без такого создателя — в `orphan_roles`; узлы к кластеру из AD не
привязываются. Списки по имени; у снапшотов, посчитанных до появления ключа, его нет —
это пустые списки.

Связки контроллеров (`dc-links`) читаются при запросе, не при анализе: имя контроллера
(`name` и `dns` сводки, без учёта регистра) ищется в Assets (сначала по FQDN, потом по
короткому имени), в хостах VM (короткое имя или FQDN) и в хостах последних снапшотов серверов
KSC. `asset_id` и `ips` — актив и его адреса (адрес карточки и адреса живых наблюдений);
`in_ad_subnet` — входит ли хоть один адрес в подсети `subnets` сводки (правило
S-DC-SubnetMissing), `null` — адресов или подсетей нет; `vm` — число CVE хоста с риском от
70 (`critical`) и CVE с известными эксплойтами (`exploitable`), статусы пар не учитываются,
`null` — хоста в VM нет; `ksc_agent` — есть ли хост с этим именем в KSC, `null` — данных KSC
нет. Сбой чтения чужого модуля даёт `null` в его поле, а не ошибку запроса.

## Группы учёток и права через GPO

Контракт с модулем Активы: кто в каких группах домена и кто через GPO входит в какие
локальные группы на каких компьютерах. Считается при запросе по файлу выгрузки снапшота,
в базе не хранится.

HTTP-ручки — для разовых запросов: каждый вызов читает и разбирает файл выгрузки целиком
(на больших доменах — секунды и сотни МБ памяти). Массовое использование (модуль Активы) —
функции `account_groups(idx)` и `gpo_rights(idx)` ниже, один раз за проход синхронизации;
не вызывать `account-groups` в цикле по SID и `gpo-rights` на каждую карточку.

```
GET  /snapshots/{id}/account-groups/{sid}
                                       {snapshot_id, collected_at, sid, name, groups: [GroupRef], notes: [str]}
                                       404 — снапшота или учётки нет; 409 «файл выгрузки снапшота недоступен»
GET  /snapshots/{id}/gpo-rights?group_sid=&local_group=&host=&hosts_limit=1000
                                       объект gpo_rights (ниже) + snapshot_id, collected_at
                                       404 — снапшота нет; 409 «файл выгрузки снапшота недоступен»;
                                       422 — hosts_limit вне 0…10000
```

`collected_at` — время сбора снапшота. `name` учётки — `DOMAIN\name` из выгрузки (или
well-known, иначе сам SID). Учётка без групп отдаётся с `groups: []`; SID, которого нет
среди учёток выгрузки, — 404. Фильтры `gpo-rights` без учёта регистра и точным
совпадением: `group_sid` — по `group_sid` записи, `local_group` — по `local_group`,
`host` — запись остаётся, если хоть один хост из её полного списка равен `host` (до
обрезки). Пустой фильтр не применяется. `hosts_limit` (0…10000, по умолчанию 1000) режет
`hosts` каждой записи, `hosts_total` — число хостов до обрезки.

Python (для Assets) — те же данные без HTTP:

```python
from api.modules.ad.core.account_groups import account_groups   # (idx: ExportIndex) -> AccountGroups
from api.modules.ad.core.gpo_rights import gpo_rights           # (idx: ExportIndex) -> dict[str, Any]
```
`AccountGroups` — dataclass: `groups: dict[str, list[GroupRef]]` (ключ — SID учётки), `notes: list[str]`.
`GroupRef` — TypedDict: `{"sid": str, "name": str, "direct": bool, "primary": bool}`.

`ExportIndex` — `api.modules.ad.core.export.ExportIndex(export)`, выгрузка —
`load_export_path(snapshot_path(data_dir, snapshot_id))` (`api.modules.ad.core.export`,
`api.modules.ad.services.snapshots`). В `account_groups` у каждой учётки сначала прямые
группы, затем вложенные, внутри — по имени; `primary` — первичная группа
(`primaryGroupID`, она же прямая). Списки общие: записи `GroupRef` одни на все учётки,
списки `hosts` и `scope` в `gpo_rights` одни на все записи одной GPO — **не изменять**;
потребитель режет (`hosts[:n]`) или копирует. Функция `gpo_rights` отдаёт полные списки
хостов, обрезка — только в HTTP.

Ответ `gpo_rights`:

```
{"links_known": bool,            # false — в выгрузке нет gPLink (сборщик старой версии)
 "files_known": bool,            # false — файлы GPO (GptTmpl.inf, Groups.xml) не собраны
 "notes": [str],                 # общие оговорки: очистка групп, доменные цели, user-часть GPP, непривязанные GPO,
                                 # файлы GPO прочитаны не полностью
 "rights": [{
   "group_sid": "S-1-5-21-…" | "",          # субъект: кто становится членом (группа ИЛИ учётка); "" — записан именем без SID
   "group_name": "CORP\\name",
   "subject_class": "group" | "user" | "computer" | "well_known" | "",
                                             # по выгрузке; well_known — неявная группа токена (ниже); "" — не найден
   "local_group": "Administrators",          # по RID для S-1-5-32-*, иначе как записано (суффикс " (built-in)" снят)
   "local_group_sid": "S-1-5-32-544" | "",
   "via": "restricted_groups" | "gpp",
   "gpo": {"name": "<displayName>", "dn": "<DN GPO>"},
   "action": "member" | "memberof" | "add" | "replace" | "delete",
   "filtered": bool | null,                  # GPP: есть item-level targeting; null — сборщик < 1.4/2.5; restricted_groups — false
   "scope": [{"dn": "<OU, домен или сайт>", "enforced": bool}],
   "hosts": ["pc01.corp.local", …],          # отсортированы; в HTTP обрезаются до hosts_limit
   "hosts_total": int,
   "notes": [str]}]}                         # по записи: ссылка на сайт и т. п.
```

Семантика `action`: `member` — `X__Members` в `GptTmpl.inf` (состав X заменяется
перечисленными); `memberof` — `X__Memberof` (X добавляется в цель); `add` — GPP ADD;
`replace` — GPP ADD при `deleteAllUsers`/`deleteAllGroups` = 1 или у элемента с действием
`R` (Replace) — прочие участники удаляются; `delete` — GPP REMOVE. Элемент GPP с действием
`D` и выключенный (`disabled` = 1 у элемента или коллекции, сборщики LDAP 1.4 / PowerShell 2.5)
записей не даёт.

`subject_class: "well_known"` — SID вида `S-1-1-*`, `S-1-2-*`, `S-1-3-*` и `S-1-5-<n>…`, кроме
доменных (`S-1-5-21-*`) и BUILTIN (`S-1-5-32-*`), которого нет объектом в выгрузке: Everyone,
Authenticated Users, Interactive, SYSTEM и др. Такие субъекты действуют на всех учёток, но в
`account_groups` их нет — членство в них даёт токен, а не `member`; потребитель учитывает
записи `well_known` для любого пользователя. BUILTIN остаётся `group`, если группа есть в выгрузке.

Разрешение имён:

- цель — SID `S-1-5-32-<RID>` или имя встроенной группы (с префиксом `BUILTIN\` и суффиксом
  ` (built-in)` или без) → английское `local_group` по RID и SID `S-1-5-32-*`; локализованные
  имена (например «Администраторы») сводятся к ним через группы `CN=Builtin` выгрузки;
  неизвестный RID встроенной группы → `local_group = "RID-<n>"`;
- цель Restricted Groups — доменная группа своего домена (по SID или имени) → записи нет,
  в `notes` — оговорка; у GPP цель всегда локальная: имя как записано, `local_group_sid: ""`,
  даже если в домене есть одноимённая группа;
- субъект — голое имя (без домена и SID), совпавшее с учёткой своего домена с RID 500 или 501
  (Administrator, Guest), — локальная учётка хоста: Windows ищет неквалифицированное имя
  сначала локально; `group_sid: ""`, имя как записано, `subject_class: ""`. С `CORP\` или
  по SID — доменная учётка;
- неверный SID в GPP (`groupSid` элемента, `sid` участника) — как пустой: разрешение по имени.

Оговорки — чего ответ не знает:

- WMI-фильтры и security filtering GPO (права на применение) не учитываются: хосты — все
  компьютеры под ссылками GPO.
- Item-level targeting GPP не вычисляется — виден только как `filtered: true`.
- Порядок применения GPO и конфликты не разрешаются: две GPO с `__Members` на одну
  локальную группу дают две записи, обе выдаются.
- Групп других доменов леса и доверий в выгрузке нет: их участники и вложенность там не
  видны.
- Список участников больших групп мог быть обрезан сборщиком — тогда об этом говорит
  `notes` в `account-groups`.
- Ссылка GPO на сайт хостов не даёт (компьютеры сайта по выгрузке не определяются) —
  в `scope` она есть, в `notes` записи — оговорка.
- Сборщик не прочитал `GptTmpl.inf`, `Groups.xml` или папку GPO (отказ в `notes` блока `gpo`) —
  в `notes` оговорка «GPO «<имя>»: файлы прочитаны не полностью — назначения групп могут быть
  неполными».

## Ячейки сводки

Кто дал число сводки снапшота: состав каждой ячейки — те же учётки, длины списков которых стали
числами (`core/summary_cells.py`), и с теми же настройками, с которыми сводка строилась (`params`
сводки версии 2). У сводки версии 1, у снапшота без сводки и у сводки, чьи `params` уже не
проходят проверку настроек, — текущие настройки модуля; тогда размер может разойтись с числом
сводки, это покажет плашка «Активов».

```
GET  /snapshots/{id}/summary-cell?cell=<ячейка>
                                       {snapshot_id, collected_at, domain, cell, label, users: N, computers: M}
                                       404 — снапшота или ячейки нет («ячейки сводки нет»);
                                       409 «файл выгрузки снапшота недоступен»
```

Ячейка — компоненты через «:», последний может сам содержать «:»:

```
accounts:<users|computers>:<ключ COUNTS>            accounts:users:inactive (у users нет laps)
<password_age|last_logon>:<all|admins>:<le|over>    password_age:admins:365, last_logon:all:over
groups:<поле>:<SID группы>                          groups:members:S-1-5-21-…-512
os:<total|enabled|active>:<сборка>:<имя ОС>         os:active:22631:Windows 11 Pro
```

`domain` — `dns_root` выгрузки, `collected_at` — время сбора. `label` — название ячейки с точным
интервалом корзины («Возраст пароля 181–365 дн., админы», последняя — «> 1095 дн. или
неизвестно»). `users`, `computers` — размеры состава, самих ключей ручка не отдаёт. Ключ учётки —
`sid or dn` (как `source_key` хоста AD в Активах). В `groups:members` пользователи-участники
идут в `users`, все остальные участники — в `computers`. Ячейка с нулём — 200 с нулями.

Известные края идентификатора: две привилегированные группы без SID дают одну ячейку
`groups:<поле>:` (фронт показывает их числа текстом, без ссылки); сборка ОС с «:» сделала бы
ячейку неоднозначной (на практике сборки числовые).

Python (для Assets) — без HTTP:

```python
from api.modules.ad.services.summary_cells import CellInfo, CellNotFound, CellUnavailable, cell_info
# cell_info(db: Session, data_dir: Path, snapshot_id: int, cell_id: str) -> CellInfo
```
`CellInfo` — frozen dataclass: `snapshot_id`, `collected_at`, `domain`, `cell_id`, `label`,
`users: frozenset[str]`, `computers: frozenset[str]`, `user_sams: Mapping[str, str]`.
`user_sams` — ключ → sAMAccountName всех пользователей снапшота (не только ячейки; `""`, если
sam нет), один словарь на снапшот, только для чтения: по нему «Активы» сверяют, кого они по
своим правилам не заводят (учётки доверий). `CellNotFound` (`LookupError`) — нет снапшота или
ячейки, `CellUnavailable` (`RuntimeError`) — файл выгрузки не читается.

Кэш: составы всех ячеек снапшота строятся при первом запросе одним разбором выгрузки и держатся
в памяти процесса — LRU на 4 снапшота, ключ — (снапшот, отпечаток выгрузки, настройки), так что
пересчёт с другими настройками строит составы заново. Построения идут по одному: одновременные
первые запросы по снапшоту ждут одного разбора, а попадания в кэш построения не ждут. Сама
выгрузка после построения не держится. Кэш у каждого процесса API свой и сбрасывается перезапуском.

## Данные центра сертификации

Файл `stools-ad-ca/1` от PowerShell-сборщика (JSON, можно gzip; поля `format`,
`collected_at`, `collector`, `domain: {sid, dns_root}`, `sections` и записи разделов:
`cas` — `name, host, os_build, edit_flags, interface_flags, disable_extension_list,
security` (дескриптор прав ЦС, base64), `dcs` — `host, strong_binding,
mapping_methods` и с PowerShell-сборщика 2.3 `lm_compatibility, no_lm_hash,
ldap_integrity, ldap_channel_binding, tls, smb1, smb_require_signing, spooler,
webclient, last_boot, os_build, registry_read, cim_read` (`tls` — `Enabled` для
`SSL 3.0`, `TLS 1.0`, `TLS 1.1` или `null`; службы — `running`, `stopped`,
`disabled`, `absent`; флаги — отработал ли канал, реестр и CIM: `null` у значения
при прочитанном реестре — значения нет), `web` — `url, status, auth`; у каждой
записи `error` — что сборщик не прочитал) загружается той же ручкой `POST /snapshots/file`: формат
определяется по полю `format`.
`stools-ad/1` — выгрузка домена (снапшот); `stools-ad-ca/*` — данные ЦС: домен
ищется по `domain.sid` (нет — задача падает «сначала загрузите выгрузку
домена»), данные сохраняются у домена, последний снапшот пересчитывается. Другая
версия `stools-ad-ca/*` — отказ с текстом про формат. Пересчёт не удался —
задача `failed`, но данные уже сохранены (текст начинается с «данные ЦС
сохранены»; у ошибок не из данных — только имя класса ошибки, подробности в
журнале сервера, логгер `stools.ad`).

```
GET    /domains/{id}/ca-data           [{id, collected_at, imported_at, filename, uploaded_by,
                                        sections, cas, dcs, web, dc_total, dc_complete}]
                                       — cas/dcs/web: число записей; dc_total/dc_complete —
                                       контроллеров и сколько прочитано полностью (реестр и CIM)
DELETE /ca-data/{id}                   {job_id} 202 — пересчёт последнего снапшота без них;
                                       204 — снапшотов домена нет; 409 — идёт задача, данные не удалены
```

Анализ берёт каждый раздел (`ca`, `dc`, `web`) из самой свежей по
`collected_at` загрузки, где он указан в `sections`. Раздел указан, список
пуст — собрано, ничего не найдено; заменяет старые данные раздела. Раздела нет
в `sections` — берётся из более ранней загрузки. Записи раздела, не указанного
в `sections`, и неизвестный раздел — отказ разбора. `collected_at` без пояса
считается UTC.

### Проверки AD CS

| Код | Что | Данные |
|---|---|---|
| `ADCS_ESC` | шаблоны сертификатов: ESC1–4, 9, 13, 15 | снапшот (ESC9 — серьёзность по разделу `dc`) |
| `ADCS_CA` | центр сертификации: ESC5–8, 11, 16 (ESC12 удалённо не определяется) | ESC5 — снапшот; 6, 7, 11, 16 — раздел `ca`; 8 — `web` |
| `ADCS_MAPPING` | привязка сертификатов к учётным записям: ESC10, 14 | ESC10 — раздел `dc`; 14 — снапшот |

Ключ находки — код ESC и объект (у шаблона `cn`, у ЦС имя, у ESC8 URL, у
ESC10 контроллер). В `details`: `esc`, `details` (текст); у ESC на выпуск —
`requesters`, `requesters_broad`; у ESC4/ESC5 — `principals`
(`[{name, sid, kind, rights}]`, у владельца в `rights` — `owner`) и
`principals_broad`; у шаблонов — `display_name`, `published`; у ESC9 —
`binding`; у находок по данным ЦС — `ca_data_collected_at`, `ca_data_id`.

ESC10: находка — `StrongCertificateBindingEnforcement` 0 или 1 либо бит UPN (0x4) в
`CertificateMappingMethods`. Значения `StrongCertificateBindingEnforcement` в
реестре нет — находки нет: на сборках контроллеров с обновлениями от февраля
2025 это полный режим. На более старых сборках отсутствие значения означает
режим совместимости — проверьте уровень обновлений контроллеров.

## Находки

```
GET  /snapshots/{id}/findings          check, severity, allowlisted, q,
                                       status (коды повторением ключа или через запятую, или all;
                                         по умолчанию — открытые: new, in_work, fixed, reopened;
                                         с risk_expiring — risk_accepted),
                                       delta (new|same|gone), assignee (логин | me | none),
                                       overdue=true, risk_expiring=true, limit≤1000, offset
                                       → {total, items, facets|null, compared_to, check_titles,
                                          is_latest, statuses_as_of: "today"}
GET  /snapshots/{id}/findings/export   format=csv|xlsx (csv) и те же фильтры, без limit/offset → файл
GET  /snapshots/{id}/findings/{key}    элемент списка + description, history[{snapshot_id, collected_at}]
```

Многозначные фасеты — `check`, `severity`, `delta`, `assignee`, `status`: несколько значений
повторением ключа (`?severity=High&severity=Critical&delta=new`), внутри фасета — «или», между
фасетами — «и»; `all` — фильтр не задан (у `status` — любые статусы). Через запятую принимается
только `status` (старая форма `status=new,in_work`); у остальных `a,b` — одно значение.

Выгрузка `findings/export` — все находки под фильтрами списка в его порядке, любой роли (объявлена
до карточки `findings/{key}`). CSV — UTF-8 с BOM, `;`, CRLF, потоком; XLSX — не больше 100 000
строк, после них строка «Выгружены первые 100 000 строк — сузьте фильтры». Колонки — как в таблице
на экране. Общие правила формата и выгрузки — `docs/api-contract.md`.

Статусы находок — общий механизм платформы: `GET/PUT /api/findings/state`,
`POST /api/findings/comment`, `POST /api/findings/bulk`, `GET /api/findings/mine`,
настройки `GET/PUT /api/settings/findings` (`module=ad`, `scope_id` — id домена).
Своих ручек смены статуса у модуля нет.

Строка списка — поля находки и её состояние: `status`, `status_title`,
`assignee`, `assignee_name`, `due_date`, `overdue`, `risk_until`,
`first_seen_at`, `age_days`, `delta` (`new` — нет в предыдущем снапшоте
домена, `same` — была, `gone` — нет в последнем снапшоте: данные из
последнего снапшота, где она была). Строки `gone` есть только у последнего
снапшота (`is_latest: true`) — устранённые системой, принятые людьми,
перенесённые вердикты; вердикт, находки которого нет ни в одном снапшоте,
показывается по строке состояния (подпись — в `target`, `check` пуст).

Статусы показываются на сегодня у любого снапшота (`statuses_as_of: "today"`),
находки — на дату снапшота. Карточка находки, которой нет в просматриваемом
снапшоте, открывается только из последнего (иначе 404).

`facets` — только на первой странице: `check`, `severity`, `allowlisted`,
`delta` — по отобранным строкам; `status` — без фильтра статуса, `assignee` —
без фильтра исполнителя (`none` — без исполнителя), `flags` (`overdue`,
`risk_expiring`) — каждый без своего фильтра, но под выбранным статусом.

Сверка статусов идёт в конце импорта и пересчёта, только если записанный
снапшот — последний домена по времени сбора, и после удаления снапшота.
Если у последнего и предыдущего снапшота разные `analyzer_version`, пропажи
не считаются и «устранена» не ставится: ключи находок разных версий не
сравнимы (в журнал — предупреждение).

## Сбор

```
GET  /collector.ps1                    PowerShell-сборщик (attachment)
GET  /connections                      [{id, title, host, port, use_ssl, verify_tls, username,
                                        password_set, base_dn, collect_sysvol, page_size,
                                        pause_ms, domain_id, schedule}]
POST /connections  PUT /{id}  DELETE /{id}      пустой пароль в PUT — оставить прежний;
                                        page_size 50–1000 (500), pause_ms 0–10000 (500) —
                                        страница LDAP и пауза между запросами к контроллеру
                                        (LDAP и SYSVOL); нет поля в PUT — оставить прежнее;
                                        DELETE уносит и расписание сбора
POST /connections/{id}/test            {ok, message}
POST /connections/{id}/collect         {job_id} | 400 нет пароля | 409 идёт задача
GET  /connections/{id}/schedule        ScheduleView | null (не задано)
PUT  /connections/{id}/schedule        {interval_hours 1–720, window_from?, window_to?, enabled}
                                        → ScheduleView | 422 окно не ЧЧ:ММ или задан один конец
DELETE /connections/{id}/schedule      204 (и когда расписания нет) | 404 подключение не найдено
```

**Расписание сбора.** У подключения одно расписание — строка `platform_schedule
(ad, collect, id подключения)`; `schedule` в списке подключений и ответ
`/schedule` — тот же `ScheduleView`, что у сетей Assets (`id, interval_hours,
window_from, window_to, enabled, next_run_at, last_run_at, last_job_id, tz`;
окно — в поясе `STOOLS_TZ`). Читать расписание могут все роли, менять —
аналитик и администратор, как и само подключение. Планировщик платформы
раз в минуту запускает ту же задачу `collect`, что и кнопка «собрать», со
`started_by = "расписание"` и адресом контроллера в `message`; в списке
задач она выглядит как обычный сбор. Три отказа обработчика: подключения
больше нет — расписание удаляется; у подключения нет логина или пароля —
расписание выключается (`enabled=false`, в настройках «выключено»; после ввода
пароля его нужно включить заново в блоке расписания); идёт задача модуля (`import_file`, `collect`, `reanalyze`)
или заняты оба слота расписания — запуск откладывается на следующий тик,
а не на интервал.

## Настройки и задачи

```
GET  /settings   {config: AdConfig, defaults, checks[]}
PUT  /settings   AdConfig
GET  /jobs  GET /jobs/{id}  POST /jobs/{id}/cancel
```

`kind` задач: `import_file | collect | reanalyze`.

Правило заявителя AD CS (поля `AdConfig`): безопасны только перечисленные
субъекты, любой другой с правом Enroll (или записи на объект PKI) — заявитель
под вопросом; `low_priv_*` задают «широкие» группы, у них серьёзность выше.

- `adcs_safe_sids` — SID (по умолчанию `S-1-5-18`, `S-1-5-32-544`, `S-1-5-9`);
- `adcs_safe_rids` — RID доменов своего леса: свой домен и доверия внутри леса
  (по умолчанию 500, 512, 516, 518, 519, 498, 521, 517);
- `adcs_safe_principals` — имена или SID своих групп администраторов ЦС
  (по умолчанию пусто).

## ATT&CK

Каждая проверка объявляет техники, которые открывает её находка
(`CheckSpec.techniques` в `api/modules/ad/core/checks/`). Из них строится
слой экспозиции `ad` платформенной матрицы: `docs/attack/api.md`.
