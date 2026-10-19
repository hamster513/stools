# API модуля Антивирус (Kaspersky Security Center)

Все ручки под `/api/ksc`, требуют сессию платформы. Ошибки — `{"detail": "…"}`.
Дизайн — `docs/superpowers/specs/2026-09-15-ksc-module-design.md`,
`docs/superpowers/specs/2026-09-17-ksc-data-expansion-design.md` (блок 1:
результаты задач, расширенные поля хостов, сервер KSC; блок 2 этап A:
содержимое политик, замки).

## Формат выгрузки

Файл — `stools-ksc/1` (JSON, при выгрузке скриптом — gzip). Секции
`role_assignments`, `internal_users`, `security`, `server_certs`,
`secondary_servers`, `update_agents`, `policy_contents` — необязательные:
файл без них (старая выгрузка или сборщику не хватило прав на метод)
разбирается как раньше и не даёт находок по этим секциям.

`policy_contents` — содержимое активных политик продуктов защиты (продукт
не агент и не сервер): `{"<KLPOL_ID>": {"product", "version", "sections":
{"<имя секции>": <ответ Ss_Read как пришёл>, …}, "errors": [...]}}`.
Собирается только на этапе выгрузки (PowerShell-флаг `-SkipPolicyContents`
или поле подключения `skip_policy_contents` выключают сбор целиком — файл
заметно больше с этой секцией). Ограничения сборщика: не больше
`policy_contents_max_policies` (200) политик и 2 МБ на секцию (размер —
компактный JSON без пробелов в обоих сборщиках). Политика за лимитом не
читается, но попадает в файл записью `{"product", "version", "sections": {},
"errors": ["лимит политик"]}` (и одна строка в `server.warnings`) — так
`POLICY_CONTENT_MISSING` показывает причину; секция за лимитом не попадает
в файл, причина — в `errors` этой политики.

Секреты: если имя секции или ключ на **любой** глубине её параметров
содержит подстроку `PASSWORD`, `PASSWD`, `PWD`, `SECRET`, `CRYPTED`,
`TOKEN`, `CREDENTIAL` или `PRIVATE` (без учёта регистра), всё поддерево под
ним скрывается: каждая непустая строка становится `"<скрыто>"`, пустая
остаётся `""`, ключи остаются на месте. Двоичные значения
(`{"type": "binary", …}`) становятся `"<скрыто>"` под любым ключом, кроме
адреса: под ключом `octets` значение длиной 4 или 16 байт (IPv4/IPv6 в
сетевых правилах) остаётся как пришло — но только вне поддерева с признаком
(под признаком 16 байт могут быть хешем или ключом, `octets` скрывается).
Так скрываются и документированная форма настройки
(`{"AdminPassword": {"KLPRSS_Val": "…", "KLPRSS_Mnd": true}}` — строка в
`KLPRSS_Val`), и секрет в обёртке `params`, и вложенный
`PasswordProtection → KLPRSS_Val → PasswordHash`, и контейнеры внутри
секции с признаком в имени. Логические и числовые значения под признаком
остаются (`EnablePasswordProtection = true`, `KLPRSS_Mnd` — видны), прочие
типизированные значения (`datetime`, `long`) тоже; непустые строки замка под
признаком (`KLPRSS_ValLckPolicy`, `KLPRSS_ValLckGroup`) скрываются вместе с
остальными строками. Адрес `octets` и пустые строки не скрываются со
сборщика 1.3. Файлы сборщиков до 1.3 остаются как записаны (1.1–1.2
скрывали все двоичные значения и все строки под признаком), разбор скрытое
не восстанавливает — адреса и признак пустоты появляются только в выгрузках
1.3+. Чего правило не делает: значения под ключами без
признака (и без признака выше по пути) не проверяются — секрет под
нейтральным именем (`Value`, `Data`) сохранится как есть; и наоборот,
несекретная строка под ключом с признаком тоже станет `"<скрыто>"`. Секция
хранится как пришла от KSC (те же обёртки типов
`{"type": "params"|"binary"|…, "value": …}`, что и в остальных секциях
файла) — обёртки `params` проходятся насквозь и остаются на месте, списки
проверяются поэлементно и остаются списками.

Из контейнера сертификата (`CertPoolCtrl.GetCertificateInfo`) в файл идёт
только поле `CPublic` — приватная часть и прочие поля контейнера не
сохраняются. Отказ в правах (HTTP 403) на этот метод считается отказом на
весь метод: `server_certs` остаётся пустой, в `server.warnings` одна
строка. Любая другая ошибка функции (`PxgError`, ответ без `CPublic`)
значит, что сертификата для этого назначения нет: функция пропускается,
остальные (1..4) собираются как обычно.

Живой KSC заворачивает каждую запись списка и каждый вложенный контейнер в
`{"type": "params", "value": {…}}`. Сборщики (PowerShell и онлайн-режим)
читают сквозь эту обёртку, но в файл кладут ответ как пришёл — не
разворачивая; развёртку (`strip_params` в `core/export.py`) делает
`load_export` при загрузке файла в память. Прочие типизированные значения
KSC (`{"type": "datetime"|"long"|"binary", "value": …}`) снимает `unwrap`
там же.

## Серверы и снапшоты

```
GET  /servers                          [{id, name, version, snapshots, last_snapshot_id, last_snapshot_at}]
GET  /servers/{id}/overview            {server, snapshot|null, coverage|null, compared_to,
                                        changes: {total|null, prev|null, compared, truncated, reason|null}|null,
                                        counted: {total, by_severity, statuses[]},
                                        summary: {by_status, overdue, risk_expiring, unassigned},
                                        checks: [{code, title, description, total, all, open, new, resolved,
                                                  by_severity}]}
GET  /snapshots?server_id              [{id, server_id, collected_at, imported_at, source, collector, filename,
                                        hosts, findings, by_severity, new, fixed, previous_id}]
GET  /snapshots/{id}
POST /snapshots/file  multipart file   {job_id} | 202
                                        422 пустой файл | 413 файл больше 200 МБ | 409 идёт задача
POST /snapshots/{id}/reanalyze         {job_id}   — проверки заново по сохранённой выгрузке
DELETE /snapshots/{id}                 204        — удаляет находки, хосты и файл; статусы находок остаются
```

`source`: `file | online`. Выгрузка хранится файлом
`STOOLS_DATA_DIR/ksc/<id>.json.gz` (лимит на приём — 200 МБ), поэтому
`reanalyze` и `policies` (ниже) работают без повторного сбора.

Обзор — по последнему снапшоту. `counted` и у проверки `total`, `by_severity` —
находки со статусами, которые велено учитывать (`counted.statuses`, настройка
платформы); список с тем же числом — `findings?severity=…&status=<код>&status=<код>…` (статус повторением ключа).
У проверки `all` — все её находки, `open` — открытые, `new` — появились в
этом снапшоте, `resolved` — пропали с предыдущего. `summary` — счётчики
статусов сервера (вместе с отсутствующими в последнем снапшоте).

## Хосты

```
GET  /snapshots/{id}/hosts             group, product, agent(none|silent|alive), protection(none|off|on),
                                       bases(fresh|old|unknown), in_ad(both|ksc_only),
                                       status(ok|warning|critical), status_reason, component, component_state(on|off|other|none),
                                       tag, policy, q, limit≤1000, offset
                                       → {total, items (каждый: … status, status_reasons: [str]|null, extra, tags, findings),
                                          facets|null, tags_collected}
GET  /snapshots/{id}/hosts/export      format=csv|xlsx (csv) и те же фильтры, без limit/offset → файл
GET  /snapshots/{id}/hosts/{host_id}   + findings[] (каждая: key, check, check_title, severity, status, status_title, details),
                                       findings_counted — учитываемые (то же правило, что `findings` в списке),
                                       policies[] — действующие политики группы хоста: {id, name, product, active, own}
GET  /snapshots/{id}/hosts/{host_id}/profiles
                                       {profiles_collected, tags: [str]|null,
                                        policies: [{id, name, product, active, own, profiles_collected,
                                                    profiles: [{name, enabled, priority, active: true|false|null, reason,
                                                                matched_tags: [str], condition: [[{field, text}]],
                                                                settings, exclusions: n|null, net_rules: n|null}]}],
                                        by_tag: [{tag, profiles: [{policy_id, policy_name, profile, enabled}]}]}
```

Названия компонентов защиты сведены к одному написанию: хост присылает имя на языке консоли своего продукта, поэтому
английское и русское название одного компонента (`Firewall` и «Сетевой экран», `File Threat Protection` и «Защита от файловых
угроз» и т. д.) — один пункт фасета `component`, одна строка карточки (`components`: `[название, код состояния]`) и один
фильтр. Показывается русское название, у компонента без пары — имя как пришло. Справочник пар —
`core/dictionary/components.py` (`component_code`, `component_title`). Если хост перечисляет компонент под обоими написаниями,
состояния сливаются по худшему (в карточке — строка с худшим состоянием). Находки `COMPONENT_OFF` у хоста — одна на компонент.

Многозначные фасеты хостов — `protection`, `agent`, `bases`, `in_ad`, `status`, `status_reason`, `component`, `tag`, `group`,
`product`: несколько значений повторением ключа (`?group=Офис%2C%20Москва&group=DMZ&status=warning&status=critical`),
значение по запятой не делится (в именах групп и продуктов бывают запятые); внутри фасета — «или», между фасетами — «и»;
`all` — фильтр не задан. `tag=-` — хосты без тегов. `status` ещё принимает старую форму через запятую
(`status=ok,warning`). `component_state` — одно значение, применяется к любому из выбранных компонентов. Выгрузка
`hosts/export` — все хосты под фильтрами списка в его порядке, любой роли; формат — общая «Выгрузка списков»
(`docs/api-contract.md`: CSV — UTF-8 с BOM, `;`, CRLF; XLSX — не больше 100 000 строк и строка-предупреждение).

Компонент защиты: `component=<название>` (любое написание, без учёта регистра и краевых пробелов) без состояния — хосты, у которых компонент есть; с `component_state`:
`on` — работает (код 4), `off` — остановлен, приостановлен, сбой, не установлен, нет лицензии
(`COMPONENT_OFF_STATES`), `other` — прочие коды, `none` — у хоста такого компонента нет.
`component_state` без `component` или с неизвестным значением — 422. Если хост перечисляет компонент дважды
(две версии продукта), берётся худшее состояние: выключен, затем прочее, затем работает.

`tag=<тег>` — хосты с этим тегом (точное совпадение), `tag=-` — хосты без тегов; `policy=<policy_id>` — хосты групп,
на которые действует политика (своя или унаследованная). `q` дополнительно ищет по тегам.

**Статус устройства по KSC с причинами.** `status` — `KLHST_WKS_STATUS_ID` (`ok` | `warning` | `critical`);
`status_reasons` — почему сервер KSC так считает: расшифрованные биты `KLHST_WKS_STATUS_MASK` по порядку номеров
(`STATUS_MASK_REASONS` в `core/export.py`, 20 битов; бит без расшифровки — «код N»), затем, если непустой, текст
статуса, заданного управляемым продуктом (`KLHST_WKS_STATUS_HSDP`, бит 18) — как есть, это текст продукта, не наш.
У статуса `ok` с пустой маской — `[]`; статус не `ok` без единого бита и без текста — `["причина не расшифрована"]`
(так же в находках `HOST_CRITICAL` и `HOST_WARNING`). `null` — причины не разобраны: строка хоста записана до этой
версии (в `extra_json` нет ключей `status_mask`, `status_text`); пересчёт снапшота (`reanalyze`) переписывает строки
хостов и заполняет их. Маска и текст лежат в `extra.status_mask` (число) и `extra.status_text`. Фильтр
`status_reason=<текст причины>` — повтором ключа, внутри «или», текст — точно как в `status_reasons`; неизвестный
текст просто ничего не находит (не 422). Фасет `status_reason: {текст: n}` — только непустые причины
отфильтрованного набора; у строк с `null` причин в фасете нет. Расшифровка битов маски с консолью KSC не сверена
(см. «Известные оговорки»). Устройство со статусом `warning` даёт находку `HOST_WARNING` (Low), с `critical` — как и
прежде `HOST_CRITICAL` (Medium); `details.reasons` обеих — те же `status_reasons`. С появлением `HOST_WARNING`
`ANALYZER_VERSION` модуля — `3`: первый снапшот новой версии после снапшота версии `2` статусы находок не сверяет
(см. «Находки»).

Фасеты (по отфильтрованному набору) дополнены: `component: {русское название: {on, off, other}}` и `tag: {тег: n}`.
Теги приходят не от всех сборщиков: `tags_collected` — в выгрузке снапшота была секция тегов. Если нет, у хоста
`tags: null`, фасета `tag` в ответе нет, фильтр `tag` (включая `-`) ничего не находит. Если секция была, у хоста
без тегов — `tags: []`.

Элемент хоста несёт `extra`: `os_build`, `cpu_arch`, `vm_type`,
`reboot_required`, `reboot_requested_at`, `reboot_reason`, `edr_status`,
`managed_by_other_server` — расширенные поля блока 1 (`KLHST_WKS_OS_BUILD_NUMBER`
и другие из `docs/superpowers/specs/2026-09-17-ksc-data-expansion-design.md`).
Они не входят в колонки таблицы `ksc_host` — хранятся в текстовой колонке
`extra_json`, отдельной от `components_json`. `vm_type`, `edr_status` — сырые
коды KSC (`HST_VM_TYPE`, `KLHST_WKS_EDR_STATUS`): их перечисления в открытой
документации Open API не описаны, поэтому на экране показываются как есть,
без расшифровки.

`agent`, `bases` — фасады над `agent_silent_days` и `bases_old_days` из
настроек: считаются на лету от `snapshot.collected_at`, в базе не хранятся.

Профили на хосте (`/hosts/{host_id}/profiles`; `404` — хоста нет в снапшоте): политики группы хоста, как `policies`
карточки, у каждой — профили по приоритету и их активация на этом хосте, вычисленная по тегам хоста
(`core/profile_activation.py`). `profiles_collected` у политики — как `profiles != null` (у политик агента и сервера
профили не читаются — «не собрано», не «без профилей»); верхний `profiles_collected` — секция профилей была хотя бы
у одной политики снапшота. `tags` — теги хоста (`null` — не собраны). У профиля: `active` — `true` (активен),
`false`, `null` (не определить); `reason` — «по тегу X» / «по тегам X, Y» (`matched_tags` — эти теги в написании
хоста), «нет подходящего тега», «правил активации нет» (пустое условие: в KSC такой профиль не активируется),
«профиль выключен» (`enabled: false`, условие при этом не вычисляется), «условие не по тегам», «теги хоста не
собраны»; `condition` — условие словами: список групп, группа — список условий `{field: tag|nla|cpus|unknown, text}`
(пусто — правил активации нет); `settings` — настроек профиля; `exclusions`, `net_rules` — записей профиля в
таблицах исключений и правил (`null` — продукт политики не описан: записей нет потому, что извлекателя нет). `by_tag` —
для каждого тега хоста (в его порядке) профили политик хоста, в условии которых этот тег встречается (без учёта
регистра), включая выключенные — с `enabled`; теги не собраны — пустой список.

**Трактовка условия активации** (с консолью KSC не сверена — принята по виду данных). Условие профиля
(`condition.EXPRESSION` в карточке политики, атрибуты как пришли): `EXPRESSION.KLPRSS_Val` — список с одним элементом
`{"ARGS": [<группа>…], "LOP": 2}`; группа — `{"ARGS": [<условие>…], "LOP": 1, "Name": "…"}`; условие —
`{"OP": <код>, "name": "<поле>", "val": <значение>}`; пустое условие — `KLPRSS_Val: [{}]`. Известные поля:
`NGTPP_sHostTag` (тег хоста, `OP` 9), `NGTPP_sNlaLocation` (сетевое расположение, `OP` 7), `NGTPP_nCpus` (число
процессоров, `OP` 7). Принято: внутри группы все условия должны выполниться (И), профиль активен, если выполнена хоть
одна группа (ИЛИ); условие по тегу выполнено, если у хоста есть тег с таким значением (сравнение без учёта регистра).
Коды `OP` не расшифрованы: у тега код 9 считается «равно», другой код — «не определить». Поле не из списка известных и
нетеговые поля (сетевое расположение, число процессоров) по снапшоту решить нельзя: группа с таким условием — «не
определить», если только несовпавший тег в ней не отверг её (тогда «нет»); «не определить» целиком — когда ни одна
группа не решена тегами в «да». Теги не собраны и в условии есть тег — «теги хоста не собраны»; без тегов в условии —
«условие не по тегам». Типизированные значения (`{"type": "long", …}`) и обёртки `params` снимаются; условие
неожиданной формы — группа из одного условия `unknown` («условие не разобрано»).
`in_ad` — `both`, если хост сопоставлен с включённым компьютером домена по
последнему снапшоту модуля AD на момент анализа, `ksc_only` — если нет,
`null` — снапшота AD не было вовсе.

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
настройки `GET/PUT /api/settings/findings` (`module=ksc`, `scope_id` — id сервера KSC).
Своих ручек смены статуса у модуля нет.

Строка списка — поля находки и её состояние: `status`, `status_title`,
`assignee`, `assignee_name`, `due_date`, `overdue`, `risk_until`,
`first_seen_at`, `age_days`, `delta` (`new` — нет в предыдущем снапшоте
сервера, `same` — была, `gone` — нет в последнем снапшоте: данные из
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
снапшот — последний сервера по времени сбора, и после удаления снапшота.
Если у последнего и предыдущего снапшота разные `analyzer_version`, пропажи
не считаются и «устранена» не ставится: ключи находок разных версий не
сравнимы (в журнал — предупреждение).

Не собрано ≠ пусто: пропажа находок проверок, которые в последнем снапшоте не проверялись, — не устранение (их статусы
сверка не трогает). Это `COVER_AD_MISSING` и `COVER_KSC_ONLY` без снапшота AD и проверки оценки политик (`GRADE_CHECKS`,
см. «Оценка политики»), если хотя бы у одной активной политики продукта защиты содержимое не собрано (сбой сбора, отказ
чтения или предел `policy_contents_max_policies`) или собрано не полностью (секции прочитались, но `errors` записи не пуст:
ошибка чтения секции или секция больше лимита) — грубо, по проверке целиком, а не по политике. Счётчики — в
`stats_json` снапшота: `policies = {active_protection, without_contents, partial}` (пишутся при импорте и пересчёте; у
снапшота, посчитанного раньше, их нет — правило не действует до пересчёта).

Находки про хост несут `host`, находки про группу, политику, задачу или
лицензию — только `target` (путь группы, имя политики/задачи/ключа), `host` пуст.
Находки про сервер (`KSC_2FA_OFF`, `KSC_INTERNAL_ADMIN`, `KSC_ADMINS`,
`SERVER_CERT`, `SECONDARY_SERVER_STALE`) не привязаны ни к хосту, ни к
группе: `target` — учётка (UPN, а если его нет — отображаемое имя),
сертификат или подчинённый сервер. Это обычные находки: их отдаёт
`/findings` наравне с остальными, а `GET /server` (ниже) показывает те же
строки, отфильтрованные по коду проверки.

Ключ находки про хост (`host_key`) строится из FQDN устройства
(`KLHST_WKS_FQDN`), а не из отображаемого имени (`KLHST_WKS_DN`) — оно не
уникально в выгрузке. Если у хоста нет FQDN, используется имя в нижнем
регистре. Этот же ключ соединяет находки с карточкой хоста в
`/hosts/{host_id}` и со счётчиком `findings` в списке `/hosts`.

## Политики и задачи группы

```
GET  /snapshots/{id}/policies          {groups: [{id, name, path, level, hosts,
                                        policies: [{id, name, product, active, inherited,
                                                    accept_parent, modified_at, modified_group,
                                                    locks: {total, locked, with_lock_flag}|null,
                                                    has_contents}],
                                        tasks: [{id, name, type, product, inherited, schedule,
                                                 last_run_at, ok, warning, failed}],
                                        findings: [{key, check, check_title, severity}]}]}
GET  /snapshots/{id}/policies/{policy_id}/contents
                                        {policy: {id, name, product, version, group},
                                        summary: {total, locked, share, with_lock_flag}|null,
                                        sections: [{name, settings: [{path, value, locked,
                                                                       inherited_lock, lock_from}]}],
                                        errors: [...]}
```

Дерево строится из сохранённого файла выгрузки, а не из базы (`404`, если
файл снапшота удалён вручную с диска). Корнями считаются и группы без
родителя, и группы, чей `parentId` отсутствует в выгрузке (частичный
экспорт) — иначе их поддерево пропадает из ответа. `findings` группы — те
находки `POLICY_NONE`, `POLICY_INHERIT_BROKEN`, `TASK_NO_UPDATE`,
`TASK_NO_SCAN`, чей `target` совпадает с путём группы.

У задачи `last_run_at` — `TASK_LAST_EXEC_TIME`; `ok`, `warning`, `failed` —
счётчики устройств из последнего запуска (`statistics["4"|"8"|"16"]`,
`Tasks.GetTaskStatistics`), а не история запусков — это тот же сырой ответ,
что читает `TASK_FAILED` (см. «Известные оговорки»).

У политики продукта защиты `locks` — свод по замкам её содержимого
(`total`, `locked`, `with_lock_flag` — из `walk_settings`/`lock_summary`,
`core/policy_contents.py`; `with_lock_flag` — сколько настроек несут
признак замка `KLPRSS_Mnd`, `0` — замки в политике не распознаны, экран
пишет «замки не распознаны»); свод считается один раз на политику за
запрос, сколько бы групп её ни получали. `null`, если содержимого нет в
секции `policy_contents` (нет прав или ошибка сбора — см. «Формат
выгрузки»). `has_contents` — есть ли у политики запись в `policy_contents`
вообще (`true` и тогда, когда все её секции провалились или политика
пропущена по лимиту и `sections` пуст — `locks` при этом не `null`, а
`{total: 0, locked: 0, with_lock_flag: 0}`). Для политик агента и сервера (`KLPOL_PRODUCT`
`1103`/`1093`) содержимое не собирается — `locks` всегда `null`,
`has_contents` всегда `false`.

`GET /policies/{policy_id}/contents` берёт данные из того же сохранённого
файла выгрузки (`404`, если файл или политика не найдены). `summary.share` —
доля замкнутых среди настроек с признаком замка (`locked / with_lock_flag`,
`0`, если таких нет); при `with_lock_flag == 0` страница показывает «замки в
этой политике не распознаны». Значения длиннее
200 символов (JSON-представление) обрезаются с пометкой «… (обрезано)»
(`truncate_value`). Если политики нет в `policy_contents` — `summary: null`,
`sections: []`, `errors: ["содержимое не собрано"]`; это отдельный случай от
ситуации, когда запись есть, но пуста (`summary` тогда `{total: 0, locked: 0,
share: 0, with_lock_flag: 0}`, `errors` несёт причины из сборщика, в том
числе «лимит политик») — обе неотличимы от «замков
нет» на экране, поэтому за них отвечает справочная `POLICY_CONTENT_MISSING`
(см. «Проверки»), не сама ручка.

## Аналитика политик

```
GET  /snapshots/{id}/policy-list?q=&product=&active=true|false&grade=bad|ok|good|none
                                        {items: [PolicyItem], facets: {product: {код: n}, active: {true, false},
                                                 grade: {bad, ok, good, none}},
                                        profiles_collected}
GET  /snapshots/{id}/policies/{pid}     PolicyItem + {settings_total, settings_known, errors: [str], changes}
GET  /snapshots/{id}/policies/{pid}/findings
                                        {items: [{key, check, check_title, severity, status, status_title,
                                                  counted: bool, details}]}
GET  /snapshots/{id}/policies/{pid}/scope
                                        {groups: [{group_id, path, own, hosts}], hosts}
GET  /snapshots/{id}/policies/{pid}/profiles
                                        {collected, errors: [str],
                                        profiles: [{name, enabled, priority, condition, settings, errors,
                                                    diff: [{section, path, value, policy_value, locked}]}]}
GET  /snapshots/{id}/policies/{pid}/settings
                                        {described, known, total,
                                        groups: [{component, title, enabled: bool|null,
                                                  settings: [{section, path, title, value, raw, locked, verified}]}],
                                        other: [{section, path, value, locked}]}
GET  /snapshots/{id}/policy-list/export?format=csv|xlsx&<те же фильтры>   → файл
GET  /snapshots/{id}/tasks?q=&type=&failed=true
                                        {items: [{id, name, type, product, group, schedule, last_run_at,
                                                  ok, warning, failed}], facets: {type: {тип: n}}}
GET  /snapshots/{id}/tasks/export?format=csv|xlsx&<те же фильтры>         → файл
```

Многозначные: у списка политик — `product` и `grade` (`grade=bad&grade=none`), у задач — `type`; повторением
ключа, внутри фасета — «или», `all` — не задан. Выгрузки — весь отфильтрованный список в его порядке, любой роли,
формат — общая «Выгрузка списков» (`docs/api-contract.md`).

`PolicyItem` = `{id, name, product, version, group, active, accept_parent, modified_at, has_contents,
contents_partial, described, groups, hosts, profiles, exclusions, net_rules, locks: {locked, with_lock_flag}|null, grade,
grade_reason, findings}`. Список, привязка и счётчики — из таблиц снапшота (`ksc_policy`, `ksc_policy_scope`,
`ksc_profile`); они заполняются при импорте и пересчёте, а у снапшота, импортированного до их появления, —
при первом обращении к политикам, исключениям, сетевым правилам или хостам снапшота (из файла выгрузки, вместе с
группой у хостов; находки и журнал изменений не трогаются — для них нужен «пересчитать»). Нет файла — списки
остаются пустыми. `404` — снапшот или политика не найдены; `404 «файл выгрузки не найден»` —
файл снапшота удалён с диска (он нужен ради замков, отличий профилей, ошибок сбора и задач; список
политик файл не открывает, пока ни у одной политики нет содержимого).

Список: `q` — подстрока имени (без регистра), `product` — код продукта, `active` — признак активности;
фасеты считаются по отфильтрованному набору. Порядок: активные первыми, затем по имени. `groups` и `hosts` — групп,
где политика действует (своя группа и наследники), и хостов прямо в них (в каждой группе только прямые хосты, без подгрупп). `group` — группа, где политика создана.
`locks` — свод замков содержимого (`null`, если содержимого нет); `findings` — считаемые находки оценки политики
(см. «Оценка политики» ниже; по `details.policy_id`, одноимённые политики счёт не делят).

Не собрано и пусто: `profiles: null` — профили политики не собраны (выгрузка без секции `policy_profiles`,
политика агента/сервера, отказ чтения списка профилей без единого профиля), `0` — собраны, профилей нет.
`profiles_collected` — хотя бы у одной политики снапшота `profiles` не `null` (по таблице, без чтения файла);
`false` значит, что профили в выгрузке не собирались вовсе.

`described` — для продукта есть извлекатель исключений и сетевых правил (`core/policy_model.EXTRACTORS`).

Оценка политики (`services/grade.py`). Находки оценки — находки снапшота проверок `GRADE_CHECKS` (все `POLICY_*`, кроме
`POLICY_NONE`, `POLICY_INHERIT_BROKEN` и справочной `POLICY_CONTENT_MISSING`: `POLICY_NO_LOCKS`, `POLICY_WEAK_LOCKS`,
`POLICY_EXCLUSION_RISKY` и правила оценки из «Проверок»), отнесённые к политике по `details.policy_id`. Считается
находка, если её статус платформы входит в учитываемые (настройка `counted`, то же правило, что счётчик находок хоста):
по умолчанию «принят риск», «ложное срабатывание» и «устранена» оценку не портят. `grade`: `bad` — среди считаемых есть
Critical или High, `ok` — только Medium или Low, `good` — ни одной из них (Info оценку не меняет); `grade_reason` —
пояснение. Политика, собранная не полностью (`ksc_policy.contents_partial`: секции есть, но `errors` записи содержимого не
пуст), «нормальной» и «хорошей» не бывает: при считаемой Critical или High она `bad` (если оценка возможна по остальным
условиям, к причине `bad` дописано « (содержимое собрано не полностью)»), иначе без оценки. `grade: null` с причиной, в
порядке проверки: «содержимое не собрано» (нет содержимого), иначе для снапшота, посчитанного другой версией
анализатора, — «пересчитайте снапшот: оценка считается с версии анализатора 2» (у находок прежних версий нет `policy_id`,
а `settings_known` и `contents_partial` у строк, записанных до их появления, — `0` и `false` до пересчёта), иначе
«политика неактивна», иначе «содержимое собрано не полностью» (неполное и без считаемых Critical/High), иначе
«структура продукта не описана» (для продукта нет словаря, сейчас описан только `KES`), иначе «настройки политики не
распознаны словарём» (словарь есть, но `settings_known == 0` — например, другая версия продукта с иными именами секций:
правила молчат от незнания, и такая политика не может стать «хорошей»). `contents_partial` — признак неполного
содержимого: списки исключений, правил и настроек политики могут быть неполными. `findings` считается и для политик
без оценки. Какие секции не прочитались — `errors` карточки. Фильтр `grade` — оценка или `none` (без оценки),
другое значение — `422`; фасет `grade` — по отфильтрованному набору, как остальные. Оценка считается при каждом запросе:
смена статуса находки меняет её сразу, без пересчёта снапшота.

Находки политики (`/policies/{pid}/findings`): все находки оценки этой политики — и считаемые, и нет (`counted`), со
статусом платформы (`status`, `status_title`); порядок — считаемые первыми, затем по серьёзности. `404` — снапшот или
политика не найдены. Ключ находки по политике строится из имени политики (`target`) и `key_extra`: переименование
политики меняет ключи её находок — прежние уходят «устранёнными», новые появляются (существующее соглашение ключей).

Карточка: `settings_total` — настроек (листьев, см. «Настройки») в содержимом политики, `settings_known` — распознанных словарём продукта
(считается при импорте и пересчёте; `0`, если словаря нет), `errors` — ошибки сбора: содержимого (`policy_contents[…].errors`) и чтения профилей
(`policy_profiles[…].errors`), `changes` — записей журнала изменений этого снапшота по политике.

Привязка: строки по пути группы; `own` — политика создана в этой группе, `hosts` — хостов в ней
прямо; верхний `hosts` — сумма по группам.

Профили: `collected` — как `profiles != null` у политики; `errors` — ошибки чтения профилей политики целиком;
порядок профилей — по приоритету. `condition` — атрибуты профиля как пришли (включённость, условие
активации `EXPRESSION`), секреты скрыты при загрузке выгрузки. `diff` — каждая настройка профиля (`walk_settings`
по его секциям): `value` — её значение, `policy_value` — значение той же пары `(section, path)` в политике
(`null` — в политике такой настройки нет или содержимого политики нет в выгрузке), `locked` — признак замка
настройки профиля (`null` — признака нет); значения — JSON-текст, длиннее 200 знаков обрезаются (`truncate_value`).

Настройки — содержимое политики человеческим языком по словарю продукта (`core/dictionary`; пока есть только `KES` —
KES для Windows). Настройки считаются до листьев (`flat_settings`): секция проходится насквозь через контейнеры
`KLPRSS_Val` и обычные словари до не-словарей с полным путём (`a.b.c`), списки остаются целыми; замок листа — замок
ближайшего контейнера сверху (вне контейнеров — `null`), значения рядом с вложенными контейнерами не теряются; так
чтение не зависит от того, на каком уровне в выгрузке стоят контейнеры (замки и «Все поля» по-прежнему по
контейнерам). Секция сопоставляется по точному имени, настройка — по точному пути листа; всё остальное
(секции без компонента, уведомления, шаблоны сообщений, неизвестные ключи) — в `other` в техническом виде (`value` —
JSON-текст, как у профилей). `described: false` — словаря для продукта нет: `groups` пуст, все настройки в `other`.
`known` — распознанных, `total` — всех настроек (`known + len(other)`; совпадают с `settings_known` / `settings_total`
карточки). Группы — по компонентам защиты в порядке словаря (общие настройки, исключения и доверенная зона,
предотвращение вторжений, сетевой экран, защита от файловых угроз, …), пустые не отдаются; `enabled` — признак
«включён» компонента в политике (`null` — у компонента его нет, например у общих настроек и KSN, или его нет в
политике). `value` — значение по виду: «включено» / «выключено», подпись кода, число с единицей, строка («—» для
пустой, «<скрыто>» как есть), «записей: N» у списков; `raw` — значение как есть (JSON-текст, длиннее 200 знаков
обрезается). `verified: false` — код перечисления не расшифрован, значение показано «код N» (у KES для Windows
подписи подтверждены только у уровня эвристики). Значение не того вида, что ждёт словарь, показывается как есть,
без толкования. Секреты скрыты при загрузке выгрузки. `404` — как у карточки.

Задачи: плоский список всех задач выгрузки (не по дереву групп). `group` — путь группы из `PRTS_TASK_GROUPID`,
пусто — задача для набора устройств; `failed=true` оставляет задачи с `failed > 0` (счётчики —
как в `/policies`); `q` — подстрока имени, `type` — `TASK_NAME`. Порядок: по группе, затем по имени.

## Исключения, сетевые правила, изменения

```
GET  /snapshots/{id}/exclusions?q=&policy_id=&profile=&kind=&enabled=true|false&dup=multi|single|covered&risky=true|false&host_id=&limit=200&offset=0
                                        {total, items: [{id, policy_id, policy_name, profile, kind, value, components,
                                                         enabled, comment, risks, risk_titles, key, policies, covered_by}],
                                        facets: {policy: {id: n}, kind, enabled: {true, false}, dup: {multi, single, covered},
                                                 risky: {true, false}}|null,
                                        summary: [{policy_id, policy_name, hosts, total, by_kind, risky, partial}]|null,
                                        undescribed: [код продукта],
                                        undetermined: [{policy_id, policy_name, profile}] — только с host_id}
GET  /snapshots/{id}/exclusions/{row_id}  {…элемент списка (включая policies, covered_by),
                                        risk_details: [{code, severity, title, detail, recommendations: [str]}],
                                        same_in: [{row_id, policy_id, policy_name, profile, enabled}],
                                        policy_hosts, policy_partial}
GET  /snapshots/{id}/net-rules?q=&policy_id=&profile=&action=&direction=&enabled=&host_id=&limit=200&offset=0
                                        {total, items: [{id, policy_id, policy_name, profile, layer, position, name, action,
                                                         direction, protocol, local_ports, remote_ports, addresses, enabled, key}],
                                        facets: {policy, action, direction, layer, enabled}|null, undescribed: [код продукта],
                                        partial: [policy_id], undetermined: [{policy_id, policy_name, profile}] — только с host_id}
GET  /snapshots/{id}/net-rules/{row_id}   {…элемент списка, same_in: [{row_id, policy_id, policy_name, profile, enabled}],
                                        policy_hosts, policy_partial}
GET  /servers/{id}/changes?kind=&action=&policy_id=&snapshot_id=&limit=200&offset=0
                                        {total, items: [{id, snapshot_id, collected_at, kind, action, policy_id, policy_name,
                                                         profile, section, path, before, after}],
                                        facets: {kind: {…}, action: {…}}|null,
                                        snapshots: [{id, collected_at, prev, total|null, compared, truncated, reason|null}]}
GET  /snapshots/{id}/exclusions/export?format=csv|xlsx&<те же фильтры>   → файл
GET  /snapshots/{id}/net-rules/export?format=csv|xlsx&<те же фильтры>    → файл
GET  /servers/{id}/changes/export?format=csv|xlsx&<те же фильтры>        → файл
```

Многозначные (повторением ключа, внутри фасета — «или», `all` — не задан): у исключений — `policy_id`, `kind`, `dup`
(`?policy_id=12&policy_id=15&dup=multi`), у сетевых правил — `policy_id`, `action`, `direction`, у изменений —
`kind`, `action`, `policy_id`, `snapshot_id`; `policy_id` и `snapshot_id` — числа. Остальные параметры однозначные.
Выгрузки — все записи под фильтрами списка без `limit`/`offset`, в его порядке, любой роли; формат — общая
«Выгрузка списков» (`docs/api-contract.md`: CSV — UTF-8 с BOM, `;`, CRLF, потоком; XLSX — не больше 100 000 строк и
строка-предупреждение).

`404` — снапшот или сервер не найдены, у карточек — ещё «исключение не найдено» / «правило не найдено» (строки нет
или она из другого снапшота), с `host_id` — «хост не найден»; `422` — неизвестное значение `dup` или `limit` вне 1..1000.
`facets` (и `summary` у исключений) приходят только при `offset=0`, иначе `null`.

`host_id=<host_id хоста>` — записи, действующие на хост: политик его группы (`ksc_policy_scope`, как `policies` карточки
хоста), у которых запись принадлежит самой политике (`profile` пуст) или профилю, активному на хосте по тегам (см.
«Профили на хосте» в разделе «Хосты» — та же трактовка условия). Профиль, активацию которого не определить (условие не по
тегам, теги хоста не собраны), не исключается: его записи остаются в списке, а сам профиль перечислен в `undetermined`,
чтобы интерфейс пометил их как «возможно»; выключенный и не подошедший по тегам профиль — исключается. Фасет `policy` и
`total` считаются по этому набору; с `policy_id`, `profile` и другими фильтрами — пересечение; `summary` исключений,
`policies` и `covered_by` по-прежнему по всему снапшоту. Без `host_id` ключа `undetermined` в ответе нет.

Карточка исключения или правила — та же строка, что в списке (у исключения `policies` и `covered_by` считаются по
всем строкам снапшота, как в списке), плюс `same_in` — другие строки снапшота с тем же `key`: та же запись в других
политиках и в профилях (в том числе профилях той же политики), без самой строки, по имени политики, затем профиль;
`policy_hosts` — хостов под политикой записи; `policy_partial` — содержимое этой политики собрано не полностью.
У исключения ещё `risk_details` — риски из `risks` в том же порядке с полями `Risk` (ниже); код, которого в правилах
уже нет, — `{code, severity: "", title: code, detail: "", recommendations: []}`.

Исключения и правила берутся из таблиц снапшота, которые заполняет извлекатель продукта при импорте. `undescribed` —
коды продуктов политик с содержимым, для которых извлекателя нет: у них список пуст потому, что продукт не описан,
а не потому, что исключений нет (у `summary` такие политики не показываются).

Извлекатель есть только у `KES` (KES для Windows, `core/extractors/kes_windows.py`). Он читает секции в «голом» виде
(`bare_sections`: контейнеры `KLPRSS_Val` на любом уровне заменены значениями, обёртки типов сняты), поэтому не зависит
от уровня контейнеров в выгрузке; элемент списка неожиданной формы пропускается. Запись выключена только явным
`enabled: false` (нет признака или он скрыт — включена). Сбой извлекателя импорт не роняет: ошибка — в журнал
приложения, записей у политики нет, продукт считается описанным.
- Исключения — `852d0287` `scanExclusionsAndTrustedZone.scanExclusions[]`: `kind` `hash` (задан `fileHash`), иначе `mask`
  (в `objectMask.objectPath` есть `*` или `?`), иначе `path`, иначе `threat` (только `objectName`). `value` — хеш, путь
  или имя объекта; `components` — подписи из `components[]`, затем «объект: <имя>» (имя объекта при заданном пути или
  хеше) и «рекурсивно» (`objectMask.recursive`).
- Доверенные программы — `…trustedApplications[]`: `kind=trusted_app`, `value` — `filePath`, `components` — подписи
  включённых флагов `exclude*` («не проверять открываемые файлы», «не контролировать активность», «не проверять сетевой
  трафик (только зашифрованный)» и т. д.); при отключённой проверке трафика — ещё «узлы: …» и «порты: …» из
  `excludeNet.hosts` / `excludeNet.ports`.
- Сетевые правила — `cf9370d5`: `firewall.networkPacketRules[]` — слой `packet`; `hips.appGroups[].networkPacketRules[]`
  и `hips.appGroups[].applications[].networkPacketRules[]` — слой `app`, `name` — «<группа или программа>: <правило>».
  `position` — сквозной номер оставленных правил в слое с 0 (`app` — по всем группам: правила группы, затем её
  программ); `log` и `networkAdapters` в запись не переносятся. `action`: разрешить / запретить / по правилам
  программ; `direction`: входящий (пакет), исходящий (пакет), входящий/исходящий, входящий (поток), исходящий (поток);
  `protocol`: TCP, UDP, ICMP, ICMPv6, без протокола — «любой», у ICMP и ICMPv6 с видом (`protocol.type.value`) —
  «ICMP (вид N)»; неизвестный код — «код N». Порты — `53, 1024-65535`. `addresses` через `; `: сети (`scope.networks`: доверенные / локальные / публичные сети), удалённые
  адреса, локальные — с префиксом «локальный: »; адрес — имя узла, иначе `octets` (4 или 16 байт) с `/маской`, иначе
  адреса из `hostNameIPs`; «адрес скрыт (сборщик до 1.3)» — `octets` скрыт старым сборщиком, «адрес не разобран» —
  другой длины.
- Списки-источники (`scanExclusions`, `trustedApplications`, их `*_merging_crutch`, `firewall.networkPacketRules`)
  журнал изменений как настройки не считает — их правки видны записями `exclusion` / `net_rule`. `hips.appGroups`
  остаётся настройкой: в нём же правила доступа к сети, привилегии, ресурсы и пути программ. Поэтому правка правила
  программы видна дважды — строкой `setting` по `hips.appGroups` и записью `net_rule`. `local*`, `exclusionGroups`,
  `edrExclusionsSettings` в записи не превращаются.

Поиск `q` — подстрока без регистра: у исключений в `value`, `comment` и имени политики, у правил в `name`, `addresses`
и портах. Порядок: имя политики, сама политика раньше профилей (`profile` — пустая строка у самой политики; фильтр `profile=` с пустым значением
оставляет только политику), затем значение (у правил — слой и позиция). Фасеты считаются по отфильтрованному набору.
`summary` — без фильтров, по политикам с описанным продуктом и собранным содержимым: исключений по видам, `hosts`
(хостов под политикой), `risky` (исключений с непустыми `risks`) и `partial` (содержимое собрано не полностью — список
может быть неполным: не собрано ≠ пусто). `partial` у сетевых правил — id таких политик описанного продукта (при любом
`offset`).

Дубли и перекрытия считаются по всем исключениям снапшота, фильтры на них не влияют: `policies` — в скольких политиках
встречается тот же `key` (вид и значение без регистра, профиль не учитывается); `dup=multi` — `policies > 1`, `single` —
`policies == 1`. `covered_by` — значение более широкого включённого исключения-пути или маски в той же политике и
профиле (каталог-префикс по границе разделителя, замыкающий разделитель не в счёт, или подходящая маска; равное
значение перекрытием не считается; исключение, суженное именем объекта — «объект: X», X ≠ `*`, — других не перекрывает),
иначе `null`; `dup=covered` — `covered_by` не пуст. Перекрытия группы (политика, профиль) считаются только когда нужны:
для фильтра `dup`, фасетов и строк страницы.

`risks` — коды рисков исключения (`core/exclusion_risks.py`), `risk_titles` — их объяснения в том же порядке (код, которого
в правилах уже нет, показывается как есть); `risky=true` — `risks` не пуст, `false` — пуст. Описание риска — `Risk`
(`RISKS: dict[code, Risk]`, порядок кодов как в таблице ниже): `severity` (High | Medium), `title` — короткое
объяснение (оно же `risk_titles` и `why` у находки), `detail` — что именно открывает исключение (2–4 предложения),
`recommendations` — 2–4 пункта, как сузить или закрыть; тексты общие по продукту, без привязки к инфраструктуре,
в каждом последним пунктом — комментарий с причиной, владельцем и датой и периодический пересмотр. Коды считаются при импорте
и пересчёте по спискам настроек модуля на тот момент: после правки списков нужен пересчёт снапшота. Выключенное
исключение рисков не имеет. Пути сравниваются без регистра, `/` и `\` не различаются, переменные окружения — как
текст; правила пути действуют на виды `path`, `mask` и `trusted_app`. Исключение с путём и именем объекта (в
`components` — «объект: <маска>», маска не `*`) касается одной угрозы в этом пути: правила ширины (`whole_drive`,
`user_writable`, `ext_mask`, `name_only`) к нему не применяются, `interpreter` — применяется; «объект: *» сужением не
считается. «Без каталога» — часть пути до имени пуста или состоит только из `*` и `\` (`tool.exe`, `*\tool.exe`,
`**\tool.exe`). Последний компонент пути, который целиком — переменная окружения (`%TEMP%`, `%ProgramFiles%`), —
каталог, а не имя файла.
Пустые элементы списков и пробелы по краям отбрасываются при сохранении настроек.

| Код | Серьёзность | Когда |
|---|---|---|
| `whole_drive` | High | Диск целиком или его корень: `C:\`, `C:\*`, `?:\*`, `*`, `\\*`, `%SystemDrive%\`, `\\?\C:\` (префикс `\\?\` снимается, замыкающие `\` и `*` отбрасываются, остаток пуст, `X:`, `?:` или `%systemdrive%`); остальные правила ширины тогда не проверяются |
| `user_writable` | High | Путь содержит подстроку из `exclusion_user_writable`; к пути добавляется замыкающий `\`, так что каталог `C:\Temp` совпадает с `\temp\` |
| `ext_mask` | High | Без каталога или прямо от корня диска (`*.exe`, `*\*.dll`, `C:\*.exe`, `C:\**\*.exe`), и маска имени покрывает маску из `exclusion_exec_extensions` (`*.exe`, `*.ex?`, `*.*`). Маска расширения не из списка (`*.log`, `*.mdf`) риска не несёт |
| `name_only` | Medium | Имя файла без каталога и без `*`/`?` в самом имени: `tool.exe`, `*\tool.exe`, `**\tool.exe` (`C:\tool.exe` — не он) |
| `interpreter` | High | Имя файла — из `exclusion_interpreters` (`powershell.exe`, `cmd.exe`, …) |
| `broad_trust` | Medium | Доверенная программа, у которой сняты три и больше из: проверка открываемых файлов, контроль активности, проверка сетевого трафика (в том числе только зашифрованного), контроль дочерних процессов (в том числе рекурсивно) |
| `threat_any` | High | Исключение по имени объекта (`kind=threat`) равно `*` |

Изменения — записи `ksc_change` всех снапшотов сервера (у настроек, `kind=setting`, `path` — путь листа, как у
«Настроек» политики): порядок — снапшот по убыванию времени сбора, затем `id`;
фасеты по отфильтрованному набору; `before` и `after` — как сохранены (JSON). `snapshots` — все снапшоты сервера,
новые первыми, со сводом: `prev` — с чем сравнивали (`null` — сравнивать не с чем, `total` тогда `0`, `compared`
пуст), `compared` — какие виды изменений сравнивались (`false` — «не сравнивалось», не «без изменений»: нет
извлекателя продукта или у предыдущего снапшота не собрано), `truncated` — записей больше лимита сравнения,
`reason` — причина несравнения. `total: null` — изменения у снапшота не считались (импортирован до журнала изменений),
нужен пересчёт. Записи `exclusion` / `net_rule` сравниваются по `(профиль, key)` как мультимножества: `key` у разных
записей может совпасть (один путь с разными именами объекта, одноимённые правила программ). По одной записи с каждой
стороны — `changed`, иначе записи без пары — `removed` / `added`; `path` — `key`. `position` правила не сравнивается
(вставка или удаление правила сдвигает номера всех ниже — это не их изменение), но остаётся в `before` / `after`. Тот же свод последнего снапшота — `changes` в обзоре сервера (`null`, если снапшотов нет).

## Сервер KSC

```
GET  /snapshots/{id}/server            {two_factor_required_for_all,
                                        admins: [{account, internal, role, group}],
                                        certs: [{function, subject, not_after, days_left}],
                                        secondary_servers: [{name, address, version,
                                                             last_connected, status}],
                                        update_agents: [{host, group}],
                                        warnings: [...],
                                        findings: [{key, check, check_title, severity, target}]}
```

Данные из сохранённого файла выгрузки, как у `/policies` (`404`, если файл
снапшота удалён с диска). `admins` — держатели ролей из `admin_role_patterns`
(и внутренние, и доменные учётки), `internal` — признак внутренней учётки
KSC (не доменной); `account` — то же значение, что `target` находок о
ролях (UPN, иначе отображаемое имя), поэтому находки пристают к строке
таблицы. Секция `internal_users` в выгрузке остаётся (проверка про
административные роли читает `role_assignments`, список внутренних учёток
пригодится дальше), но в ответе ручки её нет — на экране он не
показывается. `certs` — записи `server_certs`, у которых сертификат
разобран (`cryptography` читает `CPublic`); `function` — номер функции
`CertPoolCtrl.GetCertificateInfo` (`1`..`4`) как строка, не расшифровывается.
`secondary_servers.status` — сырой код `KLSRVH_SRV_STATUS`: перечисление не
документировано в открытом Open API, значение показывается как есть.
`warnings` — предупреждения сбора секций сервера (`server.warnings` в
файле): отказ в правах на метод для конкретной секции, а не для всего
сбора. `findings` — те же `KSC_2FA_OFF`, `KSC_INTERNAL_ADMIN`, `KSC_ADMINS`,
`SERVER_CERT`, `SECONDARY_SERVER_STALE`, что лежат в базе находок снапшота,
здесь просто отфильтрованы по коду проверки.

## Сбор

```
GET  /collector.ps1                    PowerShell-сборщик (attachment)
GET  /connections                      [{id, title, host, port, username, password_set,
                                        verify_tls, internal, domain, server_id,
                                        skip_policy_contents, schedule}]
POST /connections  PUT /{id}  DELETE /{id}      пустой пароль в PUT — оставить прежний;
                                        DELETE уносит и расписание сбора
POST /connections/{id}/test            {ok, message, server_name, version}
POST /connections/{id}/collect         {job_id} | 400 нет логина или пароля | 409 идёт задача
GET  /connections/{id}/schedule        ScheduleView | null (не задано)
PUT  /connections/{id}/schedule        {interval_hours 1–720, window_from?, window_to?, enabled}
                                        → ScheduleView | 422 окно не ЧЧ:ММ или задан один конец
DELETE /connections/{id}/schedule      204 (и когда расписания нет) | 404 подключение не найдено
```

`internal` — внутренняя учётная запись KSC; `false` требует `domain`
(доменная учётная запись). Порт по умолчанию — 13299 (Open API KSC).
`skip_policy_contents` — не собирать секцию `policy_contents` при
онлайн-сборе (файл без содержимого политик заметно меньше); по умолчанию
`false` (собирать). Тот же переключатель в PowerShell-сборщике —
`-SkipPolicyContents`.

**Расписание сбора.** У подключения одно расписание — строка `platform_schedule
(ksc, collect, id подключения)`; `schedule` в списке подключений и ответ
`/schedule` — тот же `ScheduleView`, что у сетей Assets (`id, interval_hours,
window_from, window_to, enabled, next_run_at, last_run_at, last_job_id, tz`;
окно — в поясе `STOOLS_TZ`). Читать расписание могут все роли, менять —
аналитик и администратор, как и само подключение. Планировщик платформы
раз в минуту запускает ту же задачу `collect`, что и кнопка «собрать», со
`started_by = "расписание"` и адресом сервера в `message`; в списке задач
она выглядит как обычный сбор. Три отказа обработчика: подключения больше
нет — расписание удаляется; у подключения нет логина или пароля —
расписание выключается (`enabled=false`, в настройках «выключено»; после ввода
пароля его нужно включить заново в блоке расписания); идёт задача модуля (`import_file`, `collect`, `reanalyze`)
или заняты оба слота расписания — запуск откладывается на следующий тик,
а не на интервал.

## Настройки и задачи

```
GET  /settings   {config: KscConfig, defaults, checks: [{code, title, description}]}
PUT  /settings   KscConfig
GET  /jobs  GET /jobs/{id}  POST /jobs/{id}/cancel
```

`KscConfig`: `agent_silent_days` (по умолчанию 7), `bases_old_days` (3),
`fullscan_days` (30), `license_days` (30), `key_components` (код компонента
→ подстроки отображаемого имени на двух языках), `allowlist_hosts` (маски
`fnmatch` без учёта регистра — их находки понижаются до `Info` и
помечаются `allowlisted`), `task_failed_share` (0.2 — доля провалов
`statistics["16"]` от завершённых, с которой `TASK_FAILED` становится
High), `task_stale_days` (7 — `TASK_STALE`), `reboot_pending_days` (7 —
`REBOOT_PENDING`), `cert_days` (60 — `SERVER_CERT` становится High в
пределах этого срока, Critical — если сертификат уже истёк),
`admin_role_patterns` (имена ролей KSC, которые считаются
административными: по умолчанию `Main Administrator`, `Administrator`,
`Главный администратор`, `Администратор` — используются `KSC_INTERNAL_ADMIN`
и `KSC_ADMINS`), `policy_lock_share` (0.5 — доля замкнутых среди настроек
политики с признаком замка, ниже которой срабатывает `POLICY_WEAK_LOCKS`;
`0` не в счёт — это `POLICY_NO_LOCKS`), `policy_contents_max_policies` (200 — сколько активных
политик продуктов защиты собирает онлайн-сбор; PowerShell-сборщик несёт
тот же предел своей константой независимо от `KscConfig`), списки правил рисков исключений:
`exclusion_user_writable` (подстроки пути каталогов с правом записи пользователя: `\temp\`, `\tmp\`, `%temp%`,
`%tmp%`, `\downloads\`, `\appdata\`, `%appdata%`, `%localappdata%`, `%userprofile%`, `\users\public\`,
`\windows\temp\`; `ProgramData` в умолчаниях нет: подкаталоги поставщиков там закрыты правами, а находок High было бы
много), `exclusion_exec_extensions` (маски исполняемых: `*.exe`,
`*.dll`, `*.ps1`, `*.bat`, `*.cmd`, `*.js`, `*.vbs`, `*.scr`, `*.msi`, `*.jar`), `exclusion_interpreters` (`powershell.exe`,
`pwsh.exe`, `cmd.exe`, `wscript.exe`, `cscript.exe`, `mshta.exe`, `rundll32.exe`, `regsvr32.exe`, `python.exe`, `java.exe`,
`javaw.exe`, `msbuild.exe`, `installutil.exe`, `certutil.exe`, `bitsadmin.exe`, `wmic.exe`) — см. «Исключения»,
`policy_key_components` (коды компонентов словаря, выключение которых — `POLICY_COMPONENT_OFF`, а незамкнутый признак
«включён» — `POLICY_KEY_UNLOCKED`; по умолчанию все десять: `file_threat`, `behavior`, `exploit`, `network_threat`,
`remediation`, `web_threat`, `mail_threat`, `amsi`, `firewall`, `hips`).

Границы порогов: `cert_days` — находка есть, когда дней до истечения
**меньше или равно** порогу (60 дней → находка); `reboot_pending_days`,
`task_stale_days`, `agent_silent_days` — находка есть, когда возраст
**строго больше** порога (ровно 7 дней → находки нет). Возраст без даты
вовсе («никогда») считается превышением порога. `policy_lock_share` —
`POLICY_WEAK_LOCKS` срабатывает при доле замкнутых настроек **строго
меньше** порога (ровно 0.5 → находки нет); доля `0` при наличии настроек с
признаком замка — не `POLICY_WEAK_LOCKS`, а `POLICY_NO_LOCKS`.

`kind` задач: `import_file | collect | reanalyze`.

## Проверки

38 проверок, коды латиницей:

```
COVER_AD_MISSING        Есть в AD, нет в KSC
COVER_KSC_ONLY          Есть в KSC, нет в AD
NO_PROTECTION           Нет продукта защиты
RTP_OFF                 Постоянная защита не работает
NO_AGENT                Нет агента администрирования
BASES_OLD               Устаревшие базы
THREATS_ACTIVE          Необработанные угрозы
AGENT_SILENT            Агент давно не выходил на связь
UNASSIGNED              Нераспределённые устройства
COMPONENT_OFF           Выключен ключевой компонент
HOST_CRITICAL           Критический статус по KSC
HOST_WARNING            Предупреждение по статусу KSC
NO_FULLSCAN             Давно не было полного поиска
PRODUCT_OUTDATED        Устаревшая версия продукта или агента
POLICY_NONE             Нет действующей политики
POLICY_INHERIT_BROKEN   Наследование политики отключено
TASK_NO_UPDATE          Нет задачи обновления
TASK_NO_SCAN            Нет задачи поиска
LICENSE                 Лицензия
TASK_FAILED             Провалы в групповой задаче
TASK_STALE              Задача обновления давно не запускалась
REBOOT_PENDING          Зависла запрошенная перезагрузка
KSC_2FA_OFF             Двухэтапная проверка не обязательна для всех
KSC_INTERNAL_ADMIN      Административная роль у внутренней учётки KSC
KSC_ADMINS              Держатель административной роли
SERVER_CERT             Истекающий сертификат сервера
SECONDARY_SERVER_STALE  Подчинённый сервер молчит
POLICY_NO_LOCKS         В политике нет ни одного замка
POLICY_WEAK_LOCKS       Мало замкнутых настроек в политике
POLICY_CONTENT_MISSING  Содержимое политики не собрано
POLICY_EXCLUSION_RISKY  Опасное исключение в политике
POLICY_COMPONENT_OFF    Ключевой компонент выключен в политике
POLICY_NOTIFY_ONLY      Компонент только уведомляет
POLICY_SELFDEFENSE_OFF  Самозащита выключена
POLICY_PASSWORD_OFF     Нет защиты паролем
POLICY_THREAT_TYPES_OFF Выключено обнаружение типов угроз
POLICY_LOCAL_EXCLUSIONS Разрешены локальные исключения
POLICY_KEY_UNLOCKED     Ключевой признак не под замком
```

Восемь проверок начиная с `TASK_FAILED` — блок 1 расширения (результаты
задач, сервер KSC); три проверки начиная с `POLICY_NO_LOCKS` — блок 2 этап A
(содержимое политик и замки); `POLICY_EXCLUSION_RISKY` и семь правил оценки начиная с `POLICY_COMPONENT_OFF` — этап 2b;
их коды и описания — те же строки, что в `backend/api/modules/ksc/core/checks/__init__.py`.

Правила оценки (`core/checks/policy_rules.py`) проверяют активные политики продукта со словарём (`core/dictionary`, сейчас
`KES` — KES для Windows) и собранным содержимым. Значения читаются по листьям `flat_settings` (`find_setting`), от уровня
контейнеров `KLPRSS_Val` в выгрузке не зависят; нет настройки или значение не того вида — неизвестно, находки нет. У всех
`target` — имя политики, `details` — `{policy_id, product, …}`, `key_extra` начинается с id политики:

| Код | Серьёзность | Когда | Ключ (`key_extra`), детали |
|---|---|---|---|
| `POLICY_COMPONENT_OFF` | High: `file_threat`, `behavior`, `exploit`, `network_threat`, `remediation`; Medium: остальные | признак «включён» компонента из `policy_key_components` равен `false` | `{id}\|{компонент}`; `component`, `title` |
| `POLICY_NOTIFY_ONLY` | High | `firewall.notifyOnly`, `hips.notifyOnly`, `notifyOnly` защиты от сетевых угроз равно `true`, а компонент включён | `{id}\|{компонент}`; `component`, `title` |
| `POLICY_SELFDEFENSE_OFF` | High | `selfDefense.enableSelfDefence` равно `false` | `{id}` |
| `POLICY_PASSWORD_OFF` | Medium | `passwordProtection.passwordHash` равен `""` (сборщик 1.3+); `passwordProtection.login` не в счёт — учётная запись задана всегда (по умолчанию); `"<скрыто>"` (пароль задан или сборщик до 1.3 скрыл и пустое) или ключа нет — неизвестно, находки нет | `{id}` |
| `POLICY_THREAT_TYPES_OFF` | High, если выключены `virusesAndWorms`, `trojans` или `maliciousTools`; иначе Medium | выключено обнаружение типов `threats.*` (девять типов словаря) | `{id}`; `types`, `titles` |
| `POLICY_LOCAL_EXCLUSIONS` | Medium | `allowUseLocalScanExclusions` или `allowUseLocalTrustedApps` равно `true` | `{id}`; `allowed`, `titles` |
| `POLICY_KEY_UNLOCKED` | Medium | признак «включён» компонента из `policy_key_components` или `selfDefense.enableSelfDefence` не под замком (`locked` `false`; без признака замка — молчит) | `{id}`; `unlocked` (`self_defense` — самозащита), `titles` |

Состав списков в деталях (`types`, `allowed`, `unlocked`) в ключ не входит: находка на политику одна, её статус переживает
правку списка. `POLICY_NO_LOCKS`, `POLICY_WEAK_LOCKS`, `POLICY_CONTENT_MISSING` несут `details.policy_id` тоже, ключи у
них прежние. Правила «только уведомлять» для файловой и почтовой защиты нет: коды `scanAction` не расшифрованы.

`POLICY_EXCLUSION_RISKY` — находка на каждое исключение или доверенную программу с рисками (коды и правила — в
«Исключения») у активной политики с собранным содержимым и у её включённых профилей (`KLSSPOL_PRF_ENABLED`;
строки выключенного профиля в таблице исключений остаются с кодами, но находок не дают). Серьёзность — старшая из кодов;
`target` — имя политики; `details = {policy_id, profile, kind, value, risks, why, comment}` (`why` — объяснения
кодов); ключ — `f"{policy_id}|{profile}|{exclusion_key}"`: правка комментария находку не меняет. Исключение профиля —
отдельная находка, только если у самой политики нет записи с тем же `exclusion_key` и рисками (копия исключения
политики в профиле своей находки не даёт). Записи с одним ключом в той же политике и профиле (тот же вид и значение)
— одна находка: коды объединяются, серьёзность — старшая, `value`, `kind` и `comment` — первой записи.
Проверка считает по выгрузке, а не по таблице исключений; списки — из настроек на момент анализа.
С появлением проверки `ANALYZER_VERSION` модуля — `2`: первый снапшот новой версии после снапшота версии `1` статусы
находок не сверяет (см. «Находки»).

`POLICY_NO_LOCKS`, `POLICY_WEAK_LOCKS` разбирают только секцию
`policy_contents` и молчат на файле без неё (старый сборщик или
`skip_policy_contents`). Считают они только настройки с признаком замка
(`KLPRSS_Mnd`): настройка без признака в знаменатель доли не идёт, а
политика, где признака нет ни у одной настройки (`with_lock_flag == 0`,
формат замков не распознан), не оценивается вовсе — ни `High`, ни
`Medium`. Настройка — контейнер с `KLPRSS_Val`; внутрь `KLPRSS_Val` обход
спускается, только если среди его детей есть такой же контейнер, иначе весь
словарь — значение одной настройки с замком этого контейнера. `POLICY_CONTENT_MISSING` молчит тоже, если секции
нет вовсе — иначе отсутствие данных было бы неотличимо на экране от
«проверка прошла» на каждом файле без `policy_contents`; она срабатывает,
только когда секция в файле есть, а у конкретной активной политики продукта
защиты записи в ней нет (`case=missing`) или запись есть, но ни одна секция
не прочиталась (`case=empty`, оба случая — `Info`, различаются полем
`case` в `details` находки). Ни одна из трёх проверок не разбирает *смысл*
настроек KES (что выключена самозащита, слишком широкие исключения и
т. п.) — имена ключей и секций KES для Windows/Linux не документированы в
открытом Open API (описаны только сервер и агент), поэтому предметные
проверки по конкретным настройкам откладываются до первой живой выгрузки
заказчика, на которой эти имена станут известны (этап B, отдельная спека);
этап A ограничен тем, что не зависит от вендорских имён — сбором,
просмотром содержимого и подсчётом замков по универсальному формату
`KLPRSS_Val`/`KLPRSS_Mnd`.

`COVER_AD_MISSING` и `COVER_KSC_ONLY` считаются, только если у сервера есть
хотя бы один снапшот модуля AD; пересчёт снапшота KSC (`reanalyze`)
подхватывает актуальный на момент пересчёта снапшот AD, а не тот, что был
на момент сбора. Полные тексты описаний — `GET /settings` (`checks[]`) и
`GET /snapshots/{id}/findings/{key}` (`description`).

Без слоя ATT&CK: проверки модуля техник не объявляют, `register_layer` не
вызывается (решение зафиксировано в спеке).

## Известные оговорки

- **`TASK_NO_UPDATE`** видит только отсутствие групповой задачи обновления
  баз на группе с защищёнными устройствами — провал или ошибку последнего
  запуска существующей задачи проверка не обнаруживает. Сырой ответ
  `Tasks.GetTaskStatistics` сохраняется у каждой задачи в выгрузке под
  ключом `statistics` (см. `core/collector.py`) на будущее — под него
  написан `TASK_FAILED` (ниже).
- **`ip_from_long`** (`core/export.py`) разворачивает `KLHST_WKS_IP_LONG`
  как little-endian. На синтетике и тестовых выгрузках это даёт верный
  адрес, но порядок байт в этом поле у живого KSC 15.1 не проверялся —
  это будет сделано на первой выгрузке заказчика; при расхождении хосты
  получат неверный `ip` (сама находка `COVER_*` от этого не пострадает,
  сверка идёт по `host_id`, а не по IP).
- **`TASK_FAILED`** и счётчики `ok`/`warning`/`failed` в `/policies` считают
  хосты с провалом по статистике последнего запуска задачи
  (`Tasks.GetTaskStatistics`), а не по истории запусков: сколько раз задача
  проваливалась и когда — KSC этой проверке не сообщает, только текущий
  снимок счётчиков устройств.
- **Точки распространения** (`update_agents`, `UaControl.GetUpdateAgentsList`
  → `pUasArr`): имена полей записи (`KLUAGNT_HOST_DN`, `KLUAGNT_HOST_NAME`,
  `KLUAGNT_GROUP_ID`) взяты из документации и на живом сервере не
  проверены — пока это не сделано на первой выгрузке, блок «Точки
  распространения» на экране «Сервер KSC» может показывать пустые хост и
  группу, хотя сама секция собрана.
- **`SecondaryServerView.status`** (`/server`) и `extra.edr_status`
  (`/hosts`) — сырые коды KSC (`KLSRVH_SRV_STATUS`, `KLHST_WKS_EDR_STATUS`):
  их перечисления не документированы в открытом Open API, поэтому STools
  показывает число как есть, без текстовой расшифровки.
- **Расшифровка битов `KLHST_WKS_STATUS_MASK`** (`STATUS_MASK_REASONS`,
  20 битов; `status_reasons` хоста, `details.reasons` находок `HOST_CRITICAL`
  и `HOST_WARNING`) составлена на этапе 1 и с консолью KSC не сверена:
  номер бита может быть отнесён не к той причине, а текст — расходиться
  с подписью консоли. Бит вне
  таблицы показывается как «код N». Текст `KLHST_WKS_STATUS_HSDP` —
  продукта, не наш, показывается как есть.
- **Предметные проверки по содержимому политик KES** (защита паролем,
  самозащита, исключения, KSN, отчёты об угрозах — по конкретным именам
  ключей) — вне этапа A: имена настроек KES для Windows/Linux не
  документированы в открытом Open API (описаны только сервер и агент), их
  предстоит узнать по первой живой выгрузке заказчика (этап B, отдельная
  спека). Этап A разбирает содержимое политики только по универсальному
  формату (`KLPRSS_Val`/`KLPRSS_Mnd`/`KLPRSS_ValLck*`), не по смыслу
  конкретных настроек — `walk_settings` (`core/policy_contents.py`) не
  знает, какая секция и ключ что означают в KES, поэтому находки `POLICY_*`
  этапа A говорят только о доле замков, а не о том, что именно замкнуто
  или не замкнуто. Этап 2b добавил словарь KES для Windows и правила оценки по нему (см. «Проверки»).
- **`policy_contents == {}` неотличимо от отсутствия секции в старом
  файле.** Поле разбирается как `dict[str, ...] = Field(default_factory=dict)`
  (`core/export.py`) — и «ключа `policy_contents` не было в JSON вовсе»
  (старый файл), и «ключ был, но со значением `{}`» после загрузки дают один
  и тот же пустой словарь; различить их по факту нечем. Поэтому
  `POLICY_CONTENT_MISSING` (`check_policy_content_missing`,
  `core/checks/policy_contents.py`) молчит на обоих сразу
  (`if not idx.export.policy_contents: return []`) — тем же способом, каким
  `POLICY_NO_LOCKS`/`POLICY_WEAK_LOCKS` молчат на файле без секции: реальное
  «пустая секция без единой политики» на живом KSC ожидается только при
  `skip_policy_contents`, где секции нет вовсе, так что практической разницы
  это не даёт, но как гарантия граница неявная, а не проверенный признак.
- **Уязвимости и обновления ПО, события и инвентарь ПО** — вне блока 1 и
  блока 2 этапа A, следующие блоки дорожной карты
  (`docs/superpowers/specs/2026-09-17-ksc-data-expansion-design.md`).
  Наложение находок KSC на матрицу ATT&CK также остаётся вне блока 1: см.
  «Без слоя ATT&CK» выше.
