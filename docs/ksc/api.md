# API модуля Антивирус (Kaspersky Security Center)

Все ручки под `/api/ksc`, требуют сессию платформы. Ошибки — `{"detail": "…"}`.
Дизайн — `docs/superpowers/specs/2026-09-15-ksc-module-design.md`.

## Серверы и снапшоты

```
GET  /servers                          [{id, name, version, snapshots, last_snapshot_id, last_snapshot_at}]
GET  /servers/{id}/overview            {server, snapshot|null, coverage|null, compared_to, accepted_total,
                                        checks: [{code, title, description, total, by_severity, new, fixed, accepted}]}
GET  /snapshots?server_id              [{id, server_id, collected_at, imported_at, source, collector, filename,
                                        hosts, findings, by_severity, new, fixed, previous_id}]
GET  /snapshots/{id}
POST /snapshots/file  multipart file   {job_id} | 202
                                        422 пустой файл | 413 файл больше 200 МБ | 409 идёт задача
POST /snapshots/{id}/reanalyze         {job_id}   — проверки заново по сохранённой выгрузке
DELETE /snapshots/{id}                 204        — удаляет находки, хосты и файл; вердикты остаются
```

`source`: `file | online`. Выгрузка хранится файлом
`STOOLS_DATA_DIR/ksc/<id>.json.gz` (лимит на приём — 200 МБ), поэтому
`reanalyze` и `policies` (ниже) работают без повторного сбора.

## Хосты

```
GET  /snapshots/{id}/hosts             group, product, agent(none|silent|alive), protection(none|off|on),
                                       bases(fresh|old|unknown), in_ad(both|ksc_only),
                                       status(ok|warning|critical), q, limit≤1000, offset
                                       → {total, items, facets|null}
GET  /snapshots/{id}/hosts/{host_id}   + findings[] (каждая: key, check, check_title, severity, status, details)
```

`agent`, `bases` — фасады над `agent_silent_days` и `bases_old_days` из
настроек: считаются на лету от `snapshot.collected_at`, в базе не хранятся.
`in_ad` — `both`, если хост сопоставлен с включённым компьютером домена по
последнему снапшоту модуля AD на момент анализа, `ksc_only` — если нет,
`null` — снапшота AD не было вовсе.

## Находки и вердикты

```
GET  /snapshots/{id}/findings          check, severity, status(new|persisting|accepted|fixed),
                                       allowlisted, q, limit≤1000, offset
                                       → {total, items, facets|null, compared_to, check_titles}
GET  /snapshots/{id}/findings/{key}    + description, history[], verdict|null
PUT  /verdicts/{key}  {server_id, reason}   204   принять как норму
DELETE /verdicts/{key}?server_id=      204
```

Статус: `new` — нет в предыдущем снапшоте сервера; `persisting` — была;
`accepted` — есть вердикт; `fixed` — была в предыдущем, нет в этом (только
при `status=fixed`, строки берутся из предыдущего снапшота). Находки про
хост несут `host`, находки про группу, политику, задачу или лицензию —
только `target` (путь группы, имя политики/задачи/ключа), `host` пуст.

## Политики и задачи группы

```
GET  /snapshots/{id}/policies          {groups: [{id, name, path, level, hosts,
                                        policies: [{id, name, product, active, inherited,
                                                    accept_parent, modified_at, modified_group}],
                                        tasks: [{id, name, type, product, inherited, schedule}],
                                        findings: [{key, check, check_title, severity}]}]}
```

Дерево строится из сохранённого файла выгрузки, а не из базы (`404`, если
файл снапшота удалён вручную с диска). Корнями считаются и группы без
родителя, и группы, чей `parentId` отсутствует в выгрузке (частичный
экспорт) — иначе их поддерево пропадает из ответа. `findings` группы — те
находки `POLICY_NONE`, `POLICY_INHERIT_BROKEN`, `TASK_NO_UPDATE`,
`TASK_NO_SCAN`, чей `target` совпадает с путём группы.

## Сбор

```
GET  /collector.ps1                    PowerShell-сборщик (attachment)
GET  /connections                      [{id, title, host, port, username, password_set,
                                        verify_tls, internal, domain, server_id}]
POST /connections  PUT /{id}  DELETE /{id}      пустой пароль в PUT — оставить прежний
POST /connections/{id}/test            {ok, message, server_name, version}
POST /connections/{id}/collect         {job_id} | 400 нет логина или пароля | 409 идёт задача
```

`internal` — внутренняя учётная запись KSC; `false` требует `domain`
(доменная учётная запись). Порт по умолчанию — 13299 (Open API KSC).

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
помечаются `allowlisted`).

`kind` задач: `import_file | collect | reanalyze`.

## Проверки

18 проверок, коды латиницей:

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
NO_FULLSCAN             Давно не было полного поиска
PRODUCT_OUTDATED        Устаревшая версия продукта или агента
POLICY_NONE             Нет действующей политики
POLICY_INHERIT_BROKEN   Наследование политики отключено
TASK_NO_UPDATE          Нет задачи обновления
TASK_NO_SCAN            Нет задачи поиска
LICENSE                 Лицензия
```

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
  проверка ещё не написана.
- **`ip_from_long`** (`core/export.py`) разворачивает `KLHST_WKS_IP_LONG`
  как little-endian. На синтетике и тестовых выгрузках это даёт верный
  адрес, но порядок байт в этом поле у живого KSC 15.1 не проверялся —
  это будет сделано на первой выгрузке заказчика; при расхождении хосты
  получат неверный `ip` (сама находка `COVER_*` от этого не пострадает,
  сверка идёт по `host_id`, а не по IP).
