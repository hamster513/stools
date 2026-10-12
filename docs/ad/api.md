# API модуля Active Directory

Все ручки под `/api/ad`, требуют сессию платформы. Ошибки — `{"detail": "…"}`.

## Домены и снапшоты

```
GET  /domains                          [{id, sid, dns_root, netbios, dn, snapshots, last_snapshot_id, last_snapshot_at}]
GET  /domains/{id}/overview            {domain, snapshot|null, compared_to,
                                        counted: {total, by_severity, statuses[]},
                                        summary: {by_status, overdue, risk_expiring, unassigned},
                                        checks: [{code, title, description, total, all, open, new, resolved,
                                                  by_severity, unchecked}]}
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
GET  /snapshots?domain_id              [{id, domain_id, collected_at, imported_at, source, collector, filename,
                                        objects, findings, by_severity, new, fixed, previous_id}]
GET  /snapshots/{id}
POST /snapshots/file  multipart file   {job_id} | 409 идёт задача
POST /snapshots/{id}/reanalyze         {job_id}   — проверки заново по сохранённой выгрузке
DELETE /snapshots/{id}                 204        — удаляет находки и файл; статусы находок остаются
```

Обзор — по последнему снапшоту. `counted` и у проверки `total`, `by_severity` —
находки со статусами, которые велено учитывать (`counted.statuses`, настройка
платформы); список с тем же числом — `findings?severity=…&status=<statuses через запятую>`.
У проверки `all` — все её находки, `open` — открытые, `new` — появились в
этом снапшоте, `resolved` — пропали с предыдущего. `summary` — счётчики
статусов домена (вместе с отсутствующими в последнем снапшоте).

## Данные центра сертификации

Файл `stools-ad-ca/1` от PowerShell-сборщика (JSON, можно gzip; поля `format`,
`collected_at`, `collector`, `domain: {sid, dns_root}`, `sections` и записи разделов:
`cas` — `name, host, os_build, edit_flags, interface_flags, disable_extension_list,
security` (дескриптор прав ЦС, base64), `dcs` — `host, strong_binding,
mapping_methods`, `web` — `url, status, auth`; у каждой записи `error` — что
сборщик не прочитал) загружается той же ручкой `POST /snapshots/file`: формат
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
                                        sections, cas, dcs, web}]   — cas/dcs/web: число записей
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
                                       status (коды через запятую или all; по умолчанию — открытые:
                                         new, in_work, fixed, reopened; с risk_expiring — risk_accepted),
                                       delta (new|same|gone), assignee (логин | me | none),
                                       overdue=true, risk_expiring=true, limit≤1000, offset
                                       → {total, items, facets|null, compared_to, check_titles,
                                          is_latest, statuses_as_of: "today"}
GET  /snapshots/{id}/findings/{key}    элемент списка + description, history[{snapshot_id, collected_at}]
```

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
