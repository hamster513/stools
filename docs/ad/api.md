# API модуля Active Directory

Все ручки под `/api/ad`, требуют сессию платформы. Ошибки — `{"detail": "…"}`.
Дизайн — `docs/superpowers/specs/2026-09-09-ad-module-design.md`.

## Домены и снапшоты

```
GET  /domains                          [{id, sid, dns_root, netbios, dn, snapshots, last_snapshot_id, last_snapshot_at}]
GET  /domains/{id}/overview            {domain, snapshot|null, compared_to, accepted_total,
                                        checks: [{code, title, description, total, by_severity, new, fixed, accepted}]}
GET  /snapshots?domain_id              [{id, domain_id, collected_at, imported_at, source, collector, filename,
                                        objects, findings, by_severity, new, fixed, previous_id}]
GET  /snapshots/{id}
POST /snapshots/file  multipart file   {job_id} | 409 идёт задача
POST /snapshots/{id}/reanalyze         {job_id}   — проверки заново по сохранённой выгрузке
DELETE /snapshots/{id}                 204        — удаляет находки и файл; вердикты остаются
```

## Находки и вердикты

```
GET  /snapshots/{id}/findings          check, severity, status(new|persisting|accepted|fixed),
                                       allowlisted, q, limit≤1000, offset
                                       → {total, items, facets|null, compared_to, check_titles}
GET  /snapshots/{id}/findings/{key}    + description, history[], verdict|null
PUT  /verdicts/{key}  {domain_id, reason}   204   принять как норму
DELETE /verdicts/{key}?domain_id=      204
```

Статус: `new` — нет в предыдущем снапшоте домена; `persisting` — была;
`accepted` — есть вердикт; `fixed` — была в предыдущем, нет в этом (только
при `status=fixed`, строки берутся из предыдущего снапшота).

## Сбор

```
GET  /collector.ps1                    PowerShell-сборщик (attachment)
GET  /connections                      [{id, title, host, port, use_ssl, verify_tls, username,
                                        password_set, base_dn, collect_sysvol, page_size,
                                        pause_ms, domain_id}]
POST /connections  PUT /{id}  DELETE /{id}      пустой пароль в PUT — оставить прежний;
                                        page_size 50–1000 (500), pause_ms 0–10000 (500) —
                                        страница LDAP и пауза между запросами к контроллеру
POST /connections/{id}/test            {ok, message}
POST /connections/{id}/collect         {job_id} | 400 нет пароля | 409 идёт задача
```

## Настройки и задачи

```
GET  /settings   {config: AdConfig, defaults, checks[]}
PUT  /settings   AdConfig
GET  /jobs  GET /jobs/{id}  POST /jobs/{id}/cancel
```

`kind` задач: `import_file | collect | reanalyze`.

## ATT&CK

Каждая проверка объявляет техники, которые открывает её находка
(`CheckSpec.techniques` в `api/modules/ad/core/checks/`). Из них строится
слой экспозиции `ad` платформенной матрицы: `docs/attack/api.md`.
