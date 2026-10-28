# API модуля Vulnerability Management

Все ручки под `/api/vm`, требуют сессию платформы (cookie `stools_session`).
Ошибки — `{"detail": "текст по-русски"}`. Дизайн — `docs/superpowers/specs/2026-09-09-vm-module-design.md`.

## Уязвимости

```
GET /vulns     q, host, cve, criticality, zone, os, level, exploits, msf,
               kev, cvss_source, host_id, status, assignee, overdue, risk_expiring,
               sort, limit≤1000 (200), offset
               → {total|null, items[], facets|null}  total и фасеты только
               при offset=0: следующие страницы их не пересчитывают
GET /vulns/{host_id}/{cve_id}   карточка расчёта: host, cve (с kev, kev_added,
                                kev_ransomware, kev_due), risk{score, raw, level,
                                likelihood, severity, value и их части
                                likelihood_parts, severity_parts, value_parts:
                                {value, source, substituted}}, refs_loaded_at
                                (все справочники, незагруженные — null)
GET /hosts/{host_id}            хост и его пары (до 500, по риску)
GET /export    format=csv|xlsx (csv), те же фильтры и `sort`, что у списка,
               и так же по умолчанию — только открытые пары (`status=all` —
               все) → файл; CSV потоком, XLSX — до 100 000 строк;
               колонка KEV — «да» или пусто; последние — Статус,
               Исполнитель, Срок
GET /overview  счётчики, distribution, findings, top_cves, top_hosts, data{…}
```

`sort`: `risk_desc` (по умолчанию; при равном балле — по сырому риску),
`risk_asc`, `cvss_desc`, `epss_desc`, `exploits_desc`, `host_asc`, `cve_asc`.
При равных значениях — по паре (`host_id`, `cve_id`): порядок один и тот же в
каждом запросе, страницы по offset не повторяют и не теряют пар.
`level`: `low | medium | high | critical` по порогам `weights.levels` настроек (по умолчанию 0–14, 15–34, 35–59, 60–100; риск = 100 × вероятность × тяжесть × ценность, спека 2026-10-21 §9); `kev=true|false` — CVE в каталоге CISA KEV (фасет `kev`, в обзоре `kev_pairs`).

Многозначные фасеты — `level`, `criticality`, `zone`, `cvss_source`, `os`,
`assignee`, `status`: несколько значений повторением ключа
(`?level=high&level=critical&os=Windows%20Server%202019%2C%20x64`), значение
по запятой не делится; внутри фасета — «или», между фасетами — «и».
Пустое значение («не задано») у `criticality`, `zone`, `os` — маркер `-`
(`?zone=-&zone=DMZ` — без зоны или DMZ); `all` — фильтр не задан. Через
запятую принимается только `status` (старая форма `status=new,in_work`).
Общие правила формата и выгрузки — `docs/api-contract.md`.

Выгрузка `/export` — любой роли, CSV — UTF-8 с BOM, `;`, CRLF; XLSX — не
больше 100 000 строк и строка «Выгружены первые 100 000 строк — сузьте
фильтры». Имя файла — `stools-vm-vulns-<ГГГГММДД-ЧЧММ>.<csv|xlsx>`.

### Статусы пар

У пары хост × CVE — общий статус находки платформы (`/api/findings/*`,
`module = "vm"`, `scope_id = 0`), ключ — `hostname|ip|cve` из `vm_host` как
есть (без приведения регистра), до 400 символов. Хост с новым IP — новые
пары: статус не переносится. То же при смене регистра имени хоста в
MaxPatrol (`SRV01` → `srv01`): ключ другой, решения по прежнему ключу
остаются без пары (после импорта — `resolved` или `present = false`), а пары
под новым именем — «новые». Символ `|` в имени хоста допустим: ключ
разбирается справа.

- Список: `status` — коды повторением ключа (или через запятую) или `all`,
  по умолчанию открытые (`new, in_work, fixed, reopened`; с `risk_expiring` —
  принятые); `assignee` — `me | none | <логин>`, несколько — повторением
  ключа; `overdue`, `risk_expiring` — `true`.
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
  `filter` (те же параметры, что у `/vulns`, без `sort`, `limit`, `offset`;
  многозначные — JSON-списком, «не задано» — пустой строкой `""` или `-`)
  — 202 `{job_id}`: задача `vm_job` `kind = bulk_status` меняет пары
  кусками по 1000 с общим `bulk_id`, прогресс и отмена — `/jobs/{id}`;
  сделанное до отмены остаётся. Ошибка фильтра или смены, не зависящая от
  пары (нет обоснования к статусу, роль, срок риска, исполнителя нет в
  справочнике), — 422 до запуска задачи; зависящая от пары (срок риска без
  статуса у непринятой пары) останавливает задачу на первой такой паре,
  ключ — в `error`. Срок принятого риска продлевается сменой без `status`
  (`{"risk_until": …}`) по фильтру `status=risk_accepted`.
- Массовая смена и импорт не идут одновременно: смена во время импорта или
  пересчёта — 409 «идёт импорт VM — повторите после него», импорт во время
  смены — 409 «идёт массовая смена статусов». Импорт, записанный всё же
  посреди смены, останавливает её (`failed`). У остановленной или упавшей
  задачи `message` — «применено N из M до остановки»; в `message` задачи и
  в журнале действий — `bulk_id` и фильтр (до 300 символов; журнал хранит
  200 символов описания целиком).
- `/overview`: `pairs`, `distribution`, `above_threshold` и слой ATT&CK
  считают пары с учитываемым статусом (настройка `counted`, по умолчанию без
  «Принят риск», «Ложное срабатывание», «Устранена»); `pairs_all` — все
  пары; `findings` — сводка статусов (`by_status`, `overdue`,
  `risk_expiring`, `unassigned`) по парам текущих данных — как в списке, куда
  ведут плитки. Топы CVE и хостов — по всем парам.

## Данные

```
POST /import/vm                 {job_id} | 400 не настроено | 409 уже идёт
                                или идёт массовая смена статусов
POST /import/file  multipart file=<csv|json>   {job_id} | 409
GET  /import                    {last: vm_import|null, active: job|null}
GET  /refs                      [{name, title, url, loaded_at, source, records, detail, stale, active_job_id}]
POST /refs/{name}/download      {years?} (nvd)  → {job_id} | 409
POST /refs/{name}/upload        multipart files=…  → {job_id}
POST /refs/bundle/upload        multipart file=<zip>  → 202 {job_id} | 409 идёт
                                задача данных VM, массовая смена или загрузка
                                справочника | 422 в архиве нет известных
                                справочников
POST /recalculate               {job_id} | 409
```

`name`: `epss | nvd | exploitdb | msf | attack` (CVE → ATT&CK, CTID) `| kev`
(CISA KEV, `.json` или `.csv`).

Архив справочников (спека 2026-10-21 §4, §8) собирают скрипты
`frontend/public/vm/download-references.{ps1,sh}`; справочник узнаётся по
имени файла, незнакомые файлы пропускаются. Одна задача `ref_bundle`, стадии
`extracting → loading → enriching → scoring → done`; пересборка витрины CVE и
пересчёт риска — один раз в конце. Отказ файла останавливает задачу с его
именем, загруженное до него остаётся и пересчитывается.

## Настройки

```
GET  /settings   {connection{host, verify_tls, os_exclude, pdql_extra,
                  limit, api_token_set, configured},
                  weights, threshold, attack_min_risk,
                  defaults{weights, threshold, attack_min_risk}}
PUT  /settings   {connection{…, api_token}, weights, threshold,
                  attack_min_risk}
                 пустой api_token — оставить прежний; смена host/verify_tls без
                 нового токена — 422. Токен — персональный API-токен MaxPatrol
                 (pat_…), уходит как Bearer; логин, пароль и client secret не нужны
POST /settings/test-vm   {ok, message}   PDQL limit(1) под токеном
GET  /zones      [{name, internet_access, confidential_data, marked, hosts}]
PUT  /zones      [{name, internet_access, confidential_data}] → 204
```

`weights` (спека 2026-10-21 §9; риск = round(100 × L × S × V)):
`prior_epss` (EPSS, если не измерен), `p_exdb{тип эксплойта: 0..1}`,
`p_msf{ранг модуля: 0..1}` — для L; `cvss_missing`, `reach{network_internet,
network_internal, adjacent, local}`, `reach_unknown` — для S;
`value{criticality{…: 0..1}, conf_bonus, inet_bonus}` — для V;
`levels{medium, high, critical}` — целые пороги уровней (low — ниже medium).
Веса старой схемы (множители первой итерации), сохранённые до обновления, не
переводятся: действуют умолчания новой формулы, пока веса не сохранят заново.

## Образы контейнеров

Образы приходят из Harbor синхронизацией (раздел «Harbor» ниже; установка и
ограничения — `docs/vm/harbor.md`); эти ручки только читают, уровень — `read`.
Дизайн — `docs/superpowers/specs/2026-10-28-harbor-images-design.md`.

```
GET /images                       q, project, scan_status, level, trivy,
                                  sort, limit≤1000 (200), offset
                                  → {total|null, items[], facets|null}
GET /images/{id}                  карточка образа + last_sync_at | 404
GET /images/{id}/vulns            q, severity, level, fixed, sort,
                                  limit≤1000 (200), offset
                                  → {total|null, items[], facets|null} | 404
GET /images/{id}/vulns/{cve_id}   package (обязателен), installed_version ("")
                                  → {image, vuln, factors|null, nvd_url|null} | 404
GET /images/export                format=csv|xlsx (csv), те же фильтры и `sort`,
                                  что у списка образов, и image_id → файл
```

`total` и фасеты — только при `offset=0`, как у `/vulns`. Фасеты-фильтры
(`project`, `scan_status`, `level`, `trivy` у образов; `severity`, `level` у
находок) — повторением ключа: внутри фасета «или», между фасетами «и».
Неизвестная `sort` — 422 «неизвестная сортировка».

Образ — одна строка на `(project, repository, digest)`, `id` стабилен между
синхронизациями. Элемент списка и карточка: `id, project, repository, name`
(`project/repository`), `platform` (платформы мультиархитектурного индекса
через «, » или `null`), `tags[]`, `digest_short` (12 знаков), `digest`, `size`,
`pushed_at`, `scan_status`, `scanned_at`, `scanner`, `trivy{critical, high,
medium, low, unknown, total}`, `risk_max`, `level`, `cves_scored`, `sync_error`
(почему образ не обновлён в последней синхронизации). Карточка добавляет
`last_sync_at`.

- **Образы.** `q` — подстрока по `project/repository` и по тегам; `project` —
  имена проектов; `scan_status` — `success | pending | running | error | none`;
  `level` — `low | medium | high | critical` по `risk_max` с порогами
  `weights.levels` настроек VM и `none` — у образа нет риска; `trivy` —
  `critical | high`: есть хотя бы одна находка такой серьёзности. `sort`:
  `risk_desc` (по умолчанию; образы без риска в конце), `name`, `pushed_desc`,
  `trivy_desc` (по числу Critical, затем High и далее). Фасеты: `project`,
  `scan_status`, `level` (с ключом `none`).
- **Находки образа.** `q` — подстрока по идентификатору и пакету; `severity` —
  оценка Trivy: `critical | high | medium | low | unknown`; `level` — по
  `risk`, `none` — риска нет; `fixed=yes|no` — есть ли исправленная версия
  (другое значение — 422). `sort`: `risk_desc` (по умолчанию), `severity_desc`,
  `package`, `cve`; при равных значениях — по ключу находки, страницы по offset
  не повторяют и не теряют строк. Элемент: `cve_id` (идентификатор из отчёта
  как есть), `package`, `installed_version`, `fixed_version`, `trivy_severity`,
  `trivy_cvss`, `risk`, `level`, `epss`, `kev` (`null`, если идентификатора нет
  в витрине CVE), `cvss`, `cvss_source`, `description`, `link`, `is_cve`.
  Фасеты: `severity`, `level`, `fixed{yes, no}`.
- **Расчёт риска находки.** Находка — тройка `(cve_id, package,
  installed_version)`: один CVE бывает в нескольких пакетах, поэтому `package`
  в запросе обязателен. `factors` — те же L, S, V и их части, что в карточке
  пары хоста, но с условиями образа: интернета нет, критичности и
  конфиденциальности нет, ценность у всех образов одна. Для идентификатора не
  из CVE (`GHSA-…`, `TEMP-…`, `GO-…`) и для CVE, которого нет в витрине,
  `factors` — `null`, у не-CVE `nvd_url` тоже `null`; остаётся оценка Trivy.
  Нет такой находки или образа — 404.
- **Выгрузка** `/images/export` — любой роли, пишется в журнал действий, как
  `/export` уязвимостей. CSV — UTF-8 с BOM, `;`, CRLF; XLSX — не больше 100 000
  строк. Строка — образ × находка (образ без находок — одна строка с пустыми
  колонками находки). Колонки: Образ, Платформа, Теги, CVE, Пакет, Установлена,
  Исправлена, Trivy, CVSS Trivy, Риск, Уровень, EPSS, KEV («да» или пусто),
  Статус скана, Дата скана. `image_id` ограничивает выгрузку одним образом.
  Формат, не равный `csv` и `xlsx`, — 422. Имя файла —
  `stools-vm-images-<ГГГГММДД-ЧЧММ>.<csv|xlsx>`.

## Harbor

Подключение к реестру Harbor с отчётами Trivy: одно на установку, как
подключение к MaxPatrol (хранится в `app_setting['vm_harbor']`).

```
GET    /harbor            read    {url, robot_name, robot_secret_set, verify_tls,
                                  projects[], tags_per_repo, configured,
                                  last_sync|null, schedule|null}
PUT    /harbor            admin   те же поля + robot_secret → тот же вид | 422
POST   /harbor/test       admin   {ok, message} | 400 не настроено
POST   /harbor/sync       write   202 {job_id} | 400 не настроено | 409
GET    /harbor/schedule   read    ScheduleView | null
PUT    /harbor/schedule   admin   {interval_hours 1..720, window_from?, window_to?,
                                  enabled} → ScheduleView | 422
DELETE /harbor/schedule   admin   204
```

- **Поля.** `url` — `http://` или `https://`, до 512 знаков, без завершающего
  «/» (иначе 422); `robot_name` — имя робота вида `robot$<имя>`, до 128 знаков;
  `robot_secret` — секрет робота, печатная латиница (иначе 422); `verify_tls` —
  по умолчанию `true`; `projects` — имена проектов (строчные латинские буквы,
  цифры, «.», «_», «-»), пусто — все проекты, доступные роботу;
  `tags_per_repo` — 1..100, по умолчанию 10. `configured` — заданы адрес, имя
  и секрет. Секрет хранится зашифрованным, наружу выходит только
  `robot_secret_set`.
- **Секрет и смена адреса.** Пустой `robot_secret` в `PUT` — оставить прежний.
  Смена `url`, `robot_name` или `verify_tls` без нового секрета — 422 «при смене
  адреса секрет робота нужно ввести заново»: прежний секрет на другой адрес не
  уходит. В журнале действий — список изменённых полей без значений.
- **`last_sync`** — итог последней записанной синхронизации: `finished_at,
  images, cves` (пар), `repositories, skipped_unscanned` (образы без готового
  скана), `errors[]` (проекты и репозитории `проект/репозиторий`, не
  прочитанные в этот раз).
- **`/test`** проверяет сохранённое подключение, а не поля формы: `GET
  /api/v2.0/systeminfo`, затем чтение списка проектов под роботом. Ответ — 200:
  `{ok: true, message: "Harbor <версия>"}` или `{ok: false, message: <класс
  отказа>}` — `NO_LINK`, `TLS_FAILED`, `LOGIN_REJECTED`, `NO_RIGHTS`,
  `server_error(<код>)`. Адрес и текст ответа Harbor в сообщение не попадают.
  Частота проверок ограничена на пользователя, как у остальных подключений VM.
- **`/sync`** — задача `harbor_sync`, прогресс и отмена через `/jobs/{id}`
  (стадии — в разделе «Задачи»). 409 «идёт задача #N, синхронизация после неё»,
  если идёт импорт VM, пересчёт, загрузка архива справочников или другая
  синхронизация Harbor: все они пересобирают витрину CVE и риск. Расписание в
  таком случае пропускает запуск. Не настроено — 400. Синхронизация не трогает
  пары хостов, импорт VM не трогает образы.
- **Расписание** — синглтон (`module = "vm"`, `kind = "harbor"`, `target_id =
  0`); формат общий для платформы: окно `HH:MM` в поясе `STOOLS_TZ`, оба
  поля пустые — без окна. Без настроенного подключения расписание
  выключается с пометкой в `last`.
- **Свежесть.** Строка `harbor` в сводке «Данные» (`/api/settings/data-status`):
  «Образы контейнеров (Harbor)», устаревает через 7 дней.

## Задачи

```
GET  /jobs?limit        идущие сверху, затем последние
GET  /jobs/{id}         {id, kind, stage, status, progress, processed, total,
                         message, error, cancel_requested, started_at,
                         finished_at, started_by}
POST /jobs/{id}/cancel  204 | 409 уже завершена
```

`kind`: `import_vm | import_file | ref_epss | ref_nvd | ref_exploitdb | ref_msf |
ref_attack | ref_kev | ref_bundle | recalculate | bulk_status | harbor_sync`. После обновления
формулы старт API сам ставит `recalculate` (`started_by` — «после обновления»),
пока полный пересчёт не запишет версию формулы в `app_setting['vm_formula_version']`.
Стадии импорта: `fetching → parsing → writing → enriching → scoring → done`;
отмена принимается до `writing`. У импорта из VM после `scoring` — `groups`:
локальные группы Windows и Linux вторым и третьим PDQL, отдельным снимком;
его сбой импорт не роняет. Сообщение стадии — итог по семействам: «локальные
группы: Windows — строк N, хостов M; Linux не получены (причина) — прежний
снимок от ДД.ММ ЧЧ:ММ UTC»; с лимитом подключения — пометка «снимок неполный».

Синхронизация Harbor (`harbor_sync`): стадии `listing → reports → writing →
enriching → scoring → done`. `listing` — проекты, репозитории и артефакты
(прогресс — число репозиториев); `reports` — отчёты Trivy у образов с новым
сканом; `writing` — запись образов и их находок; `enriching` — витрина CVE по
новым идентификаторам; `scoring` — риск находок образов. Отказ входа или списка
проектов останавливает задачу, ничего не записав; сбой одного проекта,
репозитория или отчёта задачу не роняет: образы остаются прежними с пометкой
`sync_error`, а имя попадает в `errors` итога.
