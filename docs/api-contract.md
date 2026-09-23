# Контракт API STools

Единственный источник истины для бэкенда и фронтенда. Любое расхождение —
дефект той стороны, которая отступила от этого файла.

Платформенные ручки — `/api/auth/…` и `/api/settings/…`. Ручки модулей —
`/api/<модуль>/…`; у SIEM Rules Analyzer это `/api/siem/…`, у Vulnerability
Management — `/api/vm/…` (см. `docs/vm/api.md`), у модуля Антивирус (KSC) —
`/api/ksc/…` (см. `docs/ksc/api.md`). Ниже описан модуль SIEM.

## Общие правила

- Всё, кроме `POST /api/auth/login` и `GET /api/auth/oidc/{status,start,callback}`,
  требует сессионную cookie. Без неё — `401`.
- Cookie: `stools_session`, `httpOnly`, `SameSite=Strict`, срок 12 часов.
- Секреты при хранении: в базе токен сессии — HMAC-SHA256 значения cookie
  с ключом из `STOOLS_SESSION_SECRET`,
  пароли подключений и секрет клиента OIDC зашифрованы ключом из
  `STOOLS_SESSION_SECRET`. Ответы API от этого не меняются (`password_set`,
  маска `••••`). Смена `STOOLS_SESSION_SECRET` завершает все сессии и
  делает сохранённые секреты нечитаемыми — их нужно ввести заново; до
  этого проверка подключения отвечает `{"ok": false, "message": "секрет
  зашифрован другим ключом — введите его заново"}`.
- Ошибки: `{"detail": "текст на русском"}` с осмысленным HTTP-кодом.
- **Постраничность.** `limit` не больше **1000**, по умолчанию 100. Выгрузка
  заведомо содержит больше находок, чем помещается в одну страницу
  (на эталонной — 1093), поэтому клиент обязан догружать страницами,
  а не рассчитывать получить всё разом. Превышение предела — `422`,
  а не молчаливое усечение: усечение выглядело бы как «данные кончились».
- Сообщения об ошибках сервера не содержат значений из выгрузки. Текст
  исключения драйвера базы включает запрос вместе с параметрами, то есть
  имена хостов и учётные записи, — наружу отдаётся только класс ошибки.
- **Значения находок не отдаются в списках.** Никогда. Только в
  `GET /api/siem/findings/{id}/detail` по явному запросу.
- **Три роли**: `admin`, `analyst`, `auditor`. Чтение (`GET`/`HEAD`/`OPTIONS`)
  в ручках модулей (`/api/siem/…`, `/api/vm/…`) доступно любой роли, запись
  там требует `analyst` или выше. Под `/api/settings/…` роль `admin` нужна
  и на запись, и на чтение `/api/settings/users…`, `/api/settings/audit…`,
  `/api/settings/security`: учётки, журнал и правила сессий модулей не
  касаются. Чтение `/api/settings/llm…` и `/api/settings/attack…` открыто
  любой роли — состояние модели и матрицы показывают страницы самих
  модулей. Исключение — свой профиль и сессия: `POST /api/auth/logout`,
  `POST /api/auth/password`, `PATCH /api/auth/me` доступны любой роли.
  Отказ — `403 {"detail": "нужна роль: <название по-русски>"}`.

## Аутентификация

```
POST /api/auth/login      {login, password} -> 204 + cookie | 401
POST /api/auth/logout     -> 204
```

Свой профиль и пароль — в «Общих настройках» ниже, вместе с остальным
самообслуживанием.

Вход через провайдера (Avanpost FAM или другой OpenID Connect) — три
публичные ручки, без сессионной cookie:

```
GET /api/auth/oidc/status    -> {enabled, display_name}
GET /api/auth/oidc/start     -> 302 на провайдера | 404, если вход выключен
GET /api/auth/oidc/callback  ?code=&state=&error= -> 302 /attack + cookie сессии
                              | 302 /login?error=<код>
```

`start` кладёт `state` ещё и в cookie `stools_oidc_state` (`httpOnly`,
`SameSite=Lax`, путь `/api/auth/oidc`, живёт десять минут) — `callback`
принимает `state` из запроса только при совпадении с этой cookie, иначе
подсунутая ссылка возврата сработала бы в чужом браузере: **вход нужно
заканчивать в том же браузере, в котором он начат**. Адрес авторизации
собран с PKCE (`code_challenge`, метод `S256`) — секрет клиента наружу
не попадает.

Любой отказ на `callback` — редирект на `/login?error=<код>`, а не JSON
(сюда возвращается браузер человека, а не API-клиент), код — один из:

- `oidc_unavailable` — провайдер недоступен или ответил невнятно
  (discovery или JWKS не тот JSON);
- `oidc_state` — нет cookie состояния, она не совпала с `state` из
  запроса, либо состояние не найдено в базе или просрочено (десять минут);
- `oidc_denied` — провайдер вернул `error=` или не вернул `code`;
- `oidc_token` — обмен кода или проверка `id_token` отклонены: подпись,
  издатель, аудитория, срок действия, `nonce` или `code_verifier` не сошлись;
- `oidc_no_role` — ни одна группа из claim'а не сопоставлена роли —
  учётка при этом не заводится;
- `oidc_login_taken` — логин из claim'а уже занят другой (локальной)
  учёткой;
- `blocked` — учётка найдена по `sub`, но заблокирована администратором.

`GET /api/auth/me` (ниже) отдаёт `auth_source`: `local` или `oidc` — по
нему фронтенд решает, показывать ли форму смены пароля.

## Общие настройки

Ручки под `/api/settings/…` — панель администратора; и запись, и чтение
там требуют роль `admin`, кроме состояния модели и матрицы
(см. «Общие правила»). `GET /api/auth/me`, `PATCH /api/auth/me`
и `POST /api/auth/password` — своя учётка, доступны любой роли.

```
GET   /api/auth/me         -> {login, display_name, role, theme, auth_source} | 401
PATCH /api/auth/me         {display_name?, theme?} -> 204
POST  /api/auth/password   {current, new} -> 204 | 400 «текущий пароль неверен»
```

`PATCH /api/auth/me` меняет отображаемое имя и тему оформления — логин
и роль себе не назначают. `theme` — `dark` (по умолчанию) или `light`,
другое значение отвечает `422`. `POST /api/auth/password` требует текущий пароль и обрывает
остальные сессии этого пользователя, кроме той, из которой пришёл запрос.

```
GET    /api/settings/users              -> [{id, login, display_name, role,
                                        is_active, last_login_at, created_at}]
POST   /api/settings/users              {login, display_name?, role, password}
                                    -> 201 UserView
PATCH  /api/settings/users/{id}         {display_name?, role?, is_active?}
                                    -> UserView
DELETE /api/settings/users/{id}         -> 204
POST   /api/settings/users/{id}/password {password} -> 204
```

Нельзя понизить, заблокировать или удалить себя, и нельзя оставить систему
без активного администратора — обе проверки отвечают `409`. Смена пароля
и блокировка обрывают все сессии пользователя.

```
GET /api/settings/security  -> {session_ttl_hours, idle_timeout_minutes,
                              audit_retention_days}
PUT /api/settings/security  {session_ttl_hours?, idle_timeout_minutes?,
                              audit_retention_days?} -> 204
```

Поля `PUT` независимы: опущенное сохраняет прежнее значение, это не полная
замена настройки.

```
GET /api/settings/audit?user_id=&since=&until=&denied_only=&page=&page_size=
    -> {total, items: [{id, at, user_id, login, role, method, path, status,
                         ip, summary}]}
GET /api/settings/audit/export.csv?…   тот же фильтр -> CSV
```

CSV — с BOM и `;`-разделителем для русского Excel; ячейки, начинающиеся
с `= + - @` или таба, экранируются кавычкой: значения в журнале — логины
и пути из чужого ввода, а не только записи сервиса.

```
GET  /api/settings/llm       -> {base_url, model, embed_model, think,
                                  timeout, enabled}
PUT  /api/settings/llm       {base_url, model, embed_model, think, timeout,
                               enabled} -> 204
POST /api/settings/llm/test  {base_url, model, timeout} -> {ok, latency_ms,
                                                             error}
```

Настройки модели общие для платформы, а не только для SIEM — адрес и модель
одни на все ручки, что к ней обращаются (включая перевод техник ATT&CK).
Пустой `base_url` — законное состояние, а не ошибка: без модели работает
всё, кроме обращений к ней. `POST /api/settings/llm/test` проверяет адрес
из запроса, а не сохранённый, — до сохранения, чтобы не узнавать
о неработоспособности через час на фоновой задаче.

```
GET  /api/settings/oidc       -> {enabled, display_name, public_url, issuer_url,
                                   client_id, client_secret, has_secret, scopes,
                                   groups_claim, login_claim, name_claim,
                                   group_roles, redirect_uri}
PUT  /api/settings/oidc       {то же, без has_secret и redirect_uri} -> 204
POST /api/settings/oidc/test  {issuer_url} -> {ok, issuer, endpoints, keys, error}
```

Секрет клиента наружу не отдаётся: в `GET` вместо него — маска `••••`
(пусто, если секрет не задан), рядом `has_secret` — задан ли он на самом
деле. `PUT` с маской или с пустым `client_secret` оставляет сохранённый
секрет — только явное новое значение его меняет. `redirect_uri` в `GET`
собран из `public_url` — его нужно зарегистрировать в FAM как адрес
возврата. Включить вход (`enabled: true`) нельзя, не заполнив
`public_url`, `issuer_url`, `client_id`, `client_secret` и хотя бы одно
сопоставление в `group_roles` — иначе `422` со списком недостающих полей.
`public_url` и `issuer_url` обязаны быть `https://`, кроме `localhost`
и `127.0.0.1`, — иначе `422`: по этим адресам идут `id_token`, код
авторизации и сессионная cookie.

`POST /api/settings/oidc/test` проверяет связь с провайдером по адресу
из запроса (не по сохранённому — до сохранения настроек), без секрета:
скачивает discovery и JWKS мимо кэша. `ok: true` — вместе с адресами
эндпоинтов (`authorization`, `token`, `jwks`, `userinfo`) и числом
подписных ключей; `ok: false` — с текстом ошибки в `error`, `issuer`
и `endpoints` — `null`, `keys` — `0`. `issuer_url` проверяется тем же
правилом https, что и в настройках.

## Снапшоты

```
POST /api/siem/snapshots       multipart file=<zip> -> {job_id, snapshot_id}
GET  /api/siem/snapshots       -> [{id, created_at, filename, rule_count,
                              finding_count, kb_version}]
GET  /api/siem/snapshots/{id}  -> сводка (см. ниже)
```

Повторная загрузка архива с тем же sha256 не создаёт второй снапшот:
возвращается существующий с `"duplicate": true`.

Сводка снапшота:

```json
{
  "id": 1,
  "created_at": "2026-08-24T10:00:00Z",
  "filename": "kb.zip",
  "rule_count": 187,
  "group_count": 44,
  "rules_without_code": 0,
  "unsupported_count": 3,
  "edge_count": 12,
  "scoped_count": 60,
  "finding_count": 1093,
  "findings_by_kind": {"1": 488, "2": 371, "3": 33, "4": 20, "5": 181},
  "findings_by_polarity": {"negation": 140, "assertion": 953},
  "findings_by_object_type": {"correlation": 1059, "filter": 26, "enrichment": 8},
  "objects_with_findings": 86,
  "in_table_count": 488,
  "divergence_count": 488,
  "clone_count": 16,
  "rules_without_msgid": 40,
  "name_scheme_coverage": "187/187",
  "profile_confirmed": false,
  "authors": {"DEMO": 172, "acme": 9, "SOC": 5, "IOC": 1},
  "table_ranking": [
    {"name": "DEMO_User_Authentications", "exists": false, "value_count": 0,
     "dependant_count": 72, "is_empty": true, "is_scoping": false, "risk": 72}
  ],
  "delta": {"finding_count": -15, "rule_count": 0}
}
```

`delta` — разность агрегатов с предыдущим снапшотом, `null` если он первый.

## Задания

```
GET /api/siem/jobs/{id} -> {id, stage, status, progress, error}
```

`stage ∈ {pending, parsing, analyzing, persisting, done}`
`status ∈ {running, done, failed}`
`progress` — целое 0..100.

Фронт опрашивает раз в секунду, пока `status == "running"`.

## Находки

```
GET /api/siem/findings?snapshot_id=1&kind=1&polarity=negation&object_type=correlation
                 &in_table=true&status=open&field=src.ip&q=текст
                 &sort=kind&order=asc&limit=100&offset=0
```

Ответ:

```json
{
  "total": 1093,
  "items": [
    {"id": 42, "kind": 1, "severity": "high", "object_type": "correlation",
     "object_name": "DEMO_HC_002_029_Impacket", "object_uuid": "000ffb49-…",
     "field": "subject.account.name", "polarity": "assertion",
     "in_table": true, "table_name": "DEMO_Hosts, DEMO_TTX_Servers",
     "status": "open", "has_value": true}
  ],
  "facets": {
    "kind": {"1": 488, "2": 371, "3": 33, "4": 20, "5": 181},
    "polarity": {"negation": 140, "assertion": 953},
    "object_type": {"correlation": 1059, "filter": 26, "enrichment": 8},
    "in_table": {"true": 488, "false": 605},
    "status": {"open": 1093, "accepted": 0, "in_progress": 0}
  }
}
```

Фасеты считаются по всему снапшоту с учётом **остальных** активных фильтров,
но не самого фасета — иначе счётчик всегда показывал бы выбранное значение.

```
GET  /api/siem/findings/{id}/detail -> {value, body_excerpt, table_name,
                                   affected_rules: [...]}
POST /api/siem/findings/verdict     {finding_id, status, reason} -> 204
```

`status ∈ {open, accepted, in_progress}`. При `accepted` поле `reason`
обязательно, пустое — `422`.

Вердикт переживает загрузку нового снапшота: он привязан к
`(object_uuid, kind, field, value_hash)`, а не к идентификатору находки.

## Расхождения правило ↔ список

```
GET /api/siem/divergences?snapshot_id=1&limit=100&offset=0
-> {"total": 488, "items": [{"id": 7, "field": "event_src.host",
     "table_name": "DEMO_Hosts, DEMO_TTX_Servers", "hardcoded_in": "DEMO_AC_020_004_…",
     "blast_radius": 64, "has_value": true}]}
```

## Правила

```
GET /api/siem/rules?snapshot_id=1&author=DEMO&category=HC&group=002&q=текст
-> {"total": 187, "items": [{"uuid", "name", "author", "category", "group",
     "rule_id", "origin", "parse_status", "msgid_count", "finding_count",
     "table_reads", "scoped": true}]}
GET /api/siem/rules/{uuid}?snapshot_id=1
-> подробности: msgids с учётом наследования, зависимости, находки, тело
```

Тело правила отдаётся только по этой ручке и содержит чувствительные данные —
фронт показывает его по явному раскрытию, не в списке.

## Клоны и граф

```
GET /api/siem/clones?snapshot_id=1 -> [{rule_a, rule_b, similarity}]
GET /api/siem/clones/compare?snapshot_id=1&rule_a=…&rule_b=…
    -> {a: {uuid, name, title, body|null}, b: {…}, similarity|null,
        signature: {msgids|fields|filters: {common[], only_a[], only_b[]}},
        lines: [{kind: equal|replace|insert|delete, a|null, b|null}], changed_lines}
    Тела выровнены построчно (difflib) для показа бок о бок; similarity null,
    если пара не из таблицы клонов — сравнить можно любые два правила.
GET /api/siem/graph?snapshot_id=1  -> {edges: [{parent, child}], unresolved: {...}}
```

## Профиль инсталляции

```
GET  /api/siem/profile?snapshot_id=1 -> профиль снапшота
PUT  /api/siem/profile               {snapshot_id, tables: {scoping, watched},
                                 builtin_accounts, field_roles, name_scheme}
                                -> 204, снапшот пересчитывается
GET  /api/siem/profile/suggest?snapshot_id=1 -> черновик по данным
```

Изменение профиля пересчитывает производные числа снапшота: какие правила
ограничены списками, какие списки критичны. Разбор архива при этом не
повторяется — берётся сохранённая копия.

`name_scheme` — форма ядра `kbaudit.naming.NameScheme`, а не макета:
`{separator, segments: [role…], total, coverage, group_count,
stats: [{position, role|null, coverage, distinct, numeric_share, examples}],
depth, score}`. Может быть `null`, если схему вывести не удалось.

---

## Разметка ATT&CK

Разметка делается по группам правил, а не по каждому правилу: группа —
единица привязки, и разметка переносится на все её правила. Результат
модели — **предложение, а не факт**: пока человек не подтвердил, оно
показывается отдельным состоянием.

```
GET  /api/siem/attack/coverage?snapshot_id=1
GET  /api/siem/attack/groups?snapshot_id=1&status=suggested|confirmed|unmapped
POST /api/siem/attack/run          {snapshot_id} -> {job_id}
POST /api/siem/attack/confirm      {snapshot_id, group, techniques: [...], reason?}
GET  /api/siem/attack/matrix?snapshot_id=1        матрица с состоянием покрытия
GET  /api/siem/attack/technique/{id}?snapshot_id=1   подробности техники
GET  /api/siem/attack/group?snapshot_id=1&group=X    подробности группы
GET  /api/siem/attack/layer/{snapshot_id}        слой для ATT&CK Navigator
GET  /api/siem/attack/techniques?q=текст          справочник с русскими описаниями
```

Покрытие:

```json
{
  "attack_version": "19.2",
  "group_count": 44,
  "confirmed": 0,
  "suggested": 44,
  "unmapped": 0,
  "techniques_covered": 56,
  "by_tactic": {"execution": 12, "credential-access": 8},
  "model": "qwen3:8b-q4_K_M"
}
```

Группа с разметкой:

```json
{
  "group": "DEMO/HC/002",
  "rule_count": 29,
  "status": "suggested",
  "techniques": [
    {"technique_id": "T1047", "name_ru": "Windows Management Instrumentation",
     "tactics": ["execution"], "confidence": "высокая",
     "evidence": "в описании прямо упоминается использование WMI",
     "source": "llm", "reviewed_by": null, "reviewed_at": null}
  ],
  "candidates": ["T1047", "T1053", "..."]
}
```

`status ∈ {unmapped, suggested, confirmed}`. `source ∈ {llm, manual}`.

`POST /api/siem/attack/confirm` принимает **любые** техники бандла, а не только
предложенные моделью: правка разметки — это не только вычёркивание, модель
могла нужную технику вовсе не увидеть. Тактика при этом отдельно не
задаётся: в ATT&CK она свойство техники и приходит вместе с ней.

Подтехника принимается и **засчитывается покрытием своего родителя** —
в матрице, в слое и в счётчиках. Уточнить разметку до `T1021.001` значит
закрыть `T1021` точнее, а не перестать её закрывать.
`candidates` — что видела модель: без этого разобраться в спорной разметке
через полгода невозможно, потому что кандидаты меняются вместе с бандлом,
моделью и выжимкой.

**Уверенность качественная**: `высокая | средняя | низкая`. Число здесь
создаёт ложную точность — на живом прогоне модель по схеме с типом
`number` выдавала и `0.95`, и `75`.

Подробности техники — описание, подтехники с отметкой, какие из них
закрыты, и группы с их правилами. Незакрытые подтехники внутри закрытой
техники и есть пробел: правило может ловить один способ из семи, а клетка
матрицы уже зелёная.

Правила в обоих ответах приходят с той же маркировкой, что в инвентаре
(`open_finding_count`, `max_severity`, `parse_status`, `scoped`): правило
с открытыми замечаниями должно выглядеть одинаково тревожно, откуда бы
на него ни смотрели. Разметка группы, половина правил которой не
разобрана, стоит меньше — и это видно там же, где принимают решение.

Матрица отдаётся **целиком**, включая незакрытые техники: её смысл в том,
чтобы видеть незакрытое. Матрица из одних лишь закрытых техник —
список достижений, а не карта пробелов. Тактики идут в порядке,
заданном MITRE: это последовательность шагов атаки, и любая другая
сортировка читается неправильно. Подтехники не разворачиваются —
их 475 против 222 родительских; у ячейки сообщается их число.

Слой Navigator отдаётся в формате ATT&CK Navigator 4.5 с обязательными
`legendItems` и категориальной раскраской: подтверждено человеком,
предложено моделью, закрыто частично (правило ограничено списком),
не закрыто.

## Правила: что обнаруживает

`GET /api/siem/rules/{uuid}` отдаёт `description_ru` и `description_en` —
шаблоны сообщений правила из локализации выгрузки. Это единственное место,
где словами написано, что правило обнаруживает; заголовок этого не
заменяет, потому что в него дописывают служебные коды вида
`type_id=JC-MNA-005-004`. На эталонной выгрузке описание есть у 176 правил
из 187.

Описание идёт и в выжимку для разметки ATT&CK, и проходит там ту же
проверку на утечку, что и заголовок: свободный текст опасен одинаково,
откуда бы он ни взялся.

```
POST /api/siem/snapshots/{id}/reparse -> {job_id}
```

Разбор архива заново тем кодом, что есть сейчас. Нужен после обновления
сервиса: кэш разбора записан прежним кодом, и новые сведения в старом
снапшоте иначе не появятся. Архив хранится целиком именно для этого.
При неудаче снапшот сохраняется — он был рабочим до попытки.

## Правила: техника и тактика

`GET /api/siem/rules` дополняется маркировкой, по которой оператор видит,
на какие правила смотреть:

```json
{"open_finding_count": 7, "max_severity": "high"}
```

Считаются **открытые** находки: принятая находка — это уже принятое
решение, а не долг. Иначе маркировка никогда не гаснет и её перестают
замечать.

`GET /api/siem/findings` принимает `object_uuid` — разбор находок по одному
правилу открывается из инвентаря по идентификатору, а не по имени.

`GET /api/siem/rules` и `GET /api/siem/rules/{uuid}` дополняются:

```json
{"attack": {"status": "suggested",
            "techniques": [{"technique_id": "T1047",
                            "name_ru": "Windows Management Instrumentation",
                            "tactics": ["execution"], "confidence": "высокая"}]}}
```

Правило наследует разметку своей группы. В списке показывается
идентификатор и тактика, в подробностях — с названием и обоснованием.

## Обновление матрицы ATT&CK

Ручки под `/api/settings/attack` — матрица общая для всех модулей
(на её идентификаторы ссылаются разметка правил, техники VM и AD),
поэтому менять её вправе администратор. Справочник техник для разметки
остался в модуле: `GET /api/attack/techniques`.

```
GET    /api/settings/attack                 версия, происхождение, полнота перевода
POST   /api/settings/attack/preview         что изменится — ничего не сохраняет
POST   /api/settings/attack                 принять загруженный файлом бандл
POST   /api/settings/attack/download        скачать бандл -> 202 {job_id} |
                                            409 загрузка уже идёт
GET    /api/settings/attack/pending         {version, downloaded_at, url, diff} | null
POST   /api/settings/attack/pending/apply   принять скачанное -> разница |
                                            409 ожидающего бандла нет
DELETE /api/settings/attack/pending         204   отказаться от скачанного
POST   /api/settings/attack/notice/dismiss  204   человек увидел замену поставкой
POST   /api/settings/attack/translate       перевести недостающее -> {job_id, pending}
GET    /api/settings/attack/translation/gaps  чего не хватает в переводе
POST   /api/settings/attack/jobs/{id}/cancel  204 | 404 | 409 уже завершена
```

Задания скачивания и перевода запускает администратор здесь же — он их и
отменяет; ход заданий (`GET /api/attack/jobs`) читают все.

Матрица живёт в базе. Вложенный в образ бандл — база и то, что
**перекрывает загруженный при обновлении софта**: перекрытие срабатывает
на смену вложенного бандла, а не на каждый перезапуск, иначе обычный
`docker compose up` затирал бы загруженную матрицу.

Скачивать можно откуда угодно: адрес задаётся переменной
`STOOLS_ATTACK_BUNDLE_URL`, по умолчанию — репозиторий MITRE. Стенд без
выхода наружу указывает своё зеркало, а не остаётся без обновления.

**Скачанное не применяется само.** Загрузка идёт фоновой задачей
(`kind: download` в `/api/attack/jobs`), а результат ложится ожидающим
бандлом: один на систему, новая загрузка замещает прежний. Человек
смотрит разницу в `GET /pending` и решает — `POST /pending/apply` или
`DELETE /pending`. Разница при применении считается заново: пока бандл
ждал, матрицу могли сменить файлом. `source` принятой матрицы говорит,
откуда она взялась: `builtin` — из поставки, `uploaded` — принесли
файлом, `online` — скачали.

Перекрытие поставкой происходит **всегда, в том числе назад** — если она
принесла матрицу старее принятой. Но не молча: заказчик выбрал ту сам —
файлом или скачиванием, — и подмена без объяснения оставила бы его гадать,
откуда взялась другая версия. Сообщение показывается для любой не-поставки,
`uploaded` и `online` одинаково. `GET /api/settings/attack` возвращает

```json
{"replacement": {"replaced_version": "20.0", "current_version": "19.2",
                 "downgraded": true, "replaced_at": "..."}}
```

Сообщение показывается, пока человек не подтвердит, что увидел
(`POST /api/settings/attack/notice/dismiss`), и снимается само, если он
принял матрицу заново — версию он тогда выбрал сам. `downgraded`
выделяет откат назад отдельно: это не просто смена версии.

Разница показывается до принятия — `preview`, `pending.diff` и ответ
на приём:

```json
{"version": "20.0", "current_version": "19.2",
 "added": ["T9001"], "changed": ["T1047"], "removed": ["T1003"],
 "tactics_added": [], "tactics_removed": [],
 "untranslated": 12, "stale_translations": 34}
```

`changed` считается по отпечатку английского названия и описания.
**Устаревший перевод опаснее отсутствующего**: отсутствие видно сразу,
а устаревший выглядит нормальным русским текстом и просто описывает
не ту технику.

Ошибки приёма файлом: `413` файл больше 120 МБ, `422` файл не разбирается
как бандл ATT&CK или в нём нет ни одной техники. Скачивание с тем же
изъяном роняет задачу: текст ошибки — в её строке.

Обновление матрицы **не трогает разметку**: она привязана к
идентификаторам техник, а не к версии бандла. Разметка, подтверждённая
на другой версии, помечается `version_outdated`, а техника, которой
в новой матрице нет, — `missing`. И то и другое повод пересмотреть,
а не ошибка, и стирать чужую работу из-за обновления нельзя.

Перевод запускает **человек**, а не сервис сам: перевод обращается
наружу, и решение об этом принимает тот, кто знает, можно ли сейчас.
`GET /translation/gaps` отдаёт `{total, items: [{technique_id, name,
reason}]}`, где `reason` — `missing` (перевода нет вовсе) или `stale`
(исходник изменился после перевода). У перевода записано происхождение:
`builtin` — из поставки, `llm` — перевела модель, `manual` — правил
человек. Правка человека переживает обновление софта: перевод из
поставки её не затирает.

## Профиль: роли полей

```
GET  /api/siem/profile/fields?snapshot_id=1   поля правил с их ролью
POST /api/siem/profile/preview                что даст профиль, без сохранения
```

Роль поля берётся прежде всего **из самой выгрузки**: `taxonomy.json`
описывает каждое поле машиночитаемо, и это описание вендора, а не наша
догадка. Правила вывода, от надёжного к менее надёжному:

| признак в таксономии | роль | почему |
|---|---|---|
| `asset_resolution.key` ∈ fqdn, hostname, ipv4, ipv6 | средовое | по полю разрешается актив по имени или адресу |
| `asset_resolution.key` = `entity` | техническое | название источника событий, одинаково всюду |
| `class: tag` | техническое | фиксированный перечень значений — часть языка детекта |
| `type` = IPAddress, MACAddress | средовое | зависит от инсталляции по природе |
| `type` = Number, Bool, Datetime, UUID | техническое | не может быть именем чего-либо в инфраструктуре |
| `auto: true` | техническое | заполняет система, а не событие |
| `type: String` без указаний | не выводится | вопрос к человеку |

Оговорка про `entity` — не мелочь: через неё проходит `event_src.title`
со значением «windows». Без неё одно поле давало 325 ложных находок
из 349 новых.

Там, где форма поля ничего не решает — а это почти весь `String`, —
роль берётся из **документации MP SIEM** («Схема полей событий»):
описание поля словами говорит о его назначении. Таблица составлена
по описаниям и живёт в `kbaudit/analyzers/mp_taxonomy.py`.

Источник роли виден в `source`: `taxonomy` (описание поля в выгрузке),
`documentation` (таблица по документации), `builtin`, `profile`, `none`.
Решение человека перекрывает все выводы.

**Чего документация не решает.** Она описывает назначение поля, но не
отвечает, инсталляционное ли значение: в одно и то же поле правила
кладут и системные имена, и свои. Замерено трижды — `object.name`
несёт `svcctl` (имя канала, суть детекта) рядом с именами объектов
организации; `object.storage.name` несёт `lsarpc` рядом с
`PROD_AVC_FIN20`. Такие поля роли не получают и остаются вопросом
к человеку: их 29 из 123.

**Поле без роли не анализируется вовсе**: захардкоженное в нём значение
проходит мимо молча. На эталонной выгрузке правила используют 123 поля,
а роль встроенно задана двадцати шести — то есть по умолчанию инструмент
смотрит в пятую часть того, что правила трогают. Пять полей, добавленных
в средовые, дают 1093 → 1282 замечания.

`GET /api/siem/profile` дополнительно отдаёт `field_roles_default` — встроенные
наборы. Роль, заданную человеком, видно по `from_profile`: снять можно
только свою.

Предпросмотр нужен потому, что решение стоит дорого: одно поле добавляет
до семидесяти замечаний. Узнавать об этом постфактум, разыскивая источник
сотни новых находок, — плохой порядок.

## Табличные списки

```
GET /api/siem/tables?snapshot_id=1              имя, размер, сколько правил читает
GET /api/siem/tables/values?name=X&snapshot_id=1   состав строками, порциями
GET /api/siem/tables/readers?name=X&snapshot_id=1  правила, читающие список
```

**Содержимое списков — самое чувствительное, что есть в выгрузке**: это
и есть инвентарь внутренней инфраструктуры, адреса, домены и учётные
записи. Поэтому значения не приходят ни в сводку, ни в перечень списков,
а только по явному запросу на конкретный список и порциями (не больше 200
за раз).

Состав отдаётся **строками с колонками**, а не плоским перечнем значений:
в списке рядом лежат идентификатор, имя узла и комментарий, написанный
человеком для себя, и по ним принимают разные решения. Колонки-комментарии
(`description`, `comment`, `note` и русские варианты) называются отдельно
в `comment_columns` — интерфейс показывает их иначе. При сверке с телами
правил и в блоклисте они участвуют наравне с остальными: описания
содержат в том числе внутренние подсети.

Без состава, впрочем, работать нельзя: решить, ограничивает список область
действия правил или обогащает событие, по имени невозможно — перечень
критичных узлов и справочник соответствий называются одинаково безлико.

`GET /api/siem/profile` дополнительно отдаёт `builtin_accounts_default` —
принципалов, встроенных в платформу. Без них пустой список в интерфейсе
читается как «ничего не исключается», хотя исключается многое.

## Настройки

Настройки модели — общие для платформы, а не только для SIEM, и живут
под `/api/settings/llm` (см. «Общие настройки»). Здесь остаётся только своё:
сколько техник класть в промпт при разметке ATT&CK.

```
GET /api/siem/settings  -> {attack: {top_k, attack_version}}
PUT /api/siem/settings  {attack: {top_k}}  -> 204
```

```json
{"attack": {"top_k": 15, "attack_version": "19.2"}}
```
