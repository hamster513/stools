# Установка STools на сервер

Готовые образы из реестра, данные в каталогах сервера, TLS на nginx.
Файлы: `ops/docker-compose.prod.yml`, `ops/.env.example`,
`ops/nginx-stools.conf.example`.

## Что нужно

- Linux x86_64, Docker Engine с `docker compose` v2.
- Доступ к реестру с образами `stools-api`, `stools-web` и `stools-document-converter` (для приватного
  реестра — `docker login`) и к образу `postgres:16-alpine`.
- nginx на сервере с сертификатом для имени STools.
- Память: не меньше суммы лимитов контейнеров плюс запас для системы. По
  умолчанию API 6 ГБ, база 2 ГБ, web 256 МБ, конвертер 1 ГБ — сервер от 12 ГБ. Лимиты API и базы
  задаются в `.env` (раздел 2).

Конвертер документов запускается без сети. API и конвертер обмениваются временными заданиями через именованный том `document-queue`; исходники остаются в архиве API. При обновлении существующей установки используйте новый `docker-compose.prod.yml`, чтобы сервис и общий том подключились автоматически.

## 1. Каталоги данных

База и загруженные выгрузки лежат в `/data/stools` (другой путь —
`STOOLS_DATA_ROOT` в `.env`). Владельцы — пользователи внутри образов:
Postgres (uid 70) и API (uid 10001).

```bash
sudo install -d -o 70 -g 70 -m 700 /data/stools/db
sudo install -d -o 10001 -g 10001 -m 750 /data/stools/archives
```

## 2. Файлы и секреты

Нужен каталог `ops/` из репозитория той же версии, что и образы (клон на
теге или копия трёх файлов выше). В нём создаётся `.env`, права 600:

```bash
cp .env.example .env && chmod 600 .env
```

Заполнить в `.env`:

- `POSTGRES_PASSWORD` — длинная случайная строка;
- `STOOLS_SESSION_SECRET` — `openssl rand -hex 32`. Им шифруются
  сохранённые пароли подключений: храните его отдельно от резервных копий,
  без него секреты из копии не расшифровать. Менять — только по README,
  раздел «Ротация STOOLS_SESSION_SECRET»;
- `STOOLS_VERSION` — тег образов, например `ffa11c4`;
- `STOOLS_REGISTRY` — если образы не в `hamster5133`;
- `STOOLS_PORT` — порт на 127.0.0.1, куда ходит nginx (по умолчанию 8080);
- `STOOLS_API_MEM`, `STOOLS_API_CPUS`, `STOOLS_DB_MEM`, `STOOLS_DB_CPUS` —
  лимиты API и базы (по умолчанию `6g`/`4` и `2g`/`2`). Памяти API нужно
  по крупнейшему домену AD, ориентир — 2–3 ГБ на миллион находок плюс
  запас. Не хватит — ядро убивает рабочий процесс API, сбор обрывается, а
  интерфейс отвечает 502, пока процесс не поднимется. После правки —
  `docker compose -f docker-compose.prod.yml up -d`.

- `STOOLS_CA_BUNDLE` — файл сертификатов сервера, если он не
  `/etc/ssl/certs/ca-certificates.crt` (Debian/Ubuntu). На RHEL, CentOS,
  Astra — `/etc/pki/tls/certs/ca-bundle.crt`.
- `STOOLS_TZ` — часовой пояс окон расписаний, имя IANA, например `Europe/Moscow` (по умолчанию `UTC`).

`STOOLS_SITE_ADDRESS`, `STOOLS_TLS` и `STOOLS_SESSION_COOKIE_SECURE` на
сервере не используются: прод-compose задаёт их сам.

### Корпоративный УЦ

STools сам ходит по HTTPS и LDAPS к провайдеру OIDC, KSC, MaxPatrol VM и
контроллерам домена. Если их сертификаты выпущены корпоративным УЦ, ему
должен доверять сам сервер: API берёт общий файл сертификатов сервера
(`STOOLS_CA_BUNDLE`). Проверка до запуска STools:

```bash
curl -sS -o /dev/null -w '%{http_code}\n' --cacert /etc/ssl/certs/ca-certificates.crt https://<провайдер>/.well-known/openid-configuration
```

Если curl ругается на сертификат — корня нет в общем файле. На
Debian/Ubuntu он добавляется так:

```bash
sudo cp <корень>.pem /usr/local/share/ca-certificates/corp-root.crt && sudo update-ca-certificates
```

Подключать файл с одним корпоративным корнем нельзя: список доверенных УЦ
заменяется целиком, и перестанут проверяться публичные сайты (ленты VM,
бандл ATT&CK).

## 3. Запуск

```bash
cd ops
docker compose -f docker-compose.prod.yml pull
docker compose -f docker-compose.prod.yml up -d
docker compose -f docker-compose.prod.yml ps
```

API на старте применяет миграции базы. Все три сервиса должны прийти в
состояние `healthy`.

Сканер сети модуля Assets пингует без root: compose задаёт контейнеру API `sysctls: net.ipv4.ping_group_range`; если среда запрещает этот sysctl, сканер работает в режиме «только порты» (отметка в задаче скана).

## 4. Первый администратор

```bash
docker compose -f docker-compose.prod.yml exec api python -m api.cli create-user <логин> --group Администраторы
```

Пароль спрашивается дважды и никуда не пишется. Группы, роли и уровни доступа —
`docs/platform/access.md`. Дальше — вход через
интерфейс; вход через Avanpost FAM настраивается в `/settings` (README,
«Вход через Avanpost FAM»).

## 5. nginx

Взять `ops/nginx-stools.conf.example`, подставить имя сайта, сертификат и
порт, проверить и перечитать:

```bash
sudo nginx -t && sudo systemctl reload nginx
```

Что важно в конфиге и почему:

- `X-Forwarded-Proto $scheme` и `Host $host` — по ним STools проверяет
  Origin запросов на запись; без них вход отклоняется с 403;
- `X-Forwarded-For $remote_addr` (замена, не дописывание) — настоящий адрес
  клиента для журнала и порога неудачных входов;
- `client_max_body_size 600m` и таймауты 600 с — крупные выгрузки;
- HSTS — на nginx: до STools доходит HTTP.

Caddy в образе web доверяет этим заголовкам только от приватных адресов
(`STOOLS_TRUSTED_PROXIES`), а порт web слушает только 127.0.0.1.

## 6. Проверка

```bash
curl -s -o /dev/null -w '%{http_code}\n' https://<имя>/api/auth/oidc/status
curl -sI https://<имя>/ | grep -i -E 'strict-transport|content-security'
```

Ожидается `200`, оба заголовка на месте. Затем — вход в браузере и
загрузка тестовой выгрузки.

## Обновление

1. Резервная копия (ниже).
2. `STOOLS_VERSION` в `.env` — новый тег.
3. `docker compose -f docker-compose.prod.yml pull && docker compose -f docker-compose.prod.yml up -d`

Миграции применяются на старте API.

## Резервная копия

Для полного экспорта и восстановления PostgreSQL используйте
[скрипт и инструкцию](database-backup.md). Команды из корня проекта:

```bash
STOOLS_BACKUP_DIR="$HOME/stools-backups/db-$(date -u +%Y%m%dT%H%M%SZ)"
python3 ops/stools_db.py backup "$STOOLS_BACKUP_DIR" --container stools-db-1
python3 ops/stools_db.py verify "$STOOLS_BACKUP_DIR" --container stools-db-1
```

Копируется вся БД, включая `app_setting.siem_finding_key`: без этой соли
решения аналитика по находкам SIEM нельзя корректно сопоставить с находками.
Сохраняйте также всё содержимое `/data` API, версию STools и отдельно ключ
`STOOLS_SESSION_SECRET`. Файлы, ключ и SQLite коллектора не входят в PostgreSQL-дамп.
Для согласованной копии БД и файлов сначала остановите API и остальных писателей.

Восстановление после остановки API и других подключений:

```bash
python3 ops/stools_db.py restore "$STOOLS_BACKUP_DIR" \
  --container stools-db-1 --database kbaudit --confirm-database kbaudit
```

Сначала дамп загружается в новую БД; после успешной загрузки она получает
целевое имя. Прежняя БД сохраняется под именем `stools_before_...` с запретом
подключений. Скрипт не запускает API автоматически. Перед запуском верните
согласованные файлы `/data`, исходный ключ и ту же версию STools.
Требования, перенос ARM/x86, обработка ошибок и откат описаны в
[полной инструкции](database-backup.md).

## Откат

Миграции назад не катятся. Откат версии — восстановление копии, сделанной
перед обновлением, и прежний `STOOLS_VERSION`.
