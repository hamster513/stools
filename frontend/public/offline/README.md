# STools — единая выгрузка / Unified offline download

Распакуйте весь комплект. На macOS/Linux доступны `sh download-stools.sh`, `python3 offline_download.py` и прямой запуск `./offline_download.py`. Не передавайте `.py` в `sh`. Нужен Python 3.11+. Git нужен для обновлений GHSA и правил Sigma/Elastic. Установка зависимостей автоматически не выполняется.
Unpack the entire kit. Python 3.11+ is required; Git is required for GHSA and rule updates. No dependencies are installed automatically.

## Меню / Menu

Linux:

```sh
sh download-stools.sh
```

PowerShell:

```powershell
.\download-stools.ps1
```

В меню доступны выбор данных, полный режим/обновления, период, папка, системный прокси/напрямую и язык RU/EN. Переводится интерфейс, а не содержимое источников.
The menu selects datasets, full/update mode, period, output directory, system/direct proxy and RU/EN interface language. Source content is not translated.

## Тихий запуск / Unattended execution

```sh
sh download-stools.sh --datasets nvd,ghsa,news --mode updates --period 7d --output ./transfer --lang ru --quiet
sh download-stools.sh --datasets all --mode full --output ./transfer --lang en --quiet
```

```powershell
.\download-stools.ps1 -Datasets nvd,ghsa,news -Mode Updates -Period 7d -Output D:\Transfer -Lang ru -Quiet
.\download-stools.ps1 -Datasets all -Mode Full -Output D:\Transfer -Lang en -Quiet
```

Данные / Datasets: `all`, `nvd`, `ghsa`, `epss`, `kev`, `exploitdb`, `msf`, `attack` (CVE→ATT&CK/CTID), `news` (RSS/Atom + Telegram), `sigma`, `elastic`.

Периоды / Periods: `1d` — сутки/day; `7d` — неделя/week; `3m` — три календарных месяца/three calendar months. Интервал UTC `(начало, конец]`; более трёх месяцев недопустимо. В полном режиме период не применяется. Один запуск использует общее время окончания для всех выбранных данных.

`--quiet` / `-Quiet` исключает меню, вопросы и сообщения прогресса. Обязательны данные, режим и период для обновлений. Ошибки параметров выводятся в stderr; подробности загрузки сохраняются в `run.log` и `report.json`. Exit codes: `0` — успешно/success; `2` — частично/partial; `1` — ошибка/failure.

## Что переносить / Transfer results

В указанной папке создаётся новый каталог `stools-<UTC-время>-<суффикс>`: архивы, `report.json`, `run.log`. Старые результаты не перезаписываются. Успешные результаты сохраняются, даже если другой источник недоступен. Локальный `.stools-cache` используется для проверки версий и Git-метаданных.

Архивы справочников загрузите в **Настройки → VM → Справочники → Загрузить архив**. Новости и правила — в **Настройки → VM → Архив новостей**. Новости появятся в **VM → Трендовые уязвимости**; правила останутся справочными материалами. Файлы внутри архивов не переименовывайте. Лимиты STools сохраняются: 500 МиБ для справочников, 64 МиБ для новостей/правил.

Upload reference ZIPs to **Settings → VM → References → Upload archive**; news/rule ZIPs to **Settings → VM → News archive**. News appears in VM trends; rules remain reference materials. Do not rename archive contents. Existing 500 MiB/64 MiB upload limits still apply.

## Диагностика загрузки / Download diagnostics

Для macOS используется тот же `sh download-stools.sh`, что и для Linux. При скачивании каждые 5 секунд показываются ожидание ответа/получение данных, объём, средняя скорость, прошедшее время и время без новых данных. HTTP-код появляется после получения заголовков. Процент отображается только когда сервер сообщает размер: GitHub codeload может не присылать `Content-Length`, тогда показывается «размер неизвестен». Проверка и упаковка отмечаются отдельно; уже сжатые ZIP/GZIP не сжимаются повторно.

macOS uses the same `sh download-stools.sh` as Linux. Every 5 seconds, downloads report the current stage, received bytes, average speed, elapsed time and time without new data. HTTP status appears after headers arrive. A percentage is shown only when the server provides a size; GitHub codeload may omit it. Validation and packaging are separate stages; ZIP/GZIP files are not recompressed.

Диагностика сохраняется в `run.log` внутри каталога запуска, в том числе при `--quiet` / `-Quiet`. Тихий режим намеренно ничего не печатает в консоль. Для проверки запускайте без него. Ошибки DNS, TLS, HTTP и тайм-аут выводятся без паролей прокси и параметров URL. В Python тайм-аут относится к ожиданию ответа/следующих данных, в нативном Windows-транспорте — ко всему запросу. Обновлённый комплект нужно распаковать полностью: одной замены `.sh` недостаточно.

Diagnostics are also written to the run directory's `run.log` in quiet mode. Run without `--quiet` / `-Quiet` to see them in the terminal. DNS, TLS, HTTP and timeout errors do not expose proxy passwords or URL query parameters. Python timeouts bound response/data waits; the native Windows transport bounds the entire request. Unpack the entire updated kit, not just the `.sh` launcher.

## Обновления / Updates

Состояние и подключение к STools не нужны. Выгружается ровно выбранный период. Перед запуском **самостоятельно проверьте давность данных в STools**: пропущенные интервалы не догружаются. Частичное обновление сохраняет остальные записи и не означает, что вся база стала актуальной. Для первоначального заполнения используйте полный режим.

No STools state export or connection is needed. Exactly the selected period is downloaded. **Check the age of your STools data yourself**: missing intervals are not fetched automatically. A period import preserves other records and does not certify complete database freshness. Use full mode for an initial baseline.

NVD: изменения по времени `lastModified`. GHSA: разница закреплённых Git-ревизий, исходные OSV-записи, включая удаления и отозванные advisories. Sigma/Elastic: только изменённые файлы правил; пути удалённых правил перечислены в отчёте, ранее импортированные справочные материалы не удаляются.

EPSS, KEV, ExploitDB, Metasploit и CTID не предоставляют используемой здесь построчной дельты: проверяется версия/хеш, при изменении загружается полный снимок. Это явно отмечено в отчёте. Сбой сервиса не заменяется скрытой полной загрузкой NVD/GHSA.

News includes RSS/Atom and public Telegram channels via https://t.me/s/CHANNEL, without an account, bot or API keys. Full mode retrieves available history, not a complete site/channel archive. Telegram is limited to 200 text posts or 50 pages per channel per run, with a 2-second pause between pages. A limit or failed page produces a partial result, retaining collected posts. Updates exclude undated and future items and report those exclusions. Feed/source limits and unavailable sources are reported as partial results.
Новости включают RSS/Atom и публичные Telegram-каналы через https://t.me/s/CHANNEL без аккаунта, бота и API-ключей. Полный режим получает доступную историю, а не весь архив сайта/канала. Для Telegram установлен предел: 200 текстовых постов или 50 страниц на канал за запуск, пауза между страницами — 2 секунды. Достижение лимита или ошибка страницы отмечается как частичный результат; найденные посты сохраняются. В режиме обновлений материалы без даты или за пределами периода не включаются; пропуски без даты отмечаются в отчёте. Ограничения лент и недоступные источники не выдаются за полный результат.

Список Telegram-каналов лежит в `telegram-sources.json`. Встроенный каталог содержит 19 каналов, включая WMXWAS, cyberok_news, cyb3r53cr3t5, intosecurity, RalfHackerChannel, true_secator, poxek, unsec, cyberyozh_official, xor_journal, haccking. Существующие каналы сохранены, повторов нет. Сохраняются текст, дата, ссылки и номер поста; видео, изображения и файлы не скачиваются. Посты только с медиа учитываются отдельно. Повторный импорт не создаёт дубликаты; отредактированный пост обновляется. Отсутствие поста в следующем архиве не означает его удаление.

The Telegram catalog is in `telegram-sources.json`. Posts retain their text, publication date, links and message ID. Media files are not downloaded; media-only posts are counted separately. Reimports are idempotent, edits update existing posts, and missing posts do not cause deletions. Each channel has its own source identity in VM. Progress shows the channel, page and collected post count; `run.log` and `report.json` include limits and errors even in quiet mode.

Для запуска только новостей используйте `sh download-stools.sh --datasets news --mode updates --period 7d` (или `--mode full`). Telegram автоматически входит в этот набор. После импорта ZIP посты видны в VM → Трендовые уязвимости → Все собранные публикации; найденные CVE/GHSA проходят обычную классификацию, а не объявляются трендом по факту упоминания.

## Прокси / Proxy

По умолчанию используются настройки окружения (`HTTP_PROXY`, `HTTPS_PROXY`, `ALL_PROXY`, `NO_PROXY`) и системные настройки. Linux использует стандартные proxy-переменные. Windows HTTP использует системный прокси текущего пользователя, включая PAC/обход и его учётные данные прокси; явно заданные переменные окружения имеют приоритет. Адреса с паролями не выводятся в журнал.

`--no-proxy` / `-NoProxy` отключает прокси только на время запуска. Настройки ОС не меняются, проверка TLS не отключается. Git использует разрешённый для GitHub прокси; доменная авторизация требует Git с поддержкой Windows SSPI. Тихий режим не запрашивает пароль. Если прокси отклоняет вход, причина фиксируется как ошибка, без зависания на вопросе.

Default proxy configuration honors environment/system settings and bypass rules. Windows HTTP uses the current user's system proxy credentials. Git domain authentication depends on the installed Git/SSPI support. `--no-proxy` / `-NoProxy` changes only this run, never OS settings. TLS verification remains enabled. Credentials are not printed. Quiet runs never prompt for passwords.
