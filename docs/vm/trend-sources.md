# Каталог источников трендов

Каталог поставки: `collector/src/stools_threat_collector/sources.json`. Каждая запись имеет конкретный URL и издателя; домен платформы не является издателем. Сетевые проверки выполнены из контейнера сборщика 6 ноября 2026 года. Доступность может меняться; текущий результат штатного сбора виден в настройках STools.

## Правила подключения

- Официальные бюллетени, исследования, новости и общие технические ленты собираются существующими правилами. Само появление CVE, advisory, шаблона Nuclei или PoC не подтверждает эксплуатацию.
- Microsoft/MSRC/GitHub используют `microsoft`, Google/Project Zero/Mandiant — `google`, Cisco/Talos — `cisco`, Fortinet — `fortinet`, Kaspersky/Securelist/Telegram — `kaspersky`, Seebug/Knownsec Medium — `knownsec`. Wired/Ars Technica объединены под `condenast`; Kubernetes/CNCF — под `cncf`. Публикации одного издателя не дают два независимых подтверждения.
- У Habr, DEV, Slashdot, Lobsters и InfoSec Write-ups неоднородный состав авторов. Это дополнительные сигналы; проверяются оригинал, дата, CVE и самостоятельность публикации. Общетехническая лента не становится доказательством актуальности только из-за подключения.
- Источники без новых публикаций за полгода сохранены выключенными. Это статус проверки ленты, а не утверждение, что весь сайт прекратил работу.
- NVD и EPSS уже поддерживаются загрузкой справочников VM. `services.nvd.nist.gov` и `api.first.org` не добавляются как новости: CVSS, перечень CVE и вероятность эксплуатации не являются подтверждением эксплуатации.
- Новые записи каталога по умолчанию выключены. На стенде включаются проверенные актуальные RSS/API; настройки уже существующих источников сохраняются.

## Сайты из списка владельца

| Домен | Лента / результат | Статус проверки |
| --- | --- | --- |
| `3dnews.ru` | [3DNews](https://3dnews.ru/news/rss/) | Подключена на стенде |
| `aws.amazon.com` | [AWS Security Blog](https://aws.amazon.com/blogs/security/feed/) | Подключена на стенде |
| `blog.intigriti.com` | [Intigriti Blog](https://www.intigriti.com/blog/feed) | Подключена на стенде |
| `blog.jetbrains.com` | [JetBrains Security](https://blog.jetbrains.com/security/feed/) | Подключена на стенде |
| `blog.talosintelligence.com` | [Cisco Talos Intelligence](https://blog.talosintelligence.com/rss/) | Подключена на стенде |
| `blog.yeswehack.com` | [YesWeHack Blog](https://www.yeswehack.com/rss.xml) | Подключена на стенде |
| `blogs.cisco.com` | [Cisco Security Blog](https://blogs.cisco.com/security/feed) | Подключена на стенде |
| `blogs.vmware.com` | [VMware Security](https://blogs.vmware.com/security/feed) | Подключена на стенде |
| `bugalert.org` | [Bug Alert Critical](https://bugalert.org/feeds/critical-severity.atom.xml) | Архивная лента; выключена; последняя запись 2022-03-30 |
| `cert.europa.eu` | [CERT-EU](https://cert.europa.eu/publications/security-advisories-rss) | Уже есть; сохранить настройки |
| `cvefeed.io` | [CVEFeed Recent Vulnerabilities](https://cvefeed.io/rssfeed/latest.xml) | Подключена на стенде |
| `dev.to` | [DEV Security](https://dev.to/feed/tag/security) | Подключена на стенде |
| `developers.googleblog.com` | [Google Developers Blog](https://developers.googleblog.com/feeds/posts/default/) | Подключена на стенде |
| `feed.infoq.com` | [InfoQ](https://feed.infoq.com/) | Подключена на стенде |
| `feeds.arstechnica.com` | [Ars Technica](https://feeds.arstechnica.com/arstechnica/index) | Подключена на стенде |
| `feeds.feedburner.com` | [The Hacker News](https://feeds.feedburner.com/TheHackersNews) | Уже есть; сохранить настройки |
| `feeds.fortinet.com` | [Fortinet Threat Research](https://feeds.fortinet.com/fortinet/blog/threat-research) | Подключена на стенде |
| `filestore.fortinet.com` | [Fortinet PSIRT](https://filestore.fortinet.com/fortiguard/rss/ir.xml) | Подключена на стенде |
| `forklog.com` | [ForkLog](https://forklog.com/feed) | Подключена на стенде |
| `gbhackers.com` | [GBHackers](https://gbhackers.com/feed/) | Подключена на стенде |
| `github.blog` | [GitHub Security](https://github.blog/security/feed/) | Подключена на стенде |
| `govcert.ch` | Сайт переехал на BACS; официальный раздел направляет в GitHub-архив. Рабочая лента новых публикаций не найдена. | Не подключён |
| `habr.com` | [Habr Information Security](https://habr.com/ru/rss/hubs/infosecurity/articles/all/?fl=ru) | Подключена на стенде |
| `hackware.ru` | Проверенные адреса возвращают HTML/404; рабочая RSS не найдена. | Не подключён |
| `incrussia.ru` | [Inc Russia](https://incrussia.ru/feed/all/) | Подключена на стенде |
| `isc.sans.edu` | [SANS Internet Storm Center](https://isc.sans.edu/rssfeed.xml) | Подключена на стенде |
| `krebsonsecurity.com` | [Krebs on Security](https://krebsonsecurity.com/feed/) | Подключена на стенде |
| `kubernetes.io` | [Kubernetes Security Announcements](https://kubernetes.io/docs/reference/issues-security/official-cve-feed/feed.xml) | Подключена на стенде |
| `lobste.rs` | [Lobsters Security](https://lobste.rs/t/security.rss) | Подключена на стенде |
| `news.drweb.ru` | [Dr.Web Threat Alerts](https://news.drweb.ru/rss/get/?c=23) | Подключена на стенде |
| `packetstormsecurity.com` | Переезд на packetstorm.news; старый путь feeds/news возвращает HTML. Требуется новый интерфейс получения. | Не подключён |
| `portswigger.net` | [PortSwigger Research](https://portswigger.net/research/rss) | Подключена на стенде |
| `projectzero.google` | [Google Project Zero](https://projectzero.google/feed.xml) | Подключена на стенде |
| `research.checkpoint.com` | [Check Point Research](https://research.checkpoint.com/feed/) | Подключена на стенде |
| `rss.slashdot.org` | [Slashdot](https://rss.slashdot.org/Slashdot/slashdotMain) | Подключена на стенде |
| `schneier.com` | [Schneier on Security](https://www.schneier.com/feed/atom/) | Подключена на стенде |
| `sec.cloudapps.cisco.com` | [Cisco Security Advisories](https://sec.cloudapps.cisco.com/security/center/psirtrss20/CiscoSecurityAdvisory.xml) | Подключена на стенде |
| `sec.okta.com` | [Okta Security](https://sec.okta.com/rss.xml) | Подключена на стенде |
| `securityaffairs.com` | [Security Affairs](https://securityaffairs.com/feed) | Подключена на стенде |
| `stackoverflow.blog` | [Stack Overflow Blog](https://stackoverflow.blog/feed/) | Подключена на стенде |
| `support.citrix.com` | Старые RSS-адреса возвращают HTML портала поддержки; требуется актуальный интерфейс бюллетеней. | Не подключён |
| `techcrunch.com` | [TechCrunch Security](https://techcrunch.com/category/security/feed/) | Подключена на стенде |
| `thedfirreport.com` | [The DFIR Report](https://thedfirreport.com/feed/) | Подключена на стенде |
| `tproger.ru` | [Tproger](https://tproger.ru/feed) | Подключена на стенде |
| `ubuntu.com` | [Ubuntu Security Notices](https://ubuntu.com/security/notices/rss.xml) | Подключена на стенде |
| `unit42.paloaltonetworks.com` | [Unit 42](https://unit42.paloaltonetworks.com/feed/) | Подключена на стенде |
| `vc.ru` | [VC.ru](https://vc.ru/rss) | Подключена на стенде |
| `www.anti-malware.ru` | [Anti-Malware.ru](https://www.anti-malware.ru/rss.xml) | Архивная лента; выключена; последняя запись 2019-03-21 |
| `www.bleepingcomputer.com` | [BleepingComputer](https://www.bleepingcomputer.com/feed/) | Уже есть; сохранить настройки |
| `www.cert.ssi.gouv.fr` | [CERT-FR alerts](https://cert.cyber.gouv.fr/alerte/feed/) | Уже есть; сохранить настройки |
| `www.cisa.gov` | KEV уже подключён через официальный GitHub. Дополнительная официальная RSS all.xml возвращает HTTP 403; добавлена выключенной. | Не подключён |
| `www.cncf.io` | [CNCF Blog](https://www.cncf.io/feed/) | Подключена на стенде |
| `www.cnews.ru` | [CNews Security](https://www.cnews.ru/inc/rss/news.xml) | Подключена на стенде |
| `www.cobalt.io` | [Cobalt Blog](https://www.cobalt.io/blog/rss.xml) | Подключена на стенде |
| `www.comss.ru` | [Comss Security](https://www.comss.ru/rss.php) | Подключена на стенде |
| `www.csoonline.com` | [CSO Online](https://www.csoonline.com/feed/) | Подключена на стенде |
| `www.darkreading.com` | [Dark Reading](https://www.darkreading.com/rss.xml) | Подключена на стенде |
| `www.debian.org` | [Debian Security Advisories](https://www.debian.org/security/dsa) | Подключена на стенде |
| `www.docker.com` | [Docker Blog](https://www.docker.com/feed/) | Подключена на стенде |
| `www.exploit-db.com` | [Exploit Database](https://www.exploit-db.com/rss.xml) | Подключена на стенде |
| `www.group-ib.com` | Запросы RSS с адреса сборщика завершаются тайм-аутом; рабочая лента не подтверждена. | Не подключён |
| `www.hackread.com` | [HackRead](https://hackread.com/feed/) | Подключена на стенде |
| `www.helpnetsecurity.com` | [Help Net Security](https://www.helpnetsecurity.com/feed/) | Подключена на стенде |
| `www.ibm.com` | SecurityIntelligence: ошибка цепочки TLS; FeedBurner/проверенные IBM-адреса не вернули RSS. Проверку сертификатов не отключать. | Не подключён |
| `www.infosecurity-magazine.com` | [Infosecurity Magazine](https://www.infosecurity-magazine.com/rss/news/) | Подключена на стенде |
| `www.ixbt.com` | [iXBT News](https://www.ixbt.com/export/news/rss.xml) | Подключена на стенде |
| `www.kaspersky.ru` | [Kaspersky Blog](https://www.kaspersky.ru/blog/feed/) | Подключена на стенде |
| `www.kitploit.com` | [KitPloit](https://kitploit.com/en/rss.xml) | Подключена на стенде |
| `www.malwarebytes.com` | [Malwarebytes Labs](https://www.malwarebytes.com/blog/feed/index.xml) | Подключена на стенде |
| `www.mandiant.com` | [Google Mandiant Threat Intelligence](https://feeds.feedburner.com/threatintelligence/pvexyqv7v0v) | Подключена на стенде |
| `www.microsoft.com` | [Microsoft Security Blog](https://www.microsoft.com/en-us/security/blog/feed/) | Подключена на стенде |
| `www.opennet.ru` | [OpenNET Security](https://www.opennet.ru/opennews/opennews_sec.rss) | Подключена на стенде |
| `www.paloaltonetworks.com` | [Palo Alto Networks Blog](https://www.paloaltonetworks.com/blog/feed/) | Подключена на стенде |
| `www.rapid7.com` | [Rapid7 Blog](https://www.rapid7.com/rss.xml) | Подключена на стенде |
| `www.securitylab.ru` | [SecurityLab](https://www.securitylab.ru/_services/export/rss/) | Уже есть; сохранить настройки |
| `www.securitymagazine.com` | [Security Magazine Cybersecurity](https://www.securitymagazine.com/rss/topic/2236-cybersecurity) | Подключена на стенде |
| `www.securityweek.com` | [SecurityWeek](https://www.securityweek.com/feed/) | Подключена на стенде |
| `www.sentinelone.com` | [SentinelOne Blog](https://www.sentinelone.com/blog/feed/) | Подключена на стенде |
| `www.theregister.com` | [The Register Security](https://api.theregister.com/api/v1/article?orderBy=published&site_id=2&remapper=rss&query=tag:security) | Подключена на стенде |
| `www.theverge.com` | [The Verge](https://www.theverge.com/rss/index.xml) | Подключена на стенде |
| `www.welivesecurity.com` | [ESET WeLiveSecurity](https://www.welivesecurity.com/en/rss/feed/) | Уже есть; сохранить настройки |
| `www.wired.com` | [WIRED Security](https://www.wired.com/feed/category/security/latest/rss) | Подключена на стенде |
| `www.zdnet.com` | [ZDNET Security](https://www.zdnet.com/rss/news/) | Подключена на стенде |
| `www.zerodayinitiative.com` | [Zero Day Initiative Advisories](https://www.zerodayinitiative.com/rss/published/) | Подключена на стенде |
| `xakep.ru` | [Хакер](https://xakep.ru/feed/) | Подключена на стенде |
| `xn--e1agfe6atq9c.xn--p1ai` | [Техключи](https://xn--e1agfe6atq9c.xn--p1ai/rss/) | Архивная лента; выключена; последняя запись 2025-12-07 |

## Общие платформы: выбранные источники

| Платформа | Выбор | Подключение |
| --- | --- | --- |
| `raw.githubusercontent.com` | [CISA KEV](https://raw.githubusercontent.com/cisagov/kev-data/main/known_exploited_vulnerabilities.json) | Уже работает; повторная запись не создаётся. |
| GitHub | [Reviewed Advisories API](https://api.github.com/advisories) | Новый адаптер `github`; CVE/GHSA, первоначальная дата, обновления и отзывы. |
| GitHub | [ProjectDiscovery nuclei-templates releases](https://github.com/projectdiscovery/nuclei-templates/releases.atom) | Публичные новые проверки/шаблоны; не подтверждение эксплуатации. |
| FeedBurner | The Hacker News, Google Mandiant Threat Intelligence, [Troy Hunt](https://feeds.feedburner.com/TroyHunt) | Конкретные авторские ленты; Mandiant и THN не дублируются при повторной записи домена. |
| Medium | [InfoSec Write-ups](https://medium.com/feed/bugbountywriteup) | Подключена на стенде |
| Medium | [Knownsec 404 Medium](https://medium.com/feed/@knownsec404team) | Архивная лента; выключена; последняя запись 2026-03-19 |
| Medium | [SSD Secure Disclosure](https://medium.com/feed/ssd-secure-disclosure) | Архивная лента; выключена; последняя запись 2025-08-11 |
| Medium | [Tenable Tech Blog](https://medium.com/feed/tenable-techblog) | Архивная лента; выключена; последняя запись 2024-09-13 |
| Medium | [Symantec Threat Intelligence](https://medium.com/feed/threat-intel) | Архивная лента; выключена; последняя запись 2020-05-27 |

## Telegram

Выбраны публичные каналы с проверенным названием и доступными датированными публикациями. Официальные сайты связывают BI.ZONE с `bizone_channel`, SecurityLab с `SecLabNews`, Dr.Web с `DrWeb_antivirus`, Securelist с `purpleshift`. PT SWARM уже был в каталоге. BugAlert и чат BI.ZONE Bug Bounty не добавлены: при проверке публичных датированных сообщений не получено.

| Канал | Назначение |
| --- | --- |
| [PT SWARM](https://t.me/ptswarm) | Исследования уязвимостей и технические раскрытия. |
| [purple shift](https://t.me/purpleshift) | Исследования Kaspersky, угрозы и уязвимости. |
| [BI.ZONE](https://t.me/bizone_channel) | Исследования, угрозы и новости команды; встречаются организационные сообщения. |
| [SecurityLab](https://t.me/SecLabNews) | Оперативные новости; один издатель с RSS SecurityLab. |
| [Dr.Web](https://t.me/DrWeb_antivirus) | Исследования угроз и уведомления производителя. |

Все Telegram-источники на стенде выключены: нет файлов API ID/API hash и авторизованной MTProto-сессии. Публичный предпросмотр использован только для проверки каналов; это не замена штатному адаптеру. Для запуска см. Telegram в [trends.md](trends.md). Сообщения Telegram не передаются LLM.

## Обновление существующей установки

После обновления образа выполните `stools-threat-collector catalog` внутри контейнера. Команда добавляет отсутствующие URL выключенными, не меняет существующие настройки, версии и checkpoints; повторный запуск не создаёт дублей. Затем включите выбранные источники в настройках STools. Для новой БД каталог загружается при первом старте.

GitHub-адаптер использует публичный [REST API global advisories](https://docs.github.com/en/rest/security-advisories/global-advisories) без токена: reviewed advisories, до пяти страниц по сто записей за запуск. Первая выборка ограничена изменениями за месяц; продолжение сохраняет курсор и фиксированную верхнюю границу. Последующие циклы перекрывают сутки для запоздавшей индексации. Исходная дата публикации сохраняется, отзыв создаёт retract. Ошибка страницы не продвигает checkpoint. Ссылки пагинации допускаются только на HTTPS `api.github.com/advisories`.

## Источники проверки переездов

- [Mandiant / Google Threat Intelligence](https://cloud.google.com/blog/topics/threat-intelligence) публикует ссылку на свою FeedBurner-ленту.
- [Dr.Web RSS](https://news.drweb.ru/rss/) перечисляет тематические каналы, включая горячую ленту угроз.
- [Bug Alert Atom](https://bugalert.org/content/pages/atom.html) разделяет рабочие категории и тестовые уведомления; выбрана critical severity, общий тестовый поток не подключён.
- [BACS: GovCERT](https://www.bacs.admin.ch/en/govcert) объясняет перенос старого сайта в GitHub.

GitHub может ответить `403` при исчерпании общего публичного лимита. Адаптер читает `X-RateLimit-Reset`, откладывает повтор до восстановления квоты и сохраняет прежний checkpoint. Другие HTTP-ошибки показывают код ответа. Это сетевое ограничение источника, а не успешный пустой сбор.
