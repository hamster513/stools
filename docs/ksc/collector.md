# Сборщик выгрузки Kaspersky Security Center

Скрипт `STools-KSC-Collector.ps1` скачивается в интерфейсе: Антивирус →
Настройки и данные → «Скачать». Он не анализирует и не меняет ничего на
сервере KSC: вызывает методы Open API (порт 13299) и пишет один файл
формата `stools-ksc/1` (JSON, gzip) — ответы сервера складываются как есть.

## Требования

- Windows с PowerShell 5.1 или новее, либо любая ОС с PowerShell 7 — скрипт
  ходит к KSC по HTTPS, модуль ActiveDirectory не нужен.
- Сетевой доступ к серверу KSC на порт Open API (по умолчанию 13299).
- Учётная запись KSC с правом чтения (внутренняя или доменная).
- Скрипт хранится в UTF-8 с BOM: без него Windows PowerShell 5.1 читает файл
  в ANSI и ломает кириллицу в строках. При правке сохраняйте BOM (тест
  `test_collector_script_has_utf8_bom`).

## Запуск

```powershell
.\STools-KSC-Collector.ps1 -Server ksc01.corp.local -User audit -Internal
.\STools-KSC-Collector.ps1 -Server 10.0.0.5 -User audit -Domain CORP -SkipTlsCheck -OutputPath C:\Temp\ksc.json.gz
.\STools-KSC-Collector.ps1 -Server ksc01.corp.local -User audit -Internal -SkipProducts   # без продуктов и компонентов (быстрее)
```

Пароль запрашивается интерактивно (`Read-Host -AsSecureString`), если не
передан параметром `-Password`. Для самоподписанного сертификата сервера
добавьте `-SkipTlsCheck`.

Результат — `ksc-<сервер>-<дата>.json.gz` в текущем каталоге. Файл содержит
инвентарь устройств (имена, IP-адреса, версии продуктов и агента) —
обращайтесь с ним как с чувствительными данными.

## Что дальше

Загрузите файл в STools: Антивирус → Настройки и данные → «Загрузить
выгрузку». Появится снапшот сервера; повторные загрузки сравниваются с
предыдущей по времени сбора.

Онлайн-режим (сбор из STools по Open API) даёт ту же выгрузку — проверки в
обоих режимах одни и те же.
