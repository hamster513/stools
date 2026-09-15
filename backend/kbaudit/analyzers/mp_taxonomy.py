"""Роли полей по документации MaxPatrol SIEM.

Источник: «Схема полей событий», документация MP SIEM 7.0. Таблица
составлена по описаниям полей оттуда, а не по догадкам об именах, и
каждая строка отвечает на один вопрос: принадлежит ли значение этого
поля конкретной инсталляции.

Средовое — значение уникально для этой установки: логин, домен, имя
общей папки, адрес. Такой литерал в правиле — долг: он привязывает
правило к месту.

Техническое — значение одинаково всюду: имя системного процесса,
привилегия, протокол, хеш, код события. Такой литерал и есть суть
детекта, и выносить его в список незачем.

Там, где документация не даёт однозначного ответа, роли здесь нет —
и это намеренно. `object.process.fullpath` бывает и системным путём
(`C:\\Windows\\System32\\cmd.exe`, одинаковым везде), и путём к
самописному приложению. Такие поля остаются вопросом к человеку.
"""
from __future__ import annotations

#: Точные имена полей. Проверяются раньше суффиксов.
_EXACT: dict[str, str] = {
    # «Название приложения (источника)… например windows, asa, ios» —
    # одинаково в любой инсталляции, хотя по нему и разрешается актив.
    "event_src.title": "technical",
    "event_src.vendor": "technical",
    # «Уникальный идентификатор источника события», «Подсистема источника»,
    # «Название правила, службы или приложения» — свойства продукта-источника.
    "event_src.id": "technical",
    "event_src.subsys": "technical",
    "event_src.rule": "technical",
    # «Полное доменное имя (FQDN) NAS-сервера» — узел инсталляции.
    "nas_fqdn": "environmental",
    "nas_ip": "environmental",
    # «Протокол передачи данных», «Протокол уровня приложения» — стандарты.
    "protocol": "technical",
    "protocol.layer7": "technical",
    "interface": "technical",
    "tcp_flag": "technical",
    "direction": "technical",
    # «Идентификатор типа события, уникальный в рамках событий одного
    # источника» — свойство источника, а не инсталляции.
    "msgid": "technical",
    "chain_id": "technical",
    # «Название домена субъекта», «Имя домена объекта» — домен всегда
    # принадлежит установке.
    "subject.domain": "environmental",
    "object.domain": "environmental",
    # `object.name`, `subject.name`, `*.id`, `*.group` документация
    # описывает слишком общо — «Имя объекта», «Идентификатор субъекта».
    # Объектом бывает что угодно: файл, именованный канал, служба, ветка
    # реестра. Замер показал, чем это оборачивается: 146 находок из 177
    # новых пришлись на `object.name` со значением `svcctl` — имя канала,
    # по которому отличают запуск через диспетчер служб, то есть на суть
    # детекта, а не на среду. `object.id` дал «schema admins» — встроенную
    # группу Active Directory. Роль этих полей остаётся вопросом
    # к человеку: она зависит от того, что за объекты трогают правила.
    # «Изменяемое свойство объекта», «Тип объекта», «Состояние объекта» —
    # словарь предметной области, а не имена инсталляции.
    "object.property": "technical",
    "object.type": "technical",
    "object.state": "technical",
    "object.vendor": "technical",
    "object.version": "technical",
    "subject.type": "technical",
    "subject.state": "technical",
    "subject.version": "technical",
    "subject.privileges": "technical",
    "object.privileges": "technical",
}

#: Суффиксы имени поля. Проверяются по последним сегментам, поэтому
#: одно правило покрывает и `subject.*`, и `object.*`, и вложенные
#: `*.application.account.*`.
_SUFFIX: dict[str, str] = {
    # Учётные записи и их атрибуты — «Логин учётной записи», «Домен
    # учётной записи», «Отличительное имя (Distinguished Name)», «имя
    # и фамилия», «Имена групп». Всё это принадлежит установке.
    "account.name": "environmental",
    "account.domain": "environmental",
    "account.dn": "environmental",
    "account.fullname": "environmental",
    "account.group": "environmental",
    "account.id": "environmental",
    "account.contact": "environmental",
    "application.name": "environmental",
    # «Идентификатор сессии, например Logon ID» и «Хранилище учётной
    # записи» — генерируется системой либо словарное значение.
    "account.session_id": "technical",
    "account.provider": "technical",
    # «Права и привилегии учётной записи» — SeDebugPrivilege одинаков всюду.
    "account.privileges": "technical",
    # Процессы: имя, версия, метаданные, хеши — свойства программы,
    # а не установки. `cmd.exe` одинаков в любой инсталляции.
    "process.name": "technical",
    "process.original_name": "technical",
    "process.version": "technical",
    "process.meta": "technical",
    "process.guid": "technical",
    "process.id": "technical",
    "process.chain": "technical",
    "process.hash": "technical",
    "process.hash.md5": "technical",
    "process.hash.sha1": "technical",
    "process.hash.sha256": "technical",
    "process.hash.imphash": "technical",
    # `*.storage.*` документация описывает как «название общей папки или
    # общего диска», и звучит это инсталляционно. Замер показал иное:
    # рядом с `PROD_AVC_FIN20` там лежат `lsarpc`, `netdfs`, `efsrpc` —
    # имена системных именованных каналов Windows, одинаковые всюду.
    # Одно поле несёт и то и другое, и роль его — вопрос к человеку.
    # Хеши объекта.
    "hash": "technical",
    "hash.md5": "technical",
    "hash.sha1": "technical",
    "hash.sha256": "technical",
    "hash.imphash": "technical",
    # География внешних узлов: город, страна, организация, номер AS —
    # это про интернет, а не про инсталляцию.
    "geo.city": "technical",
    "geo.country": "technical",
    "geo.org": "technical",
    "geo.asn": "technical",
}

#: Префиксы разделов документации. Проверяются последними: раздел
#: говорит о назначении группы полей, но точное имя всегда весомее.
_PREFIX: dict[str, str] = {
    # «Поля корреляционного события» и «Поля, описывающие инцидент» —
    # это то, что правило пишет само, а не то, по чему фильтрует.
    "alert.": "technical",
    "incident.": "technical",
    "count.": "technical",
    # Точка сбора и сервисные поля заполняются системой.
    "recv_": "technical",
    "generator.": "technical",
}


def role_by_documentation(field: str) -> str | None:
    """Роль поля по документации MP SIEM или None, если её там нет.

    Порядок — от точного к общему: имя поля, затем суффикс, затем
    раздел. Точное правило всегда перекрывает общее.
    """
    name = field.lower()
    if name in _EXACT:
        return _EXACT[name]
    for suffix, role in _SUFFIX.items():
        if name == suffix or name.endswith("." + suffix):
            return role
    for prefix, role in _PREFIX.items():
        if name.startswith(prefix):
            return role
    return None
