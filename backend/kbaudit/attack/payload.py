"""Выжимка по группе правил: то, что уходит к модели.

Собирается из **белого списка полей**, а не вычищается от плохого. Денилист
рано или поздно пропустит, и об этом никто не узнает — а здесь цена ошибки
в том, что инвентарь внутренней инфраструктуры уедет к модели.

Блоклист строится из самих данных: все значения табличных списков выгрузки.
Это ловит то, чего не поймает регулярка. Строки `kata` или `web_api`
выглядят обычными словами, но лежат в whitelist'ах и потому чувствительны.

Чистый аллоулист при этом неприемлем: `svcctl` и `atsvc` не подходят ни под
один шаблон «безопасного вида», но именно они несут сигнал о технике.
"""
from __future__ import annotations

import re

from pydantic import BaseModel, Field

from kbaudit.analyzers.hardcode import scan_comparisons
from kbaudit.models import KbObject, Polarity, Rule

#: Формы, по которым значение отбрасывается независимо от блоклиста:
#: адреса, внутренние имена, доменные SID, номера тикетов.
RE_IP = re.compile(r"\b\d{1,3}(?:\.\d{1,3}){3}\b")
RE_CIDR = re.compile(r"\b\d{1,3}(?:\.\d{1,3}){3}/\d{1,2}\b")
RE_INTERNAL_FQDN = re.compile(r"\b[\w-]+(?:\.[\w-]+)*\.(?:local|internal|corp|lan|ru)\b", re.IGNORECASE)
RE_DOMAIN_SID = re.compile(r"^S-1-5-21-", re.IGNORECASE)
RE_TICKET = re.compile(r"\b(?:INC|REQ|RITM|SD|TASK)[-_]?\d{3,}\b", re.IGNORECASE)

#: Разбиение текста выжимки на токены для проверки перед отправкой.
RE_TOKEN = re.compile(r"[\w.\\@$-]+")

#: Обычное слово: только буквы, без цифр и разделителей. Имя узла или
#: учётной записи почти всегда содержит цифру либо дефис — `host01we289`,
#: `adm-petrov`, — а слово `Windows` не содержит ничего такого.
RE_WORDLIKE = re.compile(r"^[^\W\d_]+$", re.UNICODE)

#: Формы, безусловно безопасные: они описывают платформу, а не инсталляцию.
#: Имя `cmd.exe` не становится тайной оттого, что кто-то внёс его
#: в whitelist — в отличие от имени узла, внесённого туда же.
RE_PLATFORM_TOKEN = re.compile(
    r"""^(?:
        [\w-]+\.(?:exe|dll|ps1|bat|cmd|vbs|js|sys|scr)   # имена исполняемых файлов
      | HK(?:LM|CU|CR|U|CC)\\.*                          # ветки реестра
      | \d{1,5}                                          # идентификаторы событий
    )$""",
    re.VERBOSE | re.IGNORECASE,
)

#: Константы вида GNRL_EV_ALERT, KLAUD_EV_SERVERCONNECT — словарь продукта,
#: а не инсталляции. Каждая часть после первой обязана начинаться с буквы:
#: так `GNRL_EV_WEB_URL_BLOCKED` проходит, а `SRV_FIN_01` — нет, потому что
#: имена узлов почти всегда оканчиваются числом.
RE_CONSTANT_TOKEN = re.compile(r"^[A-Z][A-Z0-9]*(?:_[A-Z][A-Z0-9]*)+$")

#: Сколько значений одного вида класть в выжимку. Больше не нужно: техника
#: определяется характером литералов, а не их количеством.
MAX_LITERALS = 25
MAX_TITLES = 5


class GroupPayload(BaseModel):
    """То, что отправляется модели. Больше ничего отправлять нельзя."""

    group: str
    rule_count: int
    titles: list[str] = Field(default_factory=list)
    #: Что правило сообщает при срабатывании. Говорит о технике прямее
    #: заголовка, в который вендоры дописывают служебные коды.
    descriptions: list[str] = Field(default_factory=list)
    event_ids: list[str] = Field(default_factory=list)
    literals: list[str] = Field(default_factory=list)
    fields: list[str] = Field(default_factory=list)
    filters: list[str] = Field(default_factory=list)

    @property
    def embedding_text(self) -> str:
        parts = [
            " ".join(self.titles),
            " ".join(self.descriptions),
            " ".join(self.event_ids),
            " ".join(self.literals),
            " ".join(self.fields),
            " ".join(self.filters),
        ]
        return "\n".join(p for p in parts if p)


class LeakGuardError(RuntimeError):
    """Выжимка не прошла проверку и отправлена не будет."""


def classify_literal(value: str, blocklist: frozenset[str]) -> str:
    """Куда отнести литерал: `drop`, `send` или `review`.

    Три корзины вместо двух намеренно. Незнакомое не отправляется молча —
    оно попадает в `review`, то есть в файл на разовый просмотр человеком.
    Несколько сотен уникальных значений, час работы, и дальше список
    одобренного переиспользуется.
    """
    text = value.strip()
    if not text:
        return "drop"

    # Средовые формы отбрасываются раньше всего и безусловно.
    if (
        RE_CIDR.search(text)
        or RE_IP.search(text)
        or RE_INTERNAL_FQDN.search(text)
        or RE_DOMAIN_SID.match(text)
        or RE_TICKET.search(text)
    ):
        return "drop"

    # Платформенная лексика отправляется даже если встречается в табличных
    # списках: блоклист нужен, чтобы ловить значения, которые выглядят
    # безобидно, но специфичны для инсталляции, — а не чтобы объявлять
    # тайной имена системных исполняемых файлов и коды событий.
    if RE_PLATFORM_TOKEN.match(text) or RE_CONSTANT_TOKEN.match(text):
        return "send"

    if text.lower() in blocklist:
        return "drop"
    return "review"


def build_payload(
    group: str,
    rules: list[Rule],
    bodies: list[KbObject],
    blocklist: frozenset[str],
    approved: frozenset[str] = frozenset(),
    frequency: dict[str, int] | None = None,
) -> tuple[GroupPayload, list[str]]:
    """Выжимка по группе и список значений, требующих просмотра человеком.

    Литералы берутся из тел правил, а не из кодов событий: именно они несут
    сигнал о технике. `svcctl` и `atsvc` — имена именованных каналов, по
    которым отличается запуск через диспетчер служб от запуска через
    планировщик, и никакой код события этого не покажет.

    `approved` — то, что человек уже посмотрел и разрешил отправлять.
    Без него в выжимку попадёт только заведомо безопасное по форме, и
    сигнал вроде `svcctl` потеряется.
    """
    titles: list[str] = []
    descriptions: list[str] = []
    event_ids: set[str] = set()
    literals: set[str] = set()
    fields: set[str] = set()
    filters: set[str] = set()
    review: set[str] = set()

    for rule in rules:
        # Заголовок и описание правила — единственный свободный текст
        # в выжимке. Имя организации утекает в том числе через них,
        # поэтому оба проходят ту же проверку, что и литералы.
        if rule.title_ru and classify_literal(rule.title_ru, blocklist) != "drop":
            titles.append(rule.title_ru)
        # Описание из локализации — то, что правило сообщает при
        # срабатывании. Оно говорит о технике прямее заголовка:
        # «перехватил NTLM-хеш в результате принудительной аутентификации»
        # против «Обнаружена возможная атака type_id=JC-MNA-005-004».
        for text in rule.descriptions_ru:
            if classify_literal(text, blocklist) != "drop":
                descriptions.append(text)
        # Коды событий тоже проходят классификацию: обычно это числа,
        # но встречаются и символьные идентификаторы вроде
        # KLAUD_EV_SERVERCONNECT, и вендорские строки — отправлять их
        # без проверки значило бы держать в белом списке дыру.
        for value in rule.msgids:
            if classify_literal(value, blocklist) == "send" or value.lower() in approved:
                event_ids.add(value)
            elif classify_literal(value, blocklist) == "review":
                review.add(value)
        fields.update(rule.taxonomy_fields)
        filters.update(rule.filter_refs)

    known_events = set(event_ids)
    for body in bodies:
        for comparison in scan_comparisons(body.body_text):
            # Только утверждения. Отрицание — это whitelist: перечень того,
            # что правило ИСКЛЮЧАЕТ, то есть описание инсталляции, а не
            # техники. На эталонной выгрузке отрицания приносили в выжимку
            # `acrobat.exe` и путь к драйверу сканера — они забивали вектор
            # и делали отбор кандидатов почти случайным.
            if comparison.polarity is not Polarity.ASSERTION:
                continue
            value = comparison.value
            # Коды событий уже перечислены отдельно — не дублируем их
            # в литералах, иначе выжимка на четверть состоит из повторов.
            if value in known_events:
                continue
            verdict = classify_literal(value, blocklist)
            if verdict == "send" or value.strip().lower() in approved:
                literals.add(value)
            elif verdict == "review":
                review.add(value)

    payload = GroupPayload(
        group=group,
        rule_count=len(rules),
        titles=titles[:MAX_TITLES],
        descriptions=descriptions[:MAX_TITLES],
        event_ids=sorted(event_ids)[:MAX_LITERALS],
        literals=_most_distinctive(literals, frequency),
        fields=sorted(fields)[:MAX_LITERALS],
        filters=sorted(filters)[:MAX_LITERALS],
    )
    return payload, sorted(review)


def _most_distinctive(
    values: set[str], frequency: dict[str, int] | None
) -> list[str]:
    """Литералы, наиболее различающие группу, а не первые по алфавиту.

    Литерал, встречающийся в одной группе, говорит о технике больше, чем
    встречающийся в тридцати. Без такого упорядочивания обрезка по лимиту
    забирала значения на «a» — `access.exe`, `acrobat.exe`, — и выжимка
    описывала что угодно, кроме сути правила.
    """
    if not frequency:
        return sorted(values)[:MAX_LITERALS]
    ranked = sorted(values, key=lambda v: (frequency.get(v.lower(), 0), v))
    return sorted(ranked[:MAX_LITERALS])


def literal_frequency(bodies: list[KbObject]) -> dict[str, int]:
    """Во скольких телах встречается каждый литерал.

    Считается один раз по всей выгрузке и передаётся в сборку выжимки:
    различающая сила литерала — свойство всей базы знаний, а не группы.
    """
    counts: dict[str, int] = {}
    for body in bodies:
        seen = {
            c.value.lower()
            for c in scan_comparisons(body.body_text)
            if c.polarity is Polarity.ASSERTION
        }
        for value in seen:
            counts[value] = counts.get(value, 0) + 1
    return counts


def assert_no_leak(payload: GroupPayload, blocklist: frozenset[str]) -> None:
    """Последняя проверка перед отправкой.

    Срабатывание блокирует отправку, а не вычищает найденное: если что-то
    запрещённое дошло досюда, сборщик выжимки сломан, и правильная реакция —
    остановиться, а не замести следы.
    """
    text = payload.embedding_text

    for pattern, what in (
        (RE_CIDR, "подсеть"),
        (RE_IP, "адрес"),
        (RE_INTERNAL_FQDN, "внутреннее имя узла"),
        (RE_TICKET, "номер тикета"),
    ):
        if pattern.search(text):
            raise LeakGuardError(f"выжимка по группе {payload.group} содержит {what}")

    # Проверка идёт по токенам, а не по подстрокам: блоклист выгрузки
    # содержит около двадцати тысяч значений, и поиск подстрок среди них
    # даёт ложное срабатывание почти на любом тексте — защита, которая
    # блокирует всё, равносильна её отсутствию, только незаметнее.
    #
    # Обычные слова из блоклиста пропускаются. В whitelist'ах выгрузки
    # лежат в том числе `Windows`, `System`, `Service` и даже `was`;
    # заголовок правила, где встретилось такое слово, утечкой не является.
    # Имя узла или учётной записи от обычного слова отличается наличием
    # цифры или разделителя, и на такие токены запрет действует.
    for token in RE_TOKEN.findall(text):
        if classify_literal(token, blocklist) != "drop":
            continue
        if RE_WORDLIKE.match(token) and token.lower() in blocklist:
            continue
        raise LeakGuardError(
            f"выжимка по группе {payload.group} содержит значение "
            f"из табличного списка выгрузки или средовую форму: {token!r}"
        )
