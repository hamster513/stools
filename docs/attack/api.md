# API модуля ATT&CK

Все ручки под `/api/attack`, требуют сессию платформы (cookie `stools_session`).
Ошибки — `{"detail": "текст по-русски"}`.
Дизайн — `docs/superpowers/specs/2026-09-10-attack-platform-design.md`.

Модуль владеет базой знаний ATT&CK (бандл, переводы, распространённость,
кампании, РФ TTP) и матрицей. О других модулях он не знает ничего: каждый
модуль сам отдаёт ему свой **слой** (см. «Слои»). Матрица без `snapshot_id` —
она показывает текущее состояние, а не выгрузку.

## Матрица, техника, цепочки

```
GET /matrix                {attack_version, sightings_window, ru_source|null,
                            layers[], tactics[]}
GET /technique/{id}        карточка техники | 404 техника не найдена
GET /chains?limit≤200(40)  {total, items[], attack_version, exposed[],
                            latest_seen, ru_source|null}
```

`GET /matrix` — родительские техники по тактикам; подтехники не
разворачиваются (их 475 против 222), слои засчитывают разметку подтехникой
её родителю сами.

```json
{
  "attack_version": "16.1",
  "layers": [
    {"id": "siem", "title": "Покрытие SIEM", "kind": "coverage",
     "unit": ["группа правил", "группы правил", "групп правил"],
     "available": true, "note": "снапшот #1"},
    {"id": "vm", "title": "Уязвимости", "kind": "exposure",
     "unit": ["хост", "хоста", "хостов"], "available": true, "note": "риск ≥ 40"},
    {"id": "ad", "title": "Active Directory", "kind": "exposure",
     "unit": ["находка", "находки", "находок"], "available": false,
     "note": "нет снапшотов AD"}
  ],
  "tactics": [{
    "shortname": "credential-access", "name": "Credential Access",
    "covered": 4, "gaps": 3, "blind": false, "observable": true,
    "techniques": [{
      "technique_id": "T1558", "name": "…", "name_ru": "…",
      "subtechnique_count": 5, "level": 3,
      "actor_groups": 12, "campaigns": 2, "sightings": 0,
      "ru": {"actors": 3, "malware": 0, "tools": 1, "procedures": 5,
             "commands": 2, "actor_names": ["…"]},
      "layers": {"siem": {"count": 2, "status": "confirmed"},
                 "vm": null,
                 "ad": {"count": 7, "status": null}},
      "covered": true, "gap": false
    }]
  }]
}
```

`level` — 0..4 для наложения распространённости; ноль значит «данных нет»,
а не «редко». `ru` — пусто, пока выгрузку РФ TTP не загрузили: ноль читался
бы как «здесь не применяют», хотя источник просто не отчитывался.

Признаки:

- `covered` — техника закрыта хотя бы одним слоем `kind=coverage`
  со статусом `confirmed | suggested`;
- `gap` — есть экспозиция хотя бы в одном слое `kind=exposure` и нет
  покрытия. Пробел с экспозицией весит больше пробела вообще: техника не
  закрыта, и в инфраструктуре есть чем её выполнить;
- `tactics[].gaps` — сколько таких техник в тактике;
- `tactics[].blind` — в тактике есть техники и ни одна не закрыта: целый шаг
  атаки проходит незамеченным;
- `tactics[].observable: false` — разведка и подготовка ресурсов, которых
  сенсоры не видят по своей природе; требовать правил на них нельзя.

`GET /technique/{id}` — то же по одной технике плюс подробности:

```
technique_id, name, name_ru, description, description_ru, tactics[],
is_subtechnique, parent_id, covered, gap, ru
subtechniques[]  {technique_id, name, name_ru, covered, level,
                  actor_groups, sightings, ru}
layers{}         как в матрице, но с items[]:
                 {count, status, items: [{title, subtitle, href}]}  ≤ 20
ru_procedures[]  {technique_id, procedure, command_line, actors[],
                  malware[], tools[]}                              ≤ 20
```

`id` может быть подтехникой; слои читаются по родителю. Подтехники
сортируются не по номеру, а по применяемости здесь, затем по мировой:
человек уточняет разметку ради своей инфраструктуры. `items[].href` ведёт
внутрь модуля-владельца (`/siem/snapshots/{id}/rules?group=`,
`/vm/vulns?host=&cve=`, `/ad/domains/{id}/findings?check=`).

`GET /chains` — цепочки реальных кампаний ATT&CK и наши пробелы в них.
Шаги идут в порядке тактик матрицы. «Наши» техники — покрытые слоями
`coverage`; `exposed` — отсортированный список техник с экспозицией, чтобы
на экране отличить непокрытый шаг от непокрытого шага, который есть чем
пройти. `latest_seen` — дата самой свежей кампании: данные MITRE отстают,
и об этом надо сказать, а не выдавать их за оперативные.

```
items[]  {id, name, first_seen, last_seen, technique_count,
          uncovered_count, blind_steps,
          steps: [{tactic, blind, observable, total, covered,
                   uncovered: [{technique_id, name, ru}] ≤ 12}]}
```

## База знаний

```
GET /techniques?q&limit≤500(50)   {total, items[]}   справочник для разметки
```

Обновление матрицы и её перевод переехали в общие настройки —
`/api/settings/attack/*`: матрица общая для всех модулей, и менять её
вправе администратор, а не тот, кто первым до неё дошёл. Состав ручек
и формат ответов — в `docs/api-contract.md`, раздел «Обновление матрицы
ATT&CK».

## РФ TTP

Слой применяемости техник здесь. Загружает его человек своим файлом: это
чужая аналитика, а не открытые данные MITRE, и в образ она не вкладывается.
Загрузка заменяет прежнюю целиком — выгрузка это один документ на дату.

```
POST   /ru-ttp  multipart file   {rows, techniques, without_technique, moved,
                                  unknown[], columns{}, attack_version} |
                                  422 файл пуст | 422 нет ни строки с техникой
GET    /ru-ttp?limit≤500(50)     {source, attack_version, counts, ru_only[],
                                  world_only[], unknown[]}
DELETE /ru-ttp                   204   разметки и мировых данных не касается
```

`counts` — четыре состояния, а не два флага. «Только мир» не значит «здесь
не применяют», «только здесь» не значит «в мире не применяют»: и то и другое
означает лишь, что источник об этом не отчитывался. Ценность в двух списках
`ru_only` и `world_only` — мировая статистика занижает первый и завышает
второй.

## Задачи

```
GET  /jobs?limit≤200(50)   идущие сверху, затем последние
GET  /jobs/{id}            {id, kind, stage, status, progress, processed, total,
                            message, error, cancel_requested, started_at,
                            finished_at, started_by}
```

`kind`: `translate`, `download`. Задания запускаются в общих настройках, и
отменяет их администратор там же: `POST /api/settings/attack/jobs/{id}/cancel`
(204 | 404 | 409 уже завершена).

## Слои

Матрица говорит о технике, а не о правиле, узле или уязвимости. Поэтому
`attack` не читает чужие таблицы: каждый модуль отдаёт своё
«технику → ячейка» через реестр `api/modules/attack/layers.py`. Направление
зависимостей одно: модули знают про `attack`, `attack` про модули — нет.

```python
@dataclass(frozen=True)
class LayerItem:
    title: str      # «dc01: CVE-2024-1234», «svc_mpuser»
    subtitle: str   # «риск 82 · T1190 · DMZ», «Kerberoast · high · test.internal»
    href: str       # ссылка внутрь модуля

@dataclass(frozen=True)
class LayerCell:
    count: int                          # главное число ячейки
    status: str | None = None           # только для покрытия: confirmed | suggested
    items: tuple[LayerItem, ...] = ()    # ≤ MAX_ITEMS (20), для карточки техники

@dataclass(frozen=True)
class LayerResult:
    cells: dict[str, LayerCell]              # ключ — РОДИТЕЛЬСКАЯ техника
    technique_ids: frozenset[str] = frozenset()   # полные id, включая подтехники
    note: str | None = None                  # подпись слоя на экране
    available: bool = True

@dataclass(frozen=True)
class Layer:
    id: str                                  # siem | vm | ad
    title: str
    kind: Literal["coverage", "exposure"]
    unit: tuple[str, str, str]               # («хост», «хоста», «хостов»)
    build: Callable[[Session], LayerResult]
```

Два ключа, а не один, — намеренно. `cells` ключуется родителем
(`parent_of("T1558.003") == "T1558"`), потому что матрица показывает
родителей: человек, уточнивший разметку до подтехники, закрыл технику
точнее, а не перестал её закрывать. `technique_ids` хранит полные
идентификаторы — по ним считаются цепочки и признак «закрыта именно
подтехника».

`kind` решает, во что превращается ячейка: `coverage` даёт `covered`
(при `status` из `confirmed | suggested`), `exposure` даёт `gap` там, где
покрытия нет.

`collect(db)` строит все слои; упавший помечается `available: false` с
текстом ошибки, остальные не страдают — один сломанный модуль не роняет
матрицу.

### Как добавить слой новому модулю

1. `<module>/services/attack_layer.py`: функция `build(db) -> LayerResult`
   и константа `LAYER = Layer(id=…, title=…, kind=…, unit=…, build=build)`.
2. В `<module>/__init__.py` — `register_layer(LAYER)` после сборки роутера.
   `api/modules/__init__.py` импортирует все модули, поэтому к первому
   запросу реестр заполнен; ни матрицу, ни фронт править не нужно —
   слой сам появится в `layers[]` и в ячейках. Счётчик незнакомого фронту
   слоя матрица красит нейтральным тоном (`LAYER_TONE` в `MatrixPage.tsx`
   отдаёт `text-text-secondary` всему, чего в нём нет), так что свой цвет
   ему заводят, когда захотят, а не чтобы он заработал.
3. Ячейки — по `parent_of(technique_id)`; в `technique_ids` кладите полные
   идентификаторы.
4. `items` — не больше `MAX_ITEMS`, и это должны быть худшие: в карточку
   помещается двадцать строк. `href` ведёт на экран своего модуля с уже
   наложенным фильтром — человек пришёл разбираться, а не искать заново.
5. Данных нет — `LayerResult(cells={}, note="…", available=False)` с
   человеческим объяснением («нет снапшотов AD», «выгрузка VM не
   загружена»). Пусто при живых данных — это ответ «ничего не нашлось»,
   и слой остаётся доступным: `note` тогда говорит об условии
   («риск ≥ 40»), а не об отсутствии.
6. Если расчёт тяжёлый — кэшируйте в `app_setting['<module>.attack_layer']`
   и пересчитывайте там же, где меняются исходные данные (как VM: импорт,
   пересчёт риска, замена справочника, смена порога).

Экспозицией считайте то, что на экранах модуля показано как незакрытое:
принятое как норму или в allowlist экспозицией быть перестаёт — иначе
матрица спорила бы с решением, которое человек уже принял.

### Действующие слои

| Слой | Вид | Единица | Что считает |
|---|---|---|---|
| `siem` | coverage | группы правил | разметка правил последнего снапшота; `status` — сильнейшее состояние среди назвавших технику правил |
| `vm` | exposure | хосты | пары хост–CVE с `risk ≥ vm.attack_min_risk` (по умолчанию 40): техника из справочника `attack` (CTID), иначе правило по вектору CVSS |
| `ad` | exposure | находки | находки последних снапшотов доменов без allowlist и без вердикта; техники берутся из `CheckSpec.techniques` |

## Что осталось в SIEM

Всё про разметку правил: `/api/siem/attack/{coverage,groups,group,run,confirm}`,
эталон `/api/siem/attack/reference*` и экспорт покрытия в Navigator
`/api/siem/attack/layer/{snapshot_id}`. Матрица, карточка техники, цепочки,
справочник техник и РФ TTP — здесь, под `/api/attack`; обновление
матрицы и перевод — в общих настройках, под `/api/settings/attack`.
