"""Группы как активы: личность группы (спека §3), встроенные субъекты, полный состав (§6) и предки. Без базы.

Личность — `group_key(...)`, строка уникального индекса `asset_group.group_key`:
- доменная — `d:<dns-домен>:<SID>`, без SID — `d:<dns-домен>:n:<имя>`. Пара с доменом, а не один SID:
  встроенные группы Builtin (`S-1-5-32-*`) есть в выгрузке каждого домена с одним и тем же SID;
- локальная — `l:<asset_id хоста>:<SID>`, без SID — `l:<asset_id хоста>:n:<имя>`.
SID — в верхнем регистре (VM отдаёт всё в нижнем), домен и имя — в нижнем.

Встроенный субъект (`well_known`) — неявная группа токена Windows (Everyone, Authenticated Users,
SYSTEM, NT SERVICE\\…): правило `ad.core.gpo_rights._well_known`, в него входит и `S-1-5-80-*`.
Не раскрывается в пользователей; `well_known_text` — кого он означает.

Полный состав — `expand(root, edges)`: обход вниз в ширину по рёбрам `edges(group_id)` (прямой состав
группы из `asset_group_member`). Каждая группа раскрывается один раз, поэтому циклы и ромбы конечны.
Конечный участник (`Leaf`) один на ключ: пользователь — по `user_id`, компьютер — по `asset_id`, без
связи — по виду, SID и имени; встроенный субъект — по SID. У него `via` — группы кратчайшего пути от
корня (без корня, с последней группой перед участником) и `paths` — число различных путей; рёбра,
замыкающие цикл, в число путей не входят. Тупики (`dead_ends`): `unknown`, участник-группа без
`group_id` и участник-группа с `group_id`, у которой нет рёбер (нет в AD или пустая — пометку ставит
вызывающий по `in_ad`). Корень без участников тупиком не считается.

Предки — `ancestors(start, parents)`: все группы, куда входят стартовые прямо или через вложенность,
с кратчайшей цепочкой до каждой.
"""
from __future__ import annotations

from collections import deque
from collections.abc import Callable, Iterator
from dataclasses import dataclass, field

#: Пояснения к встроенным субъектам; `S-1-5-80-*` — отдельно, прочие — `WELL_KNOWN_DEFAULT`.
WELL_KNOWN_TEXT: dict[str, str] = {
    "S-1-1-0": "все, включая анонимных при старых настройках",
    "S-1-5-11": "все прошедшие проверку пользователи и компьютеры",
    "S-1-5-4": "все вошедшие интерактивно",
    "S-1-5-18": "сама система (учётка SYSTEM)",
    "S-1-5-19": "служебная учётка LOCAL SERVICE",
    "S-1-5-20": "служебная учётка NETWORK SERVICE",
    "S-1-5-17": "анонимный пользователь IIS (IUSR)",
}
WELL_KNOWN_SERVICE = "служебная учётка службы"
WELL_KNOWN_DEFAULT = "встроенный субъект Windows"
_NT_SERVICE = "S-1-5-80-"


def normalize_sid(value: str) -> str:
    return value.strip().upper()


def group_key(*, local: bool, domain: str, host_asset_id: int | None, sid: str, name: str) -> str:
    """Ключ личности группы (см. модуль). Локальная без хоста и группа без SID и имени — ошибка вызывающего."""
    sid = normalize_sid(sid)
    name = name.strip().lower()
    if local and host_asset_id is None:
        raise ValueError("локальной группе нужен хост")
    if not sid and not name:
        raise ValueError("у группы нет ни SID, ни имени")
    scope = f"l:{host_asset_id}" if local else f"d:{domain.strip().rstrip('.').lower()}"
    return f"{scope}:{sid}" if sid else f"{scope}:n:{name}"


def is_well_known(sid: str) -> bool:
    """S-1-1-*, S-1-2-*, S-1-3-*, S-1-5-<n> кроме доменных и машинных (21) и BUILTIN (32)."""
    parts = normalize_sid(sid).split("-")
    return len(parts) > 3 and (parts[2] in ("1", "2", "3") or (parts[2] == "5" and parts[3] not in ("21", "32")))


def well_known_text(sid: str) -> str:
    sid = normalize_sid(sid)
    if sid.startswith(_NT_SERVICE):
        return WELL_KNOWN_SERVICE
    return WELL_KNOWN_TEXT.get(sid, WELL_KNOWN_DEFAULT)


@dataclass(slots=True)
class Edge:
    """Прямой участник группы: `member_kind` user | group | computer | well_known | unknown и что удалось связать."""

    member_kind: str
    user_id: int | None
    group_id: int | None
    asset_id: int | None
    sid: str
    name: str
    primary: bool


@dataclass(slots=True)
class Leaf:
    """Участник полного состава: конечный, встроенный или тупик. `group_id` — у тупика-группы с записью."""

    kind: str
    user_id: int | None
    asset_id: int | None
    sid: str
    name: str
    via: list[int]
    paths: int
    group_id: int | None = None


@dataclass(slots=True)
class Expanded:
    leaves: list[Leaf] = field(default_factory=list)
    well_known: list[Leaf] = field(default_factory=list)
    dead_ends: list[Leaf] = field(default_factory=list)
    #: Пройденные группы, корень и тупики-группы с записью тоже.
    groups_seen: set[int] = field(default_factory=set)


def _leaf_key(e: Edge) -> tuple[object, ...]:
    if e.member_kind == "user" and e.user_id is not None:
        return ("user", e.user_id)
    if e.member_kind == "computer" and e.asset_id is not None:
        return ("computer", e.asset_id)
    if e.member_kind == "well_known" and e.sid:
        return ("well_known", e.sid)
    return (e.member_kind, e.sid, e.name.casefold())


def _path_counts(root: int, children: dict[int, dict[int, None]]) -> dict[int, int]:
    """Число путей от корня до каждой группы. Обход в глубину без рекурсии; ребро в группу, которая
    сейчас на стеке, замыкает цикл и отбрасывается, остальное — ациклический граф, где обратный
    порядок выхода из вершин топологический."""
    state = {root: 1}  # 1 — на стеке, 2 — пройдена
    order: list[int] = []
    dag: dict[int, list[int]] = {}
    stack: list[tuple[int, Iterator[int]]] = [(root, iter(children.get(root, ())))]
    while stack:
        node, rest = stack[-1]
        child = next(rest, None)
        if child is None:
            stack.pop()
            state[node] = 2
            order.append(node)
            continue
        if state.get(child) == 1:
            continue
        dag.setdefault(node, []).append(child)
        if child not in state:
            state[child] = 1
            stack.append((child, iter(children.get(child, ()))))
    counts = dict.fromkeys(order, 0)
    counts[root] = 1
    for node in reversed(order):
        for child in dag.get(node, ()):
            counts[child] += counts[node]
    return counts


def expand(root: int, edges: Callable[[int], list[Edge]]) -> Expanded:
    """Полный состав группы `root` (см. модуль). Порядок в каждом списке — по длине пути, затем по имени."""
    path_to: dict[int, list[int]] = {root: []}
    #: Ребро, по которому группу нашли впервые, — её SID и имя для тупика.
    found_by: dict[int, Edge] = {}
    children: dict[int, dict[int, None]] = {}
    nodes: dict[tuple[object, ...], tuple[str, Leaf]] = {}
    parents_of: dict[tuple[object, ...], dict[int, None]] = {}
    empty: list[int] = []
    queue = deque([root])
    while queue:
        gid = queue.popleft()
        members = edges(gid)
        if not members and gid != root:
            empty.append(gid)
        for e in members:
            if e.member_kind == "group" and e.group_id is not None:
                children.setdefault(gid, {})[e.group_id] = None
                if e.group_id not in path_to:
                    path_to[e.group_id] = [*path_to[gid], e.group_id]
                    found_by[e.group_id] = e
                    queue.append(e.group_id)
                continue
            key = _leaf_key(e)
            if key not in nodes:
                bucket = {"user": "leaves", "computer": "leaves", "well_known": "well_known"}.get(e.member_kind, "dead_ends")
                nodes[key] = (bucket, Leaf(e.member_kind, e.user_id, e.asset_id, e.sid, e.name, list(path_to[gid]), 0))
            parents_of.setdefault(key, {})[gid] = None

    counts = _path_counts(root, children)
    res = Expanded(groups_seen=set(path_to))
    for key, (bucket, leaf) in nodes.items():
        leaf.paths = sum(counts.get(gid, 0) for gid in parents_of[key])
        getattr(res, bucket).append(leaf)
    for gid in empty:
        e = found_by[gid]
        res.dead_ends.append(Leaf("group", None, None, e.sid, e.name, path_to[gid][:-1], counts.get(gid, 0), gid))
    for items in (res.leaves, res.well_known, res.dead_ends):
        items.sort(key=lambda x: (len(x.via), x.name.casefold(), x.sid))
    return res


def ancestors(start: set[int], parents: Callable[[int], list[int]]) -> dict[int, list[int]]:
    """Предок → кратчайшая цепочка: от стартовой группы (первой) до группы, что прямо входит в предка
    (последней), сам предок не входит. У прямого родителя старта `S` цепочка `[S]`. Стартовые группы в
    ответ не попадают, даже если цикл возвращается к ним."""
    chains: dict[int, list[int]] = {}
    seen = set(start)
    queue = deque((gid, [gid]) for gid in sorted(start))
    while queue:
        gid, chain = queue.popleft()
        for parent in parents(gid):
            if parent in seen:
                continue
            seen.add(parent)
            chains[parent] = chain
            queue.append((parent, [*chain, parent]))
    return chains
