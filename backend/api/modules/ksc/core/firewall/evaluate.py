"""Вердикт сетевого экрана хоста для пакета (спека §4.2, §4.4, §4.5): состояние экрана, пакетные правила (первое
совпавшее решает), ответный пакет (только после разрешения правилом уровня пакета, не потока), слой правил программ;
ветвление на неопределённостях.

Точки ветвления по порядку (Ruling 2, R-A): способ наложения профиля на список политики («дополняет» — `merge`,
«заменяет» — `replace`; только в режиме `auto` и только если у хоста есть профили с замком), активация каждого профиля
из `packet_undetermined` (активен / не активен), каждое правило «возможно подошло», до которого дошёл обход (подошло /
не подошло). Обход в глубину; на одном пути не больше `MAX_MAYBES` точек «возможно», всего не больше `max_branches`
ветвей — дальше путь кончается вердиктом «не определено» с `NOTE_TOO_MANY`.

`depends_on` — точки, у которых множества вердиктов двух поддеревьев различаются или хотя бы одно поддерево неоднородно
(с запасом: внешняя точка попадает в список, даже если обе её ветви расходятся одинаково, — иначе при расхождении на
двух уровнях внешняя точка терялась бы). Порядок — прямой, как точки встречаются при обходе (модель → профили →
правила). Листья-обрывы по `max_branches` в сравнении не участвуют: их вердикт — следствие предела, а не допущения;
о пределе говорит оговорка `NOTE_TOO_MANY`.
Без БД; `HostFirewall` собирает `view.host_firewall`.
"""
from __future__ import annotations

from collections.abc import Callable
from dataclasses import dataclass, field, replace
from typing import Any

from api.modules.ksc.core.firewall.match import RuleMatch, Tri, match_rule, zone_of
from api.modules.ksc.core.firewall.model import (
    HostFirewall,
    Packet,
    Protocol,
    RuleView,
    SourceSet,
    Verdict,
)

ALLOW, DENY, BY_APP = "разрешить", "запретить", "по правилам программ"
#: Точек «возможно подошло» на одном пути не больше (спека §4.4).
MAX_MAYBES = 4
#: Направления «(поток)»: в ответном пакете не участвуют (дополнение к §4.3).
_STREAM = (3, 4)
_NO_REPLY = (Protocol.ICMP, Protocol.ICMPV6)
_MODES = ("auto", "merge", "replace")

NOTE_TOO_MANY = "слишком много неопределённостей, уточните адрес или обновите выгрузку"
NOTE_HIPS_OFF = "правила программ не действуют (HIPS выключен); действие по умолчанию неизвестно"
NOTE_HIPS_NOTIFY = "HIPS в режиме „только уведомлять“"
NOTE_COMPONENT_STOPPED = "компонент Сетевой экран на хосте не запущен"
NOTE_COMPONENT_UNKNOWN = "статус компонента Сетевой экран на хосте неизвестен"
NOTE_FIREWALL_OFF = "сетевой экран выключен в действующих настройках"
NOTE_FIREWALL_UNKNOWN = "состояние сетевого экрана в выгрузке неизвестно"
NOTE_NOTIFY_ONLY = "режим „только уведомлять“: блокировки не будет"
NOTE_REPLY_APP = "ответный пакет не подошёл под разрешающее пакетное правило: решают правила программ"
NOTE_STREAM_ALLOW = "правило потока разрешает соединение целиком"
ASSUME_MERGE = "профиль дополняет список политики"
ASSUME_REPLACE = "профиль заменяет список политики"
POINT_MODEL = "способ наложения профиля на список политики"


def point_profile(name: str) -> str:
    return f"активация профиля „{name}“"


def note_unknown_action(rule: RuleView) -> str:
    return f"действие правила №{rule.position} «{rule.action}» не распознано"


def note_app_undetermined(name: str) -> str:
    return f"список правил программ может меняться профилем „{name}“ (активация не определена)"


@dataclass(frozen=True)
class Step:
    match: RuleMatch
    #: hit — решило (в ветви «подошло» и у правила «возможно»); no; maybe — «возможно», в этой ветви не подошло;
    #: disabled; skipped — правило потока в ответном пакете; not_checked — после решающего.
    status: str


@dataclass(frozen=True)
class Branch:
    #: Тексты допущений этой ветви; пусто — безусловная.
    assumptions: tuple[str, ...]
    verdict: Verdict
    decided_by: RuleView | None
    #: packet | reply | app | state
    layer: str
    steps: tuple[Step, ...]
    reply_steps: tuple[Step, ...]
    app_candidates: tuple[RuleView, ...]
    #: (имя группы доверия, allow для зоны назначения; None — правила нет или зона неизвестна без правила «любая сеть»).
    trust_groups: tuple[tuple[str, bool | None], ...]
    #: Пометка пути: «слишком много неопределённостей», HIPS выключен, ответный пакет к правилам программ.
    note: str = ""


@dataclass(frozen=True)
class SideResult:
    verdict: Verdict
    depends_on: tuple[str, ...]
    branches: tuple[Branch, ...]
    #: "" | "notify_only"
    mode: str
    notes: tuple[str, ...]
    #: «политика „…“», «профиль „…“» — источники, чьи правила участвовали хотя бы в одной ветви.
    effective_sources: tuple[str, ...]


def _sources(fw: HostFirewall, model: str, layer: str, chosen: tuple[str, ...]) -> tuple[SourceSet, ...]:
    """`merge` — политика, затем профили по приоритету; `replace` — профиль с наивысшим приоритетом, у которого есть
    правила, иначе политика. Профили — активные с замком и выбранные из неопределённых."""
    policy, active, maybe = (fw.packet, fw.packet_profiles, fw.packet_undetermined) if layer == "packet" else (fw.app, fw.app_profiles, fw.app_undetermined)
    own = (policy,) if policy is not None else ()
    profiles = sorted((*active, *(s for s in maybe if s.profile in chosen)), key=lambda s: s.priority if s.priority is not None else 1 << 31)
    if model == "merge":
        return own + tuple(profiles)
    if model == "replace":
        best = next((s for s in profiles if s.rules), None)
        return (best,) if best is not None else own
    raise ValueError(f"неизвестная модель наложения профиля: {model}")


def effective_rules(fw: HostFirewall, model: str, *, with_undetermined: tuple[str, ...] = (),
                    layer: str = "packet") -> tuple[RuleView, ...]:
    """Действующий список правил слоя (`packet` | `app`) по модели наложения `merge` | `replace`; `with_undetermined` —
    имена профилей с неопределённой активацией, которые считаются активными. Внутри источника — по позиции."""
    return tuple(r for s in _sources(fw, model, layer, with_undetermined) for r in sorted(s.rules, key=lambda r: r.position))


def _source_name(fw: HostFirewall, s: SourceSet) -> str:
    return f"профиль „{s.profile}“" if s.profile else f"политика „{fw.policy_name}“"


@dataclass(frozen=True)
class _Path:
    assumptions: tuple[str, ...] = ()
    model: str = "merge"
    chosen: tuple[str, ...] = ()
    maybes: int = 0
    #: Решения по «возможно» на этом пути: (id правила, допущение) → подошло; в ответном прогоне не ветвятся заново.
    resolved: tuple[tuple[tuple[int, str], bool], ...] = ()
    #: Шаги и решающее правило первого пакета — во время ответного прогона.
    first: tuple[Step, ...] = ()
    first_rule: RuleView | None = None

    def assume(self, text: str, **over: Any) -> _Path:
        return replace(self, assumptions=(*self.assumptions, text), **over)


@dataclass
class _Ctx:
    fw: HostFirewall
    packet: Packet
    max_branches: int
    trust_groups: tuple[tuple[str, bool | None], ...]
    #: Открытые (ещё без листа) пути и выпущенные листья — для предела `max_branches`.
    open: int = 1
    emitted: int = 0
    #: Точки ветвления в прямом порядке обхода и те из них, от которых зависит вердикт.
    order: list[str] = field(default_factory=list)
    points: set[str] = field(default_factory=set)
    #: id листьев-обрывов по `max_branches`.
    budget_caps: set[int] = field(default_factory=set)
    sources: list[str] = field(default_factory=list)
    notes: list[str] = field(default_factory=list)
    _matches: dict[tuple[int, bool], RuleMatch] = field(default_factory=dict)

    def match(self, rule: RuleView, reply: bool) -> RuleMatch:
        key = (id(rule), reply)
        if key not in self._matches:
            self._matches[key] = match_rule(rule, self.packet, self.fw.zones, self.fw.host_ip, reply=reply)
        return self._matches[key]

    def rules(self, path: _Path, layer: str) -> tuple[RuleView, ...]:
        for s in _sources(self.fw, path.model, layer, path.chosen):
            if (name := _source_name(self.fw, s)) not in self.sources:
                self.sources.append(name)
        return effective_rules(self.fw, path.model, with_undetermined=path.chosen, layer=layer)

    def can_split(self) -> bool:
        return self.emitted + self.open + 1 <= self.max_branches

    def _verdicts(self, branches: list[Branch]) -> set[Verdict]:
        return {x.verdict for x in branches if id(x) not in self.budget_caps}

    def split(self, point: str, left: Callable[[], list[Branch]], right: Callable[[], list[Branch]]) -> list[Branch]:
        if point not in self.order:
            self.order.append(point)
        self.open += 1
        a, b = left(), right()
        va, vb = self._verdicts(a), self._verdicts(b)
        if (va and vb and va != vb) or len(va) > 1 or len(vb) > 1:
            self.points.add(point)
        return a + b

    def leaf(self, path: _Path, verdict: Verdict, decided_by: RuleView | None, layer: str, steps: tuple[Step, ...],
             reply_steps: tuple[Step, ...] = (), candidates: tuple[RuleView, ...] = (),
             trust: tuple[tuple[str, bool | None], ...] = (), notes: tuple[str, ...] = ()) -> list[Branch]:
        self.open -= 1
        self.emitted += 1
        notes = tuple(n for n in notes if n)
        self.notes += [n for n in notes if n not in self.notes]
        return [Branch(path.assumptions, verdict, decided_by, layer, steps, reply_steps, candidates, trust, "; ".join(notes))]

    def cap(self, path: _Path, reply: bool = False, steps: tuple[Step, ...] = (), *, budget: bool = True) -> list[Branch]:
        """Путь обрывается: неопределённостей больше предела; `budget` — предел `max_branches`, иначе `MAX_MAYBES`."""
        first, second = (path.first, steps) if reply else (steps, ())
        out = self.leaf(path, Verdict.UNDETERMINED, None, "reply" if reply else "packet", first, second, notes=(NOTE_TOO_MANY,))
        if budget:
            self.budget_caps.add(id(out[0]))
        return out


def _trust_groups(fw: HostFirewall, packet: Packet) -> tuple[tuple[str, bool | None], ...]:
    """`allow` правила доступа группы для зоны, иначе правила «любая сеть» (-1). Зона неизвестна — правило -1, только если
    ни одно правило группы не расходится с ним по `allow`, иначе None (без оптимистичного «да»).
    Зона — удалённого адреса пакета (у входящего — источника): правила доступа группы описывают удалённую сеть."""
    zone = zone_of(packet.remote_ip, fw.zones) if packet.remote_ip else None
    out: list[tuple[str, bool | None]] = []
    for g in fw.trust_groups:
        any_net = next((a for a in g.access if a.networks == -1), None)
        if zone is not None:
            found = next((a for a in g.access if a.networks == zone), None) or any_net
        else:
            found = any_net if any_net is not None and all(a.allow == any_net.allow for a in g.access) else None
        out.append((g.name, found.allow if found is not None else None))
    return tuple(out)


def _rest(ctx: _Ctx, rules: tuple[RuleView, ...], j: int, reply: bool) -> tuple[Step, ...]:
    """Правила после решающего — «не проверялось»; «почти подошло» у них не считается (спека §4.5)."""
    return tuple(Step(replace(ctx.match(r, reply), almost=None), "not_checked") for r in rules[j + 1:])


def _app(ctx: _Ctx, path: _Path, layer: str, decided_by: RuleView | None, steps: tuple[Step, ...],
         reply_steps: tuple[Step, ...] = (), note: str = "") -> list[Branch]:
    """Слой правил программ: программа неизвестна — вердикт «решают правила программ» с кандидатами (спека §4.2 п. 5)."""
    first, second = (path.first, steps) if layer == "reply" else (steps, reply_steps)
    if ctx.fw.hips_enabled is False:
        return ctx.leaf(path, Verdict.UNDETERMINED, decided_by, layer, first, second, notes=(note, NOTE_HIPS_OFF))
    rules = ctx.rules(path, "app")
    candidates = tuple(r for r in rules if ctx.match(r, False).result is not Tri.NO)
    notify = NOTE_HIPS_NOTIFY if ctx.fw.hips_notify_only else ""
    return ctx.leaf(path, Verdict.APP, decided_by, layer, first, second, candidates, ctx.trust_groups, (note, notify))


def _decide(ctx: _Ctx, path: _Path, rules: tuple[RuleView, ...], j: int, reply: bool, steps: tuple[Step, ...]) -> list[Branch]:
    """Правило `rules[j]` подошло (последний шаг в `steps`)."""
    rule, done = rules[j], steps + _rest(ctx, rules, j, reply)
    if rule.action == DENY:
        layer = "reply" if reply else "packet"
        return ctx.leaf(path, Verdict.DENY, rule, layer, path.first if reply else done, done if reply else ())
    if rule.action == BY_APP:
        return _app(ctx, path, "reply" if reply else "app", rule, done, note=NOTE_REPLY_APP if reply else "")
    if rule.action != ALLOW:
        first, second = (path.first, done) if reply else (done, ())
        return ctx.leaf(path, Verdict.UNDETERMINED, rule, "reply" if reply else "packet", first, second, notes=(note_unknown_action(rule),))
    if reply:
        return ctx.leaf(path, Verdict.ALLOW, path.first_rule, "packet", path.first, done)
    if rule.scope.direction in _STREAM:
        # Правила потока учитывают состояние соединения: ответный прогон не нужен (Ruling 9).
        return ctx.leaf(path, Verdict.ALLOW, rule, "packet", done, notes=(NOTE_STREAM_ALLOW,))
    if ctx.packet.protocol in _NO_REPLY:
        return ctx.leaf(path, Verdict.ALLOW, rule, "packet", done)
    return _walk(ctx, replace(path, first=done, first_rule=rule), rules, 0, True, ())


def _maybe(ctx: _Ctx, path: _Path, rules: tuple[RuleView, ...], j: int, reply: bool, steps: tuple[Step, ...],
           m: RuleMatch) -> list[Branch]:
    """Правило `rules[j]` «возможно подошло»: ветви «подошло» и «не подошло» либо обрыв по пределу."""
    if path.maybes >= MAX_MAYBES or not ctx.can_split():
        budget = path.maybes < MAX_MAYBES
        return ctx.cap(path, reply, steps + (Step(m, "maybe"),) + _rest(ctx, rules, j, reply), budget=budget)
    owner = f"профиля „{m.rule.profile}“" if m.rule.profile else "политики"
    key, label = (id(m.rule), m.assumption), f"{m.assumption}: правило №{m.rule.position} {owner}"
    yes = path.assume(f"{label} подошло", maybes=path.maybes + 1, resolved=(*path.resolved, (key, True)))
    no = path.assume(f"{label} не подошло", maybes=path.maybes + 1, resolved=(*path.resolved, (key, False)))
    return ctx.split(m.assumption,
                     lambda: _decide(ctx, yes, rules, j, reply, steps + (Step(m, "hit"),)),
                     lambda: _walk(ctx, no, rules, j + 1, reply, steps + (Step(m, "maybe"),)))


def _walk(ctx: _Ctx, path: _Path, rules: tuple[RuleView, ...], start: int, reply: bool, steps: tuple[Step, ...]) -> list[Branch]:
    """Обход списка с `start`: первое подошедшее решает; «возможно» — две ветви."""
    for j in range(start, len(rules)):
        rule = rules[j]
        m = ctx.match(rule, reply)
        if not rule.enabled:
            steps += (Step(m, "disabled"),)
            continue
        if reply and rule.scope.direction in _STREAM:
            steps += (Step(m, "skipped"),)
            continue
        if m.result is Tri.NO:
            steps += (Step(m, "no"),)
            continue
        if m.result is Tri.YES:
            return _decide(ctx, path, rules, j, reply, steps + (Step(m, "hit"),))
        key = (id(rule), m.assumption)
        known = dict(path.resolved).get(key)
        if known is not None:
            if known:
                return _decide(ctx, path, rules, j, reply, steps + (Step(m, "hit"),))
            steps += (Step(m, "maybe"),)
            continue
        return _maybe(ctx, path, rules, j, reply, steps, m)
    if reply:
        return _app(ctx, path, "reply", None, steps, note=NOTE_REPLY_APP)
    return _app(ctx, path, "app", None, steps)


def _profiles(ctx: _Ctx, path: _Path, names: tuple[str, ...]) -> list[Branch]:
    if not names:
        return _walk(ctx, path, ctx.rules(path, "packet"), 0, False, ())
    if not ctx.can_split():
        return ctx.cap(path)
    name, rest = names[0], names[1:]
    return ctx.split(point_profile(name),
                     lambda: _profiles(ctx, path.assume(f"профиль „{name}“ активен", chosen=(*path.chosen, name)), rest),
                     lambda: _profiles(ctx, path.assume(f"профиль „{name}“ не активен"), rest))


def _merge(branches: list[Branch]) -> Verdict:
    verdicts = {b.verdict for b in branches}
    return verdicts.pop() if len(verdicts) == 1 else Verdict.DEPENDS


def evaluate_side(fw: HostFirewall, packet: Packet, *, profile_mode: str = "auto", max_branches: int = 16) -> SideResult:
    """Вердикт стороны хоста. `profile_mode` — `auto` (обе модели наложения, ветвление), `merge` или `replace`."""
    if profile_mode not in _MODES:
        raise ValueError(f"неизвестный режим наложения профиля: {profile_mode}")
    notes = list(fw.notes)
    mode = "notify_only" if fw.notify_only else ""

    def state(note: str) -> SideResult:
        if note and note not in notes:
            notes.append(note)
        branch = Branch((), Verdict.NOT_APPLIED, None, "state", (), (), (), (), note)
        return SideResult(Verdict.NOT_APPLIED, (), (branch,), mode, tuple(notes), ())

    if fw.policy_id is None:
        return state("")
    if fw.component_running is False:
        return state(NOTE_COMPONENT_STOPPED)
    if fw.firewall_enabled is False:
        return state(NOTE_FIREWALL_OFF)
    notes += [n for n, on in ((NOTE_COMPONENT_UNKNOWN, fw.component_running is None), (NOTE_FIREWALL_UNKNOWN, fw.firewall_enabled is None),
                              (NOTE_NOTIFY_ONLY, bool(fw.notify_only))) if on]
    names = tuple(s.profile for s in fw.packet_undetermined)
    notes += [note_app_undetermined(s.profile) for s in fw.app_undetermined if s.profile not in names]

    ctx = _Ctx(fw, packet, max_branches, _trust_groups(fw, packet))
    overlay = fw.packet_profiles or fw.packet_undetermined or fw.app_profiles or fw.app_undetermined
    if profile_mode != "auto":
        branches = _profiles(ctx, _Path(model=profile_mode), names)
    elif not overlay:
        branches = _profiles(ctx, _Path(), names)
    elif not ctx.can_split():
        branches = ctx.cap(_Path())
    else:
        branches = ctx.split(POINT_MODEL,
                             lambda: _profiles(ctx, _Path(model="merge").assume(ASSUME_MERGE), names),
                             lambda: _profiles(ctx, _Path(model="replace").assume(ASSUME_REPLACE), names))
    notes += [n for n in ctx.notes if n not in notes]
    verdict = _merge(branches)
    depends = tuple(p for p in ctx.order if p in ctx.points) if verdict is Verdict.DEPENDS else ()
    return SideResult(verdict, depends, tuple(branches), mode, tuple(notes), tuple(ctx.sources))
