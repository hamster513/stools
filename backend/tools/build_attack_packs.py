"""Сборка паков распространённости из исходных данных MITRE и CTID.

Запускается вручную при обновлении матрицы, а не при старте сервиса:
результат вкладывается в образ, чтобы всё работало при отключённой сети.

    python backend/tools/build_attack_packs.py enterprise-attack.json [sightings.csv]

Паки лежат отдельно от `attack_techniques.json` намеренно. По хешу того
файла определяется обновление софта, и его смена перекрывает матрицу,
загруженную заказчиком через интерфейс. Дописывать паки туда значило бы
затирать чужую работу при каждой пересборке статистики.
"""
from __future__ import annotations

import ast
import csv
import json
import sys
from collections import Counter, defaultdict
from pathlib import Path
from typing import Any

OUT = Path(__file__).resolve().parents[1] / "kbaudit" / "attack"
MITRE_SOURCE = "mitre-attack"


def external_id(obj: dict[str, Any]) -> str | None:
    for ref in obj.get("external_references") or []:
        if isinstance(ref, dict) and ref.get("source_name") == MITRE_SOURCE:
            return ref.get("external_id")
    return None


def build_revoked(objects: list[dict[str, Any]]) -> dict[str, str]:
    """Карта «отозванная техника → её замена».

    MITRE переносит техники сама и оставляет указатель. Без этой карты
    подтверждённая человеком разметка при обновлении матрицы превращается
    в «техника пропала, разбирайтесь», хотя разбираться не в чем.
    """
    by_id = {o["id"]: o for o in objects if "id" in o}
    out: dict[str, str] = {}
    for rel in objects:
        if rel.get("type") != "relationship" or rel.get("relationship_type") != "revoked-by":
            continue
        old, new = by_id.get(rel.get("source_ref", "")), by_id.get(rel.get("target_ref", ""))
        if not old or not new or old.get("type") != "attack-pattern":
            continue
        old_id, new_id = external_id(old), external_id(new)
        if old_id and new_id:
            out[old_id] = new_id
    return out


def resolve(technique_id: str, revoked: dict[str, str], live: set[str]) -> str | None:
    """Идентификатор в терминах действующей матрицы.

    Цепочка переносов разматывается: техника могла переезжать дважды.
    Ограничение на длину — защита от цикла в чужих данных, а не от
    ожидаемой глубины: реальные цепочки короче трёх шагов.
    """
    seen = set()
    current = technique_id
    for _ in range(8):
        if current in live:
            return current
        if current in seen:
            return None
        seen.add(current)
        nxt = revoked.get(current)
        if nxt is None:
            return None
        current = nxt
    return None


def build_prevalence(objects: list[dict[str, Any]], revoked: dict[str, str], live: set[str]) -> dict:
    """Сколько группировок и кампаний применяют технику.

    Техники берутся и напрямую, и через ПО группировки: связь
    «группировка → троян → техника» описывает её арсенал не хуже прямой,
    а в данных MITRE встречается чаще.
    """
    by_id = {o["id"]: o for o in objects if "id" in o}
    patterns = {
        o["id"]: external_id(o)
        for o in objects
        if o.get("type") == "attack-pattern"
        and not o.get("revoked")
        and not o.get("x_mitre_deprecated")
    }
    uses: dict[str, set[str]] = defaultdict(set)
    software: dict[str, set[str]] = defaultdict(set)
    for rel in objects:
        if rel.get("type") != "relationship" or rel.get("relationship_type") != "uses":
            continue
        source, target = rel.get("source_ref", ""), rel.get("target_ref", "")
        if target in patterns:
            uses[source].add(patterns[target])
        if by_id.get(target, {}).get("type") in ("malware", "tool"):
            software[source].add(target)

    def techniques_of(actor: dict[str, Any]) -> set[str]:
        found = set(uses[actor["id"]])
        for tool in software[actor["id"]]:
            found |= uses[tool]
        return {t for t in (resolve(x, revoked, live) for x in found) if t}

    def alive(kind: str) -> list[dict[str, Any]]:
        return [
            o
            for o in objects
            if o.get("type") == kind and not o.get("revoked") and not o.get("x_mitre_deprecated")
        ]

    groups: Counter[str] = Counter()
    for actor in alive("intrusion-set"):
        groups.update(techniques_of(actor))

    campaigns: Counter[str] = Counter()
    last_seen: dict[str, str] = {}
    for actor in alive("campaign"):
        year = (actor.get("last_seen") or "")[:4]
        for technique in techniques_of(actor):
            campaigns[technique] += 1
            if year.isdigit() and year > last_seen.get(technique, ""):
                last_seen[technique] = year

    # Счётчики по родительским техникам считаются отдельно, а не суммой
    # по подтехникам: группировка, применяющая три подтехники одного
    # семейства, — по-прежнему одна группировка. Сумма дала бы у T1059
    # пять сотен группировок при ста семидесяти шести существующих.
    def parent(technique_id: str) -> str:
        return technique_id.split(".")[0]

    parent_groups: Counter[str] = Counter()
    for actor in alive("intrusion-set"):
        parent_groups.update({parent(t) for t in techniques_of(actor)})
    parent_campaigns: Counter[str] = Counter()
    for actor in alive("campaign"):
        parent_campaigns.update({parent(t) for t in techniques_of(actor)})

    ids = sorted(set(groups) | set(campaigns))
    return {
        "source": "mitre-attack",
        "kind": "prevalence",
        "techniques": [
            {
                "id": t,
                "groups": groups.get(t, 0),
                "campaigns": campaigns.get(t, 0),
                "last_seen": last_seen.get(t),
            }
            for t in ids
        ],
        "parents": [
            {"id": t, "groups": parent_groups.get(t, 0), "campaigns": parent_campaigns.get(t, 0)}
            for t in sorted(set(parent_groups) | set(parent_campaigns))
        ],
    }


def build_campaigns(objects: list[dict[str, Any]], revoked: dict[str, str], live: set[str]) -> dict:
    """Кампании ATT&CK с их техниками — цепочки, пройденные в жизни.

    Кампания отличается от группировки датами: «реализовано ранее» —
    это про кампанию. Техники берутся и через ПО кампании: связь
    «кампания → троян → техника» описывает шаг не хуже прямой.

    Порядок техник не хранится: в ATT&CK его нет. Цепочка выстраивается
    при показе по порядку тактик — он задан матрицей и несёт смысл
    последовательности шагов атаки.
    """
    by_id = {o["id"]: o for o in objects if "id" in o}
    patterns = {
        o["id"]: external_id(o)
        for o in objects
        if o.get("type") == "attack-pattern"
        and not o.get("revoked")
        and not o.get("x_mitre_deprecated")
    }
    uses: dict[str, set[str]] = defaultdict(set)
    software: dict[str, set[str]] = defaultdict(set)
    for rel in objects:
        if rel.get("type") != "relationship" or rel.get("relationship_type") != "uses":
            continue
        source, target = rel.get("source_ref", ""), rel.get("target_ref", "")
        if target in patterns:
            uses[source].add(patterns[target])
        if by_id.get(target, {}).get("type") in ("malware", "tool"):
            software[source].add(target)

    out: list[dict[str, Any]] = []
    for campaign in objects:
        if campaign.get("type") != "campaign":
            continue
        if campaign.get("revoked") or campaign.get("x_mitre_deprecated"):
            continue
        found = set(uses[campaign["id"]])
        for tool in software[campaign["id"]]:
            found |= uses[tool]
        techniques = sorted({t for t in (resolve(x, revoked, live) for x in found) if t})
        if len(techniques) < 3:
            # Две техники — не цепочка. Показывать такое значит выдавать
            # обрывок отчёта за путь атаки.
            continue
        out.append(
            {
                "id": external_id(campaign) or campaign["id"],
                "name": campaign.get("name") or "",
                "first_seen": (campaign.get("first_seen") or "")[:10] or None,
                "last_seen": (campaign.get("last_seen") or "")[:10] or None,
                "techniques": techniques,
            }
        )
    out.sort(key=lambda c: (c["last_seen"] or "", c["id"]), reverse=True)
    return {"source": "mitre-attack", "kind": "campaigns", "campaigns": out}


def build_sightings(path: Path, revoked: dict[str, str], live: set[str]) -> dict:
    """Телеметрия CTID Sightings, приведённая к действующей матрице.

    Датасет собран на ATT&CK около 10-й версии, поэтому без переноса
    через `revoked-by` теряется 3.4% наблюдений, а с ним — 0.1%.
    """
    counts: Counter[str] = Counter()
    dropped = 0
    with path.open(encoding="utf-8-sig") as handle:
        for row in csv.DictReader(handle):
            try:
                ids = ast.literal_eval(row["tid"])
            except (ValueError, SyntaxError):
                continue
            for raw in ids:
                resolved = resolve(raw, revoked, live)
                if resolved is None:
                    dropped += 1
                else:
                    counts[resolved] += 1
    return {
        "source": "ctid-sightings-v2",
        "kind": "sightings",
        # Окно наблюдения по заявлению CTID. В самом файле есть записи и вне
        # него — данные о них авторы не подтверждают, но и не помечают.
        "window": "2021-08..2023-09",
        "dropped": dropped,
        "techniques": [{"id": t, "sightings": n} for t, n in sorted(counts.items())],
    }


def main() -> int:
    if len(sys.argv) < 2:
        print(__doc__)
        return 2
    stix = json.loads(Path(sys.argv[1]).read_text(encoding="utf-8"))
    objects = [o for o in stix.get("objects") or [] if isinstance(o, dict)]
    live = {t["technique_id"] for t in json.loads((OUT / "attack_techniques.json").read_text())["techniques"]}

    revoked = build_revoked(objects)
    write(OUT / "attack_revoked.json", {"source": "mitre-attack", "replaced_by": revoked})
    print(f"attack_revoked.json    переносов: {len(revoked)}")

    prevalence = build_prevalence(objects, revoked, live)
    write(OUT / "attack_prevalence.json", prevalence)
    print(f"attack_prevalence.json техник: {len(prevalence['techniques'])}")

    campaigns = build_campaigns(objects, revoked, live)
    write(OUT / "attack_campaigns.json", campaigns)
    print(
        f"attack_campaigns.json кампаний: {len(campaigns['campaigns'])}, "
        f"связей: {sum(len(c['techniques']) for c in campaigns['campaigns'])}"
    )

    if len(sys.argv) > 2:
        sightings = build_sightings(Path(sys.argv[2]), revoked, live)
        write(OUT / "attack_sightings.json", sightings)
        print(
            f"attack_sightings.json  техник: {len(sightings['techniques'])}, "
            f"потеряно упоминаний: {sightings['dropped']}"
        )
    return 0


def write(path: Path, payload: dict) -> None:
    path.write_text(json.dumps(payload, ensure_ascii=False, separators=(",", ":")), encoding="utf-8")


if __name__ == "__main__":
    raise SystemExit(main())
