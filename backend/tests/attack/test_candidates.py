"""Отбор кандидатов: детерминированная половина разметки.

Эмбеддер подставляется предсказуемый — отбор не должен зависеть ни от
весов модели, ни от сети, и проверяться должен так же.
"""
import json
from pathlib import Path

from kbaudit.attack.bundle import Technique, load_bundle
from kbaudit.attack.candidates import cosine, recall_at_k, select_candidates


def techniques() -> list[Technique]:
    return [
        Technique(technique_id="T1569", name="System Services", tactics=["execution"]),
        Technique(technique_id="T1053", name="Scheduled Task/Job", tactics=["execution"]),
        Technique(technique_id="T1110", name="Brute Force", tactics=["credential-access"]),
        Technique(technique_id="T1047", name="WMI", tactics=["execution"]),
    ]


#: Векторы заданы руками так, чтобы порядок близости был очевиден заранее.
VECTORS = {
    "T1569": [1.0, 0.0, 0.0],
    "T1053": [0.8, 0.6, 0.0],
    "T1110": [0.0, 0.0, 1.0],
    "T1047": [0.6, 0.8, 0.0],
}


def test_cosine_of_identical_vectors_is_one() -> None:
    assert cosine([1.0, 2.0, 3.0], [1.0, 2.0, 3.0]) == 1.0


def test_cosine_of_orthogonal_vectors_is_zero() -> None:
    assert cosine([1.0, 0.0], [0.0, 1.0]) == 0.0


def test_zero_vector_does_not_divide_by_zero() -> None:
    assert cosine([0.0, 0.0], [1.0, 1.0]) == 0.0


def test_candidates_are_sorted_by_similarity() -> None:
    got = select_candidates([1.0, 0.0, 0.0], techniques(), VECTORS, top_k=4)
    assert [c.technique_id for c in got] == ["T1569", "T1053", "T1047", "T1110"]


def test_top_k_truncates() -> None:
    got = select_candidates([1.0, 0.0, 0.0], techniques(), VECTORS, top_k=2)
    assert [c.technique_id for c in got] == ["T1569", "T1053"]


def test_technique_without_vector_is_skipped_not_fatal() -> None:
    """Бандл новее предрасчитанных векторов — отдаём неполный список,
    а не отказываемся работать."""
    partial = {k: v for k, v in VECTORS.items() if k != "T1047"}
    got = select_candidates([1.0, 0.0, 0.0], techniques(), partial, top_k=10)
    assert "T1047" not in {c.technique_id for c in got}
    assert len(got) == 3


def test_recall_counts_groups_where_the_answer_was_offered() -> None:
    selected = {
        "g1": select_candidates([1.0, 0.0, 0.0], techniques(), VECTORS, top_k=2),
        "g2": select_candidates([0.0, 0.0, 1.0], techniques(), VECTORS, top_k=2),
    }
    # g1 получила T1569 и T1053, g2 — T1110.
    assert recall_at_k(selected, {"g1": {"T1569"}, "g2": {"T1110"}}) == 1.0
    assert recall_at_k(selected, {"g1": {"T1047"}, "g2": {"T1110"}}) == 0.5
    assert recall_at_k(selected, {}) == 0.0


def test_recall_counts_a_hit_when_any_expected_technique_is_offered() -> None:
    """Группа правил законно соответствует нескольким техникам: Impacket —
    это и запуск через службы, и планировщик, и WMI. Достаточно, чтобы
    в кандидаты попала хоть одна из ожидаемых."""
    selected = {"g1": select_candidates([1.0, 0.0, 0.0], techniques(), VECTORS, top_k=2)}
    assert recall_at_k(selected, {"g1": {"T1047", "T1053"}}) == 1.0


def test_bundle_parses_stix_and_skips_deprecated(tmp_path: Path) -> None:
    raw = {
        "spec_version": "2.1",
        "objects": [
            {
                "type": "attack-pattern",
                "name": "System Services",
                "description": "Adversaries may abuse system services.",
                "external_references": [
                    {"source_name": "mitre-attack", "external_id": "T1569"}
                ],
                "kill_chain_phases": [
                    {"kill_chain_name": "mitre-attack", "phase_name": "execution"}
                ],
            },
            {
                "type": "attack-pattern",
                "name": "Service Execution",
                "description": "Adversaries may abuse the service control manager.",
                "x_mitre_is_subtechnique": True,
                "external_references": [
                    {"source_name": "mitre-attack", "external_id": "T1569.002"}
                ],
            },
            {
                "type": "attack-pattern",
                "name": "Устаревшая",
                "x_mitre_deprecated": True,
                "external_references": [
                    {"source_name": "mitre-attack", "external_id": "T9999"}
                ],
            },
            {"type": "intrusion-set", "name": "не техника"},
        ],
    }
    path = tmp_path / "attack.json"
    path.write_text(json.dumps(raw), encoding="utf-8")

    bundle = load_bundle(path)
    ids = {t.technique_id for t in bundle.techniques}
    assert ids == {"T1569", "T1569.002"}, "устаревшее и не-техники отбрасываются"
    assert [t.technique_id for t in bundle.parents_only()] == ["T1569"]
    assert [t.technique_id for t in bundle.children_of("T1569")] == ["T1569.002"]


def test_technique_embedding_text_leads_with_the_name(tmp_path: Path) -> None:
    t = Technique(
        technique_id="T1569",
        name="System Services",
        description="Длинное описание в несколько абзацев.",
        tactics=["execution"],
    )
    assert t.embedding_text.startswith("System Services")


def test_translation_is_applied_and_leads_the_embedding_text(tmp_path: Path) -> None:
    """Русский текст идёт первым, английский остаётся: часть сигнала —
    непереводимые имена вроде LSASS и svcctl, и они живут в оригинале."""
    from kbaudit.attack.bundle import AttackBundle, apply_translations

    bundle = AttackBundle(
        techniques=[
            Technique(technique_id="T1003", name="OS Credential Dumping", description="Adversaries may dump credentials."),
            Technique(technique_id="T1110", name="Brute Force"),
        ]
    )
    path = tmp_path / "ru.json"
    path.write_text(
        json.dumps(
            [{"id": "T1003", "name_ru": "Извлечение учётных данных", "description_ru": "Дамп памяти LSASS."}],
            ensure_ascii=False,
        ),
        encoding="utf-8",
    )

    apply_translations(bundle, path)
    by_id = bundle.by_id()
    assert by_id["T1003"].embedding_text.startswith("Извлечение учётных данных")
    assert "OS Credential Dumping" in by_id["T1003"].embedding_text
    assert by_id["T1110"].name_ru is None, "непереведённое остаётся английским"


def test_missing_translation_file_is_not_an_error(tmp_path: Path) -> None:
    from kbaudit.attack.bundle import AttackBundle, apply_translations

    bundle = AttackBundle(techniques=[Technique(technique_id="T1003", name="OS Credential Dumping")])
    apply_translations(bundle, tmp_path / "нет.json")
    assert bundle.by_id()["T1003"].name_ru is None


def test_bundle_tactic_set_is_pinned() -> None:
    """Состав тактик зафиксирован, потому что от него зависит интерфейс.

    Названия тактик по-русски живут во фронтенде
    (`frontend/src/api/types.ts`, ATTACK_TACTIC_LABELS), и связи между
    файлами нет. В версии 19.2 MITRE разделила «обход защиты» на
    Defense Impairment и Stealth — словарь названий об этом не узнал,
    и на экране две тактики показывались латиницей.

    Обновление бандла должно ронять этот тест, а не тихо портить экран.
    """
    from kbaudit.attack.bundle import load_default

    got = {t for technique in load_default().techniques for t in technique.tactics}
    assert got == {
        "collection",
        "command-and-control",
        "credential-access",
        "defense-impairment",
        "discovery",
        "execution",
        "exfiltration",
        "impact",
        "initial-access",
        "lateral-movement",
        "persistence",
        "privilege-escalation",
        "reconnaissance",
        "resource-development",
        "stealth",
    }, "состав тактик изменился — обновите ATTACK_TACTIC_LABELS во фронтенде"
