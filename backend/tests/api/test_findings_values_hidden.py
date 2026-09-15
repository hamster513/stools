"""GET /api/siem/findings не содержит значений находок (контракт, «Общие правила»).

Берёт настоящую находку, узнаёт её значение через /detail, и проверяет,
что этой строки нет нигде в сыром теле ответа списка — не только в поле
`value` (которого в схеме `FindingListItem` физически нет), а во всём
JSON, включая `body_excerpt`, который тоже может содержать значение.
"""
from __future__ import annotations

from fastapi.testclient import TestClient


def test_findings_list_never_leaks_the_value_shown_in_detail(
    auth_client: TestClient, snapshot_id: int
) -> None:
    listing = auth_client.get("/api/siem/findings", params={"snapshot_id": snapshot_id})
    assert listing.status_code == 200, listing.text
    items = listing.json()["items"]
    assert items, "у синтетической выгрузки должны быть находки — тест не о чем проверять"

    for item in items:
        assert "value" not in item, "FindingListItem не должен нести поле value вовсе"

    checked = 0
    for item in items:
        detail = auth_client.get(f"/api/siem/findings/{item['id']}/detail")
        assert detail.status_code == 200, detail.text
        value = detail.json()["value"]
        assert value, "находка без значения не годится для этой проверки"

        # Сырой текст ответа списка целиком — не только поля, которые мы
        # сами решили сериализовать в FindingListItem.
        assert value not in listing.text, (
            f"значение находки {item['id']!r} утекло в список: {value!r}"
        )
        checked += 1

    assert checked == len(items)


def test_network_shape_is_visible_even_when_the_class_hides_it(
    auth_client: TestClient, snapshot_id: int
) -> None:
    """Классы взаимоисключающи, и «дублирует список» перекрывает
    «IP / CIDR / FQDN»: продублированное значение — более тяжёлое
    замечание. Но тогда сетевое имя в интерфейсе не найти, и человек
    делает неверный вывод о числе адресов в правилах. На эталонной
    выгрузке их 585, а в классе видно 371.
    """
    body = auth_client.get(f"/api/siem/findings?snapshot_id={snapshot_id}").json()
    by_value = {f["field"]: f for f in body["items"]}
    # В фикстуре dst.ip == "10.20.30.40" — адрес, не попавший в список.
    assert by_value["dst.ip"]["shape"] == "ip"
    assert by_value["dst.ip"]["kind"] == 2

    # А это имя узла, продублированное в табличном списке: класс 1,
    # но форма всё равно видна.
    duplicated = next(f for f in body["items"] if f["kind"] == 1)
    assert "shape" in duplicated


def test_findings_can_be_filtered_by_shape(auth_client: TestClient, snapshot_id: int) -> None:
    """«Показать все сетевые имена» — вопрос, на который нельзя ответить
    фильтром по классу."""
    body = auth_client.get(f"/api/siem/findings?snapshot_id={snapshot_id}&shape=ip").json()
    assert body["total"] >= 1
    assert all(f["shape"] == "ip" for f in body["items"])


def test_shape_facet_counts_across_classes(auth_client: TestClient, snapshot_id: int) -> None:
    body = auth_client.get(f"/api/siem/findings?snapshot_id={snapshot_id}").json()
    facets = body["facets"]["shape"]
    # «plain» назван словом, а не пустой строкой: пустая строка в запросе
    # неотличима от «параметр не задан», и фильтр молча вернул бы всё.
    assert set(facets) == {"ip", "cidr", "fqdn", "plain"}
    assert facets["ip"] >= 1


def test_plain_shape_is_filterable(auth_client: TestClient, snapshot_id: int) -> None:
    """Фильтр «обычное значение» обязан работать, а не возвращать всё."""
    body = auth_client.get(f"/api/siem/findings?snapshot_id={snapshot_id}&shape=plain").json()
    assert body["total"] >= 1
    assert all(f["shape"] is None for f in body["items"])
    everything = auth_client.get(f"/api/siem/findings?snapshot_id={snapshot_id}").json()
    assert body["total"] < everything["total"]
