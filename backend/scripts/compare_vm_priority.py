"""Offline comparison: PYTHONPATH=backend python backend/scripts/compare_vm_priority.py SNAPSHOT OUTPUT_DIR."""
from __future__ import annotations

import argparse
import csv
import hashlib
import html
import json
import time
from datetime import datetime
from pathlib import Path
from zoneinfo import ZoneInfo

from api.modules.vm.services.priority_comparison import compare_snapshot

REASONS = {
    "epss_unknown": "EPSS отсутствует: начальная подстановка", "epss_band": "Диапазон EPSS",
    "public_exploit": "Опубликованный эксплойт", "ready_metasploit": "Metasploit good/great/excellent",
    "recorded_exploitation_kev": "Эксплуатация зарегистрирована в KEV", "cvss_unknown": "CVSS отсутствует: подстановка",
    "cvss": "CVSS", "network_zone_unknown": "Сетевой вектор, зона не размечена",
    "network_external_zone": "Сетевой вектор, внешняя зона", "network_internal_zone": "Сетевой вектор, внутренняя зона",
    "local_vector": "Локальный/физический вектор", "adjacent_vector": "Смежная сеть", "vector_unknown": "Вектор неизвестен",
    "criticality": "Критичность актива", "criticality_and_confidentiality": "Критичность и конфиденциальные данные",
}
LABELS = {"exploitation": "Эксплуатация", "severity": "Последствия", "exposure": "Доступность", "asset": "Значимость актива"}
MISSING = {"epss": "EPSS", "kev_catalog": "каталог KEV", "cvss": "CVSS", "exposure": "разметка зоны",
           "attack_vector": "вектор атаки", "criticality": "критичность", "confidentiality": "конфиденциальность"}
RULES = {"kev_minimum": "KEV", "kev_network_external_zone": "KEV + сетевой вектор + внешняя зона",
         "ready_exploit_critical_asset": "Готовый эксплойт + CVSS ≥9 + критичный актив"}


def csv_value(value):
    if isinstance(value, (list, tuple)):
        value = "; ".join(str(x) for x in value)
    if isinstance(value, str) and value.startswith(("=", "+", "-", "@")):
        return "'" + value
    return value


def write_csv(path, rows):
    fields = ["id", "old_rank", "new_rank", "rank_gain", "old_score", "new_score", "old_level", "new_level",
              "stored_score", "kev", "cvss", "epss", "affected_hosts", "affected_images", "identifiers",
              "exploitation", "severity", "exposure", "asset", "floor", "rules", "missing"]
    with path.open("w", encoding="utf-8-sig", newline="") as out:
        writer = csv.DictWriter(out, fieldnames=fields)
        writer.writeheader()
        for row in rows:
            data = {key: row.get(key) for key in fields}
            explanation = row["new_explanation"]
            data.update({key: explanation["blocks"][key]["points"] for key in LABELS})
            data.update(floor=explanation["floor"], rules=explanation["rules"], missing=explanation["missing"])
            writer.writerow({key: csv_value(value) for key, value in data.items()})


def write_html(path, result):
    esc = lambda value: html.escape(str(value))
    summary, coverage = result["summary"], result["coverage"]
    policy = result["policy"]
    new_thresholds = " / ".join(str(policy["levels"][key]) for key in ("medium", "high", "critical"))
    stamp = datetime.fromisoformat(result["meta"]["captured_at"]).astimezone(ZoneInfo("Europe/Moscow")).strftime("%d.%m.%Y %H:%M:%S МСК")
    old_limits = result["meta"]["weights"]["levels"]
    old_thresholds = " / ".join(str(old_limits[key]) for key in ("medium", "high", "critical"))
    old_boundary, new_boundary = summary["old_boundary"], summary["new_boundary"]
    boundary_text = (f"Старая модель: граница {old_boundary['score']} баллов, {old_boundary['strictly_above']} уязвимостей выше неё и {old_boundary['tie_size']} с равным пограничным баллом. "
                     f"Новая модель: граница {new_boundary['score']} баллов, {new_boundary['strictly_above']} выше неё и {new_boundary['tie_size']} с равным баллом.")
    rows = {row["id"]: row for row in result["old_top"] + result["new_top"]}
    table = []
    limit = summary["top_limit"]
    for row in sorted(rows.values(), key=lambda r: r["new_rank"]):
        explanation = row["new_explanation"]
        blocks = "".join(f'<li>{LABELS[key]}: <b>{block["points"]:g}/{block["maximum"]}</b> — {esc(REASONS.get(block["reason"], block["reason"]))}{" (подстановка)" if block["assumed"] else ""}</li>' for key, block in explanation["blocks"].items())
        rules = "; ".join(f'{RULES[rule]}: минимум {policy["floors"][rule]}' for rule in explanation["rules"]) or "не сработали"
        missing = ", ".join(MISSING[key] for key in explanation["missing"]) or "нет"
        old = row["old_explanation"]
        c = row["new_context"]
        kind = "хост" if c["kind"] == "host" else "образ"
        exposure = "неизвестная зона" if c["internet"] is None else "внешняя зона" if c["internet"] else "внутренняя зона"
        criticality = {"Critical": "критичная", "High": "высокая", "Medium": "средняя", "Low": "низкая"}.get(c["criticality"], "не задана")
        details = (f'<details><summary>Факторы и правила</summary><ul>{blocks}</ul>'
                   f'<p>Базовый балл: {explanation["base_score"]}; итог: {row["new_score"]}. Правила: {esc(rules)}.</p>'
                   f'<p>Нет данных: {esc(missing)}.</p><p>Контекст максимума: {kind}, критичность {criticality}, '
                   f'{exposure}. Исходный ID: {esc(c["identifier"])}.</p>'
                   f'<p>Старая формула: 100 × {old["likelihood"]:.5g} × {old["cvss_normalized"]:.3g} × '
                   f'{old["reach"]:.3g} × {old["asset_value"]:.3g} → {row["old_score"]}.</p></details>')
        table.append(f'<tr data-old="{row["old_rank"]}" data-new="{row["new_rank"]}"><td>{esc(row["id"])}</td>'
                     f'<td>{row["old_rank"]}</td><td>{row["new_rank"]}</td><td>{row["rank_gain"]:+}</td>'
                     f'<td>{row["old_score"]}</td><td><b>{row["new_score"]}</b></td><td>{"да" if row["kev"] else "нет"}</td>'
                     f'<td>{esc(row["cvss"])}</td><td>{esc(row["epss"])}</td><td>{row["affected_hosts"]} / {row["affected_images"]}</td><td>{details}</td></tr>')
    metrics = "".join(f'<tr><td>{label}</td><td>{summary["old_top_metrics"][key]}</td><td>{summary["new_top_metrics"][key]}</td></tr>' for key, label in (
        ("kev", "KEV в топе"), ("cvss_ge_9", "CVSS ≥9"), ("missing_epss", "Нет EPSS"),
        ("critical_assets", "Максимум на критичном активе"), ("known_external", "Максимум во внешней зоне"), ("unknown_exposure", "Зона максимума неизвестна")))
    levels = "".join(f'<tr><td>{level}</td><td>{summary["old_levels"].get(level,0)}</td><td>{summary["new_levels"].get(level,0)}</td></tr>' for level in ("critical", "high", "medium", "low"))
    refs = "".join(f'<li>{esc(r["name"])}: {esc(r["loaded_at"])}, записей {r["records"]}</li>' for r in result["meta"].get("references", []))
    body = '''<!doctype html><html lang="ru"><meta charset="utf-8"><meta name="viewport" content="width=device-width,initial-scale=1">
<title>Сравнение моделей приоритизации VM</title><style>
:root{color-scheme:dark}body{font:15px/1.5 system-ui,sans-serif;margin:0;background:#111827;color:#e5e7eb}main{max-width:1500px;margin:auto;padding:28px}h1{font-size:28px}h2{font-size:20px;margin-top:28px}.muted{color:#a5b4c8}.cards{display:flex;flex-wrap:wrap;gap:12px}.card{background:#1e293b;padding:16px 22px;border-radius:8px}.card b{display:block;font-size:25px;color:#5eead4}.grid{display:grid;grid-template-columns:repeat(auto-fit,minmax(310px,1fr));gap:20px}table{border-collapse:collapse;width:100%;background:#172033}th,td{text-align:left;padding:9px 11px;border-bottom:1px solid #334155;vertical-align:top}th{background:#263348;position:sticky;top:0}td:nth-child(1){white-space:nowrap}details{min-width:230px;max-width:420px}details p,details li{font-size:13px}summary{cursor:pointer;color:#93c5fd}input,select{padding:10px;border:1px solid #475569;background:#172033;color:inherit;border-radius:5px;margin:5px 8px 10px 0}.scroll{overflow:auto}a{color:#93c5fd}.note{border-left:3px solid #fbbf24;padding:10px 16px;background:#272735}li{margin:5px 0}
</style><main><h1>Сравнение моделей приоритизации VM</h1>'''
    body += f'<p class="muted">Снимок: {esc(stamp)} · {esc(result["policy"]["version"])} · READ ONLY / REPEATABLE READ</p>'
    body += f'<div class="cards"><div class="card">Находки<b>{coverage["findings"]:,}</b></div><div class="card">Уникальные оценённые уязвимости<b>{coverage["scored_vulnerabilities"]:,}</b></div><div class="card">Пересечение топ-{limit}<b>{summary["top_overlap"]}</b></div><div class="card">Вошли / вышли<b>{len(result["entered"])} / {len(result["left"])}</b></div></div>'
    body += '<h2>Начальная модель</h2><p>Эксплуатация ≤40 + последствия ≤25 + доступность ≤20 + значимость актива ≤15. В блоке эксплуатации берётся самый сильный сигнал. Итог — балл приоритета исправления, не вероятность компрометации.</p><ul>'
    body += f'<li>EPSS: &lt;0,1% →2; &lt;1% →6; &lt;10% →12; &lt;50% →20; ≥50% →30; нет данных →8.</li><li>ExploitDB/Metasploit →24; Metasploit good/great/excellent →32; KEV →40.</li><li>Последствия: CVSS ×2,5; нет CVSS →12,5. Доступность: внешняя сетевая зона 20, внутренняя 10, неизвестная 12; смежная сеть 8, локальный/физический вектор 4.</li><li>Значимость: Critical 15, High 12, Medium 8, Low 4, неизвестно 8; конфиденциальные данные +2 с потолком 15.</li><li>Минимумы: KEV {policy["floors"]["kev_minimum"]}; KEV + сеть + внешняя зона 90; готовый Metasploit + CVSS ≥9 + Critical 85.</li></ul>'
    body += '<p class="note">Это начальная экспертная политика. Сравнение показывает изменение приоритетов, но не доказывает лучшую точность без эталонных исходов. Разметка внешней зоны не подтверждает доступность конкретного сервиса. Неизвестные поля показаны явно. Рабочие оценки и настройки стенда не изменялись.</p>'
    body += f'<div class="grid"><section><h2>Состав топ-{limit}</h2><table><tr><th>Показатель</th><th>Старая</th><th>Новая</th></tr>{metrics}</table></section><section><h2>Все уровни</h2><table><tr><th>Уровень</th><th>Старая</th><th>Новая</th></tr>{levels}</table><p class="muted">Пороги старой модели: {esc(old_thresholds)}. Новой: {esc(new_thresholds)}. Поэтому различия уровней обусловлены и формулой, и порогами.</p></section></div>'
    cutoff_ties = sum(r["old_score"] == summary["old_boundary"]["score"] for r in result["entered"])
    body += f'<h2>Что изменилось</h2><p>В новом топе {len(result["entered"])} новых участников; у {cutoff_ties} из них старый балл совпадал с баллом на границе старого топа. Эта часть изменения связана с разрешением прежних равенств, а не с обнаружением ранее неизвестных угроз.</p>'
    body += f'<p class="note">High: {summary["old_levels"].get("high",0)} → {summary["new_levels"].get("high",0)}. Пороги уровней — параметры политики устранения. Перед включением модели нужно оценить размер очереди и состав уязвимостей, остающихся за её границей. Веса блоков сохранены при калибровке High.</p>'
    body += f'<p>Правила минимальной срочности фактически повысили максимум {sum(summary["effective_floor_promotions"].values())} уязвимостей. Нулевые оценки: {summary["old_zero_scores"]} → {summary["new_zero_scores"]}. Эти изменения сами по себе не являются доказательством лучшего прогноза.</p>'
    body += f'<h2>Равные баллы и полнота данных</h2><p>{esc(boundary_text)} Внутри равных баллов порядок задан идентификатором; различие позиций в такой группе не означает различие срочности.</p>'
    body += f'<p>Не оценены обеими моделями из-за отсутствия записи в витрине CVE: {len(coverage["unscored_identifiers"])} идентификаторов. Сохранённый старый максимум отличается от пересчитанного у {summary["stored_legacy_maxima_different"]} уязвимостей. В сравнении обе модели пересчитаны на одинаковых факторах и текущих весах.</p>'
    body += f'<h2>Топ-{limit}: строки сравнения</h2><label>Выборка <select id="mode"><option value="new">Новый топ</option><option value="old">Старый топ</option><option value="entered">Вошли</option><option value="left">Вышли</option><option value="all">Объединение</option></select></label><input id="search" aria-label="Поиск уязвимости" placeholder="Найти CVE / GHSA"><span id="count"></span>'
    body += '<div class="scroll"><table id="ranking"><thead><tr><th>Уязвимость</th><th>Старое место</th><th>Новое место</th><th>Подъём</th><th>Старый балл</th><th>Новый балл</th><th>KEV (снимок)</th><th>CVSS max</th><th>EPSS max</th><th>Хосты / образы</th><th>Почему</th></tr></thead><tbody>'+''.join(table)+'</tbody></table></div>'
    body += '<h2>Данные и воспроизводимость</h2><p>Уникальные CVE/GHSA объединены существующим сопоставлением; балл уязвимости — максимум по контекстам активов. Повторные пакеты и синонимы не увеличивают балл или число активов. Срез охватывает текущие находки VM-хостов и Harbor независимо от статуса обработки; отдельное сопоставление ПО KSC сюда не включено.</p><details><summary>Загруженные справочники</summary><ul>'+refs+'</ul></details><p><a href="new-top-100.csv">Новый топ CSV</a> · <a href="old-top-100.csv">Старый топ CSV</a> · <a href="all-rankings.csv">Все позиции CSV</a> · <a href="comparison.json">Полные результаты JSON</a></p>'
    body += f'''<script>const limit={limit};const rows=Array.from(document.querySelectorAll('#ranking tbody tr'));const mode=document.querySelector('#mode'),search=document.querySelector('#search');function filter(){{let n=0;const m=mode.value,q=search.value.toLowerCase();for(const r of rows){{const o=+r.dataset.old<=limit,v=+r.dataset.new<=limit;const visible=(m==='all'||m==='old'&&o||m==='new'&&v||m==='entered'&&v&&!o||m==='left'&&o&&!v)&&r.textContent.toLowerCase().includes(q);r.hidden=!visible;if(visible)n++;}}const key=m==='old'||m==='left'?'old':'new';rows.sort((a,b)=>+a.dataset[key]-b.dataset[key]).forEach(r=>r.parentNode.appendChild(r));document.querySelector('#count').textContent='Строк: '+n;}}mode.addEventListener('change',filter);search.addEventListener('input',filter);filter();</script></main></html>'''
    path.write_text(body, encoding="utf-8")


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("snapshot", type=Path)
    parser.add_argument("output", type=Path)
    parser.add_argument("--high-threshold", type=int, default=None)
    args = parser.parse_args()
    args.output.mkdir(parents=True, exist_ok=False)
    raw = args.snapshot.read_bytes()
    started = time.monotonic()
    result = compare_snapshot(json.loads(raw), high_threshold=args.high_threshold)
    result["meta"] = dict(result["meta"], snapshot_sha256=hashlib.sha256(raw).hexdigest(), comparison_seconds=round(time.monotonic()-started, 3))
    code_root = Path(__file__).resolve().parents[1]
    result["meta"]["implementation_sha256"] = {
        name: hashlib.sha256((code_root/name).read_bytes()).hexdigest()
        for name in ("api/modules/vm/core/priority.py", "api/modules/vm/services/priority_comparison.py", "scripts/export_vm_priority_snapshot.py")
    }
    (args.output/"comparison.json").write_text(json.dumps(result, ensure_ascii=False, default=lambda value: value.isoformat()), encoding="utf-8")
    for name, rows in (("new-top-100", result["new_top"]), ("old-top-100", result["old_top"]), ("entered", result["entered"]), ("left", result["left"]), ("all-rankings", result["rows"])):
        write_csv(args.output/(name+".csv"), rows)
    write_html(args.output/"report.html", result)
    print(json.dumps({"coverage": result["coverage"], "summary": result["summary"], "comparison_seconds": result["meta"]["comparison_seconds"]}, ensure_ascii=False, indent=2))


if __name__ == "__main__":
    main()
