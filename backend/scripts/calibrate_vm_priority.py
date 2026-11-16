"""Offline High calibration on a single exported snapshot; does not access the DB."""
from __future__ import annotations

import argparse
import csv
import hashlib
import html
import json
import time
from collections import Counter
from pathlib import Path

from api.modules.vm.core.priority import LEVELS, READY_MSF
from api.modules.vm.services.priority_comparison import compare_snapshot
from scripts.compare_vm_priority import csv_value, write_csv, write_html

CANDIDATES = (65, 70, 75, 80, 82)
URGENT = {"high", "critical"}


def cohort(rows):
    """Signals from the same input/context that produced the candidate maximum."""
    return {"count": len(rows),
            "epss_ge_50pct": sum((r["new_inputs"]["epss"] or 0) >= .5 for r in rows),
            "cvss_ge_9": sum((r["new_inputs"]["cvss"] or 0) >= 9 for r in rows),
            "public_exploit": sum(bool(r["new_inputs"]["exploitdb_type"] or r["new_inputs"]["msf_rank"]) for r in rows),
            "ready_msf": sum(r["new_inputs"]["msf_rank"] in READY_MSF for r in rows),
            "known_external": sum(r["new_context"]["internet"] is True for r in rows),
            "critical_asset": sum(r["new_context"]["criticality"] == "Critical" for r in rows),
            "missing_data": sum(bool(r["new_explanation"]["missing"]) for r in rows)}


def compact(row):
    c, inputs = row["new_context"], row["new_inputs"]
    return {"id": row["id"], "identifiers": row["identifiers"], "score65": row["new_score"],
            "kev": row["kev"], "cvss": inputs["cvss"], "epss": inputs["epss"],
            "exploitdb": inputs["exploitdb_type"], "msf": inputs["msf_rank"],
            "criticality": c["criticality"], "internet": c["internet"],
            "hosts": row["affected_hosts"], "images": row["affected_images"],
            "old_score": row["old_score"], "old_level": row["old_level"]}


def calibrate_snapshot(snapshot, *, selected_high=80):
    if selected_high not in CANDIDATES:
        raise ValueError("Selected High threshold must be one of the calibrated candidates")
    base = compare_snapshot(snapshot, high_threshold=65)
    by_id = {r["id"]: r for r in base["rows"]}
    queued = {r["id"] for r in base["rows"] if r["new_level"] in URGENT}
    critical = {r["id"] for r in base["rows"] if r["new_level"] == "critical"}
    kev = {r["id"] for r in base["rows"] if r["kev"]}
    old_urgent = {r["id"] for r in base["rows"] if r["old_level"] in URGENT}
    top = [r["id"] for r in base["new_top"]]
    variants, selected = [], None
    for threshold in CANDIDATES:
        result = base if threshold == 65 else compare_snapshot(snapshot, high_threshold=threshold)
        rows = result["rows"]
        urgent = {r["id"] for r in rows if r["new_level"] in URGENT}
        demoted = [r for r in rows if r["id"] in queued - urgent]
        checks = {
            "all_kev_retained": kev <= urgent,
            "critical_set_unchanged": critical == {r["id"] for r in rows if r["new_level"] == "critical"},
            "non_kev_scores_unchanged": all(r["new_score"] == by_id[r["id"]]["new_score"] for r in rows if not r["kev"]),
            "legacy_scores_unchanged": all(r["old_score"] == by_id[r["id"]]["old_score"] for r in rows),
            "only_high_to_medium": all(r["new_level"] == "medium" for r in demoted) and urgent <= queued,
        }
        if not all(checks.values()):
            raise ValueError(f"Calibration violated policy invariants at {threshold}: {checks}")
        variants.append({
            "threshold": threshold, "policy": result["policy"], "levels": dict(Counter(r["new_level"] for r in rows)),
            "urgent": len(urgent), "reduction_pct": round(100 * (len(queued) - len(urgent)) / len(queued), 2) if queued else 0,
            "kev_urgent": len(kev & urgent), "kev_score_promotions": sum(r["new_score"] > by_id[r["id"]]["new_score"] for r in rows if r["kev"]),
            "legacy_urgent_retained": len(old_urgent & urgent), "legacy_urgent_dropped": len(old_urgent - urgent),
            "affected_pairs_for_urgent_vulnerabilities": sum(r["affected_hosts"] + r["affected_images"] for r in rows if r["id"] in urgent),
            "demoted": cohort(demoted), "checks": checks,
            "top100_same_order": top == [r["id"] for r in result["new_top"]],
            "top100_overlap": len(set(top) & {r["id"] for r in result["new_top"]}),
        })
        if threshold == selected_high:
            selected = result
    report = {"meta": dict(snapshot["meta"]), "coverage": base["coverage"],
              "selected_high": selected_high, "legacy_urgent": len(old_urgent), "kev_total": len(kev),
              "variants": variants,
              "border80_81": cohort([r for r in base["rows"] if not r["kev"] and 80 <= r["new_score"] < 82]),
              "queued_vulnerabilities": [compact(r) for r in sorted(base["rows"], key=lambda r: (-r["new_score"], r["id"])) if r["id"] in queued]}
    return report, selected


def write_calibration_html(path, report):
    esc = html.escape
    selected = next(v for v in report["variants"] if v["threshold"] == report["selected_high"])
    border = report["border80_81"]
    variants = {v["threshold"]: v for v in report["variants"]}
    table = "".join(f'<tr class="{"selected" if v is selected else ""}"><td>{v["threshold"]}</td><td>{v["levels"].get("high", 0):,}</td><td>{v["levels"].get("critical", 0):,}</td><td><b>{v["urgent"]:,}</b></td><td>{v["reduction_pct"]:.1f}%</td><td>{v["kev_urgent"]}</td><td>{v["demoted"]["epss_ge_50pct"]} / {v["demoted"]["public_exploit"]}</td></tr>' for v in report["variants"])
    payload = json.dumps(report, ensure_ascii=False, default=str).replace("<", "\\u003c")
    body = '''<!doctype html><html lang="ru"><meta charset="utf-8"><meta name="viewport" content="width=device-width,initial-scale=1">
<title>Калибровка High · VM</title><style>
:root{color-scheme:dark}*{box-sizing:border-box}body{font:15px/1.5 system-ui,sans-serif;background:#101827;color:#e6edf7;margin:0}main{max-width:1350px;margin:auto;padding:30px}h1{font-size:30px}h2{font-size:21px;margin-top:30px}.muted{color:#a8b8cf}.cards{display:flex;gap:12px;flex-wrap:wrap}.card{padding:16px 22px;background:#1c2a40;border-radius:8px}.card b{display:block;font-size:27px;color:#6ee7cc}table{border-collapse:collapse;width:100%;font-variant-numeric:tabular-nums}th,td{text-align:left;padding:10px;border-bottom:1px solid #34425b;vertical-align:top}th{background:#233149}tr.selected{background:#193c43}td:first-child{white-space:nowrap}.scroll{overflow:auto}.note{background:#272b39;border-left:3px solid #f4be5a;padding:12px 18px}select,input,button{font:inherit;background:#1b2940;border:1px solid #64748b;color:inherit;border-radius:5px;padding:8px;margin:4px 8px 8px 0}button{cursor:pointer}button:disabled{opacity:.4}a{color:#93c5fd}.bar{height:20px;display:flex;background:#182338;min-width:150px}.bar span:first-child{background:#f98b88}.bar span:last-child{background:#5ccbb8}.chart-row{display:grid;grid-template-columns:70px 1fr 100px;gap:10px;margin:10px 0;align-items:center}label{display:inline-block}#queue td{font-size:13px}.check{color:#6ee7cc}
</style><main><p class="muted">Тестируемая скоринговая модель · рабочие оценки не изменены</p><h1>Порог High: размер очереди и цена сокращения</h1>'''
    body += f'<p>Один снимок стенда от {esc(report["meta"].get("captured_at", ""))}. Оценено {report["coverage"]["scored_vulnerabilities"]:,} уникальных уязвимостей, исходных находок {report["coverage"]["findings"]:,}.</p>'
    body += f'<div class="cards"><div class="card">Выбранный High<b>≥{report["selected_high"]}</b></div><div class="card">High + Critical<b>{selected["urgent"]:,}</b></div><div class="card">Сокращение от High 65<b>{selected["reduction_pct"]:.1f}%</b></div><div class="card">KEV в срочной очереди<b>{selected["kev_urgent"]} / {report["kev_total"]}</b></div></div>'
    body += '<h2>Пять вариантов</h2><p>Очередь — уникальные уязвимости с уровнем High или Critical; CVE/GHSA и повторы пакетов объединены. Числа показывают срез находок без фильтра по статусу устранения.</p><div class="scroll"><table><thead><tr><th>High от</th><th>High</th><th>Critical</th><th>Вся срочная очередь</th><th>Сокращение от 65</th><th>KEV сохранено</th><th>В Medium: EPSS ≥50% / эксплойт</th></tr></thead><tbody>'+table+'</tbody></table></div><p class="muted">Последние две группы пересекаются; складывать их нельзя. Эксплойт — запись ExploitDB или Metasploit. EPSS, эксплойт и контекст относятся к одной записи, давшей максимальный балл.</p><div id="chart" aria-label="Размер срочной очереди"></div><p class="muted">Красный — Critical, зелёный — High; одна шкала для всех порогов.</p>'
    body += f'<h2>Выбор порога</h2><p>Порог 75 оставляет {variants[75]["urgent"]:,} уязвимостей в срочной очереди, 80 — {variants[80]["urgent"]:,}. Повышение до 82 экономит ещё {border["count"]} позиций, но выводит в Medium {border["epss_ge_50pct"]} уязвимостей с EPSS ≥50% и {border["public_exploit"]} с опубликованными эксплойтами, включая {border["ready_msf"]} с Metasploit good/great/excellent. Для данного среза выбран High {report["selected_high"]} как начальный компромисс.</p>'
    body += f'<p class="note">У порога {report["selected_high"]} тоже есть цена: в Medium переходят {selected["demoted"]["count"]:,} не-KEV, в том числе {selected["demoted"]["epss_ge_50pct"]} с EPSS ≥50% и {selected["demoted"]["public_exploit"]} с эксплойтами. Это не безопасные уязвимости: они сохраняют балл и требуют планового устранения. Из {report["legacy_urgent"]} уязвимостей старой срочной очереди остаются {selected["legacy_urgent_retained"]}, {selected["legacy_urgent_dropped"]} переходят в Medium.</p>'
    body += '<h2>Что сохранено</h2><p class="check">Все KEV остаются как минимум High; сетевые KEV во внешней зоне — минимум 90/Critical. Готовый Metasploit + CVSS ≥9 + критичный актив — минимум 85/Critical.</p><p>Минимум KEV = max(70, порог High), поэтому при High 80 он равен 80. Это повышение по политике срочности; исходные баллы четырёх блоков не меняются. Critical начинается с 85, Medium с 40. Веса блоков 40/25/20/15 сохранены. Для всех пяти вариантов проверены неизменность состава Critical, старых оценок и баллов не-KEV.</p>'
    body += f'<p>Состав и порядок топ-100 относительно кандидата High 65: {"не изменились во всех вариантах" if all(v["top100_same_order"] for v in report["variants"]) else "есть изменения — см. JSON"}. Правила не являются прогнозом вероятности инцидента; порог выбран по нагрузке и наблюдаемым сигналам, без эталонной разметки инцидентов и заданного бюджета команды.</p>'
    body += '<h2>Проверить состав очереди</h2><label>Порог <select id="threshold">'+''.join(f'<option value="{h}">{h}</option>' for h in CANDIDATES)+'</select></label><label>Выборка <select id="mode"><option value="demoted">Перешли из High в Medium</option><option value="urgent">Остаются High + Critical</option><option value="border">Граница 80–81, без KEV</option></select></label><label>Сигнал <select id="signal"><option value="all">Все</option><option value="epss">EPSS ≥50%</option><option value="exploit">Опубликованный эксплойт</option><option value="kev">KEV</option><option value="legacy">Старая срочная очередь</option></select></label><input id="search" aria-label="Поиск CVE или GHSA" placeholder="CVE / GHSA"><p id="details"></p><div class="scroll"><table id="queue"><thead><tr><th>Уязвимость</th><th>Балл / уровень</th><th>KEV</th><th>CVSS / EPSS</th><th>Эксплойт</th><th>Критичность / зона</th><th>Хосты / образы</th><th>Старая модель</th></tr></thead><tbody></tbody></table></div><p><button id="prev">Назад</button><span id="count"></span><button id="next">Далее</button></p>'
    body += '<h2>Воспроизводимость</h2><p>В таблице показан контекст максимума при исходном High 65. Для не-KEV он не изменяется. Хосты/образы — количество затронутых активов для данной уязвимости; это не число задач с высоким баллом на каждом отдельном активе. Разметка внешней зоны не подтверждает доступность конкретного сервиса.</p><p><a href="selected/report.html">Сравнение выбранной модели с рабочей, топ-100</a> · <a href="variants.csv">Варианты CSV</a> · <a href="demoted-at-selected.csv">Перешедшие в Medium CSV</a> · <a href="calibration.json">Все расчёты JSON</a></p>'
    body += f'<p class="muted">SHA-256 снимка: {esc(report["meta"].get("snapshot_sha256", ""))}. Не оценены обеими моделями: {len(report["coverage"]["unscored_identifiers"])} идентификаторов без записи в витрине CVE. Отдельное сопоставление ПО KSC не входит в срез.</p><script id="data" type="application/json">'+payload+'</script>'
    body += '''<script>
const data=JSON.parse(document.getElementById('data').textContent), $=s=>document.querySelector(s), fmt=n=>n==null?'—':Number(n).toLocaleString('ru-RU'), esc=s=>String(s??'—').replace(/[&<>"']/g,c=>({'&':'&amp;','<':'&lt;','>':'&gt;','"':'&quot;',"'":'&#39;'}[c]));
const threshold=$('#threshold'),mode=$('#mode'),signal=$('#signal'),search=$('#search');threshold.value=data.selected_high;let page=0;
const max=Math.max(...data.variants.map(v=>v.urgent),1);$('#chart').innerHTML=data.variants.map(v=>`<div class="chart-row"><b>≥${v.threshold}</b><div class="bar"><span style="width:${100*(v.levels.critical||0)/max}%"></span><span style="width:${100*(v.levels.high||0)/max}%"></span></div><b>${fmt(v.urgent)}</b></div>`).join('');
function render(){const h=+threshold.value,v=data.variants.find(x=>x.threshold===h),q=search.value.trim().toLowerCase();const filtered=data.queued_vulnerabilities.filter(r=>{const score=r.kev?Math.max(r.score65,h):r.score65;return (mode.value==='demoted'?!r.kev&&score<h:mode.value==='urgent'?score>=h:!r.kev&&r.score65>=80&&r.score65<82)&&(signal.value==='all'||signal.value==='kev'&&r.kev||signal.value==='epss'&&r.epss>=.5||signal.value==='exploit'&&(r.exploitdb||r.msf)||signal.value==='legacy'&&['high','critical'].includes(r.old_level))&&r.identifiers.some(id=>id.toLowerCase().includes(q));});const pages=Math.max(1,Math.ceil(filtered.length/50));page=Math.min(page,pages-1);$('#queue tbody').innerHTML=filtered.slice(page*50,page*50+50).map(r=>{const score=r.kev?Math.max(r.score65,h):r.score65,level=score>=85?'Critical':score>=h?'High':'Medium';return `<tr><td>${esc(r.id)}</td><td>${score} / ${level}</td><td>${r.kev?'да':'нет'}</td><td>${fmt(r.cvss)} / ${r.epss==null?'—':fmt(Math.round(r.epss*10000)/100)+'%'}</td><td>${esc([r.exploitdb,r.msf].filter(Boolean).join(' / ')||'нет в справочниках')}</td><td>${esc(r.criticality)} / ${r.internet==null?'неизвестна':r.internet?'внешняя':'внутренняя'}</td><td>${fmt(r.hosts)} / ${fmt(r.images)}</td><td>${r.old_score} / ${esc(r.old_level)}</td></tr>`;}).join('');$('#details').textContent=`При High ${h}: срочная очередь ${fmt(v.urgent)}, в Medium переведено ${fmt(v.demoted.count)}. KEV сохранено ${v.kev_urgent}/${data.kev_total}.`;$('#count').textContent=`Всего: ${fmt(filtered.length)} · страница ${page+1} / ${pages}`;$('#prev').disabled=page===0;$('#next').disabled=page>=pages-1;}
for(const input of [threshold,mode,signal,search])input.addEventListener(input===search?'input':'change',()=>{page=0;render()});$('#prev').onclick=()=>{page--;render()};$('#next').onclick=()=>{page++;render()};render();
</script></main></html>'''
    path.write_text(body, encoding="utf-8")


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("snapshot", type=Path)
    parser.add_argument("output", type=Path)
    args = parser.parse_args()
    args.output.mkdir(parents=True, exist_ok=False)
    raw = args.snapshot.read_bytes()
    started = time.monotonic()
    report, selected = calibrate_snapshot(json.loads(raw), selected_high=LEVELS["high"])
    root = Path(__file__).resolve().parents[1]
    provenance = {"snapshot_sha256": hashlib.sha256(raw).hexdigest(), "calibration_seconds": round(time.monotonic()-started, 3),
                  "implementation_sha256": {name: hashlib.sha256((root/name).read_bytes()).hexdigest() for name in (
                      "api/modules/vm/core/priority.py", "api/modules/vm/services/priority_comparison.py",
                      "scripts/compare_vm_priority.py", "scripts/calibrate_vm_priority.py")}}
    report["meta"].update(provenance)
    selected["meta"] = dict(selected["meta"], **provenance)
    (args.output/"calibration.json").write_text(json.dumps(report, ensure_ascii=False, default=str), encoding="utf-8")
    write_calibration_html(args.output/"report.html", report)
    with (args.output/"variants.csv").open("w", encoding="utf-8-sig", newline="") as out:
        fields = ["threshold", "high", "critical", "urgent", "reduction_pct", "kev_urgent", "demoted", "demoted_epss_ge_50pct", "demoted_public_exploit", "legacy_urgent_dropped"]
        writer = csv.DictWriter(out, fieldnames=fields)
        writer.writeheader()
        for v in report["variants"]:
            writer.writerow({"threshold": v["threshold"], "high": v["levels"].get("high", 0),
                             "critical": v["levels"].get("critical", 0), "urgent": v["urgent"],
                             "reduction_pct": v["reduction_pct"], "kev_urgent": v["kev_urgent"],
                             "demoted": v["demoted"]["count"], "demoted_epss_ge_50pct": v["demoted"]["epss_ge_50pct"],
                             "demoted_public_exploit": v["demoted"]["public_exploit"],
                             "legacy_urgent_dropped": v["legacy_urgent_dropped"]})
    demoted = [dict(r, selected_high=report["selected_high"], selected_score=r["score65"], selected_level="medium") for r in report["queued_vulnerabilities"] if not r["kev"] and r["score65"] < report["selected_high"]]
    with (args.output/"demoted-at-selected.csv").open("w", encoding="utf-8-sig", newline="") as out:
        fields = list(compact(selected["rows"][0])) if selected["rows"] else ["id"]
        writer = csv.DictWriter(out, fieldnames=fields + ["selected_high", "selected_score", "selected_level"])
        writer.writeheader()
        for row in demoted:
            writer.writerow({key: csv_value(value) for key, value in row.items()})
    folder = args.output/"selected"
    folder.mkdir()
    (folder/"comparison.json").write_text(json.dumps(selected, ensure_ascii=False, default=str), encoding="utf-8")
    for name, rows in (("new-top-100", selected["new_top"]), ("old-top-100", selected["old_top"]), ("entered", selected["entered"]), ("left", selected["left"]), ("all-rankings", selected["rows"])):
        write_csv(folder/(name+".csv"), rows)
    write_html(folder/"report.html", selected)
    print(json.dumps({"selected_high": report["selected_high"], "variants": [{k: v[k] for k in ("threshold", "urgent", "kev_urgent", "checks", "top100_same_order")} for v in report["variants"]], "seconds": provenance["calibration_seconds"]}, ensure_ascii=False))


if __name__ == "__main__":
    main()
