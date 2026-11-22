#!/usr/bin/env python3
"""Interactive and unattended STools offline collection. Python 3.11+, stdlib."""

from __future__ import annotations

import argparse
import datetime as dt
import json
import re
import sys
import tempfile
import threading
from collections.abc import Callable
from dataclasses import dataclass
from pathlib import Path

DATASETS = (
    "nvd",
    "ghsa",
    "epss",
    "kev",
    "exploitdb",
    "msf",
    "attack",
    "news",
    "sigma",
    "elastic",
    "trivy",
    "oval",
)
TITLES = {
    "nvd": "CVE / NVD",
    "ghsa": "GitHub Advisory Database",
    "epss": "EPSS",
    "kev": "CISA KEV",
    "exploitdb": "ExploitDB",
    "msf": "Metasploit",
    "attack": "CVE → ATT&CK (CTID)",
    "news": "RSS / Atom / Telegram",
    "sigma": "SigmaHQ",
    "elastic": "Elastic Detection Rules",
    "trivy": "Trivy Vulnerability DB (SBOM)",
    "oval": "РЕД ОС / Astra Linux OVAL (SBOM)",
}
MESSAGES = {
    "ru": {
        "title": "STools — выгрузка данных из интернета",
        "datasets": "Что выгружать",
        "mode": "Режим",
        "period": "Период",
        "output": "Папка результатов",
        "proxy": "Прокси",
        "lang": "Язык / Language",
        "start": "Начать",
        "cancel": "Выход",
        "choice": "Выберите пункт: ",
        "all": "всё",
        "full": "полностью",
        "updates": "только обновления",
        "system": "системный",
        "direct": "напрямую",
        "select": "Номера или имена через запятую (all — всё): ",
        "mode_prompt": "full / updates: ",
        "period_prompt": "1d — день; 7d — неделя; 3m — три календарных месяца: ",
        "language_prompt": "ru / en: ",
        "proxy_prompt": "system / direct: ",
        "output_prompt": "Папка: ",
        "warning": "Проверьте в STools давность своих баз. Выгружается только выбранный период; пропущенные интервалы автоматически не догружаются.",
        "news_limit": "Полная выгрузка новостей ограничена историей, которую отдаёт источник; ограничения и ошибки будут в отчёте.",
        "snapshot": "EPSS, KEV, ExploitDB, Metasploit и CTID: проверка версии; изменившийся источник загружается снимком.",
        "working": "Выгрузка",
        "finished": "Готово",
        "failed": "Не удалось выгрузить",
        "failed_all": "Выгрузка не выполнена — проверьте report.json.",
        "report": "Отчёт",
        "partial": "Выгрузка завершена частично — проверьте report.json.",
        "arguments": "Для запуска с параметрами укажите --datasets и --mode; для updates также --period.",
        "terminal": "Для меню нужен терминал. В автоматическом запуске задайте параметры и --quiet.",
        "invalid": "Некорректное значение",
        "cancelled": "Выгрузка отменена",
        "description": "Базы, новости и правила для переноса в STools без доступа к интернету.",
        "quiet_help": "без вопросов и сообщений прогресса; журнал и report.json сохраняются",
    },
    "en": {
        "title": "STools — offline internet data download",
        "datasets": "Datasets",
        "mode": "Mode",
        "period": "Period",
        "output": "Output directory",
        "proxy": "Proxy",
        "lang": "Language",
        "start": "Start",
        "cancel": "Exit",
        "choice": "Select option: ",
        "all": "all",
        "full": "full",
        "updates": "updates only",
        "system": "system",
        "direct": "direct",
        "select": "Numbers or names, comma-separated (all): ",
        "mode_prompt": "full / updates: ",
        "period_prompt": "1d — day; 7d — week; 3m — three calendar months: ",
        "language_prompt": "ru / en: ",
        "proxy_prompt": "system / direct: ",
        "output_prompt": "Directory: ",
        "warning": "Check the age of your databases in STools. Only the selected period is downloaded; missing intervals are not fetched automatically.",
        "news_limit": "Full news download is limited to history available from each publisher; limits and errors are recorded in the report.",
        "snapshot": "EPSS, KEV, ExploitDB, Metasploit and CTID: version check; a changed source is downloaded as a snapshot.",
        "working": "Downloading",
        "finished": "Done",
        "failed": "Download failed",
        "failed_all": "Download failed — inspect report.json.",
        "report": "Report",
        "partial": "Download completed partially — inspect report.json.",
        "arguments": "Specify --datasets and --mode; updates also requires --period.",
        "terminal": "The menu needs a terminal. Supply parameters and --quiet for unattended execution.",
        "invalid": "Invalid value",
        "cancelled": "Download cancelled",
        "description": "Databases, news and rules for transferring to an offline STools instance.",
        "quiet_help": "no prompts or progress output; run.log and report.json are still saved",
    },
}


@dataclass
class Config:
    datasets: tuple[str, ...]
    mode: str
    period: str | None
    output: Path
    lang: str = "ru"
    quiet: bool = False
    no_proxy: bool = False
    as_of: dt.datetime | None = None


def selection(value: str) -> tuple[str, ...]:
    values = re.split(r"[,;\s]+", value.strip().lower())
    if values == ["all"] or values == ["0"]:
        return DATASETS
    result = []
    for item in values:
        if item.isdigit() and 1 <= int(item) <= len(DATASETS):
            item = DATASETS[int(item) - 1]
        if item not in DATASETS:
            raise ValueError("unknown_dataset")
        if item not in result:
            result.append(item)
    if not result:
        raise ValueError("empty_selection")
    return tuple(result)


def menu(config: Config, input_fn: Callable[[str], str]) -> Config | None:
    while True:
        m = MESSAGES[config.lang]
        print("\n" + m["title"])
        print(f"1. {m['datasets']}: {', '.join(config.datasets)}")
        print(f"2. {m['mode']}: {m[config.mode]}")
        print(f"3. {m['period']}: {config.period or '—'}")
        print(f"4. {m['output']}: {config.output}")
        print(f"5. {m['proxy']}: {m['direct' if config.no_proxy else 'system']}")
        print(f"6. {m['lang']}: {config.lang}\n0. {m['start']}\nq. {m['cancel']}")
        choice = input_fn(m["choice"]).strip().lower()
        try:
            if choice == "0":
                if config.mode == "updates" and config.period not in ("1d", "7d", "3m"):
                    raise ValueError("period")
                return config
            if choice == "q":
                return None
            if choice == "1":
                for index, name in enumerate(DATASETS, 1):
                    print(f"{index}. {name}: {TITLES[name]}")
                config.datasets = selection(input_fn(m["select"]))
            elif choice == "2":
                value = input_fn(m["mode_prompt"]).strip().lower()
                if value not in ("full", "updates"):
                    raise ValueError("mode")
                config.mode = value
            elif choice == "3":
                value = input_fn(m["period_prompt"]).strip().lower()
                if value not in ("1d", "7d", "3m"):
                    raise ValueError("period")
                config.period = value
            elif choice == "4":
                value = input_fn(m["output_prompt"]).strip()
                if not value:
                    raise ValueError("output")
                config.output = Path(value).expanduser()
            elif choice == "5":
                value = input_fn(m["proxy_prompt"]).strip().lower()
                if value not in ("system", "direct"):
                    raise ValueError("proxy")
                config.no_proxy = value == "direct"
            elif choice == "6":
                value = input_fn(m["language_prompt"]).strip().lower()
                if value not in MESSAGES:
                    raise ValueError("lang")
                config.lang = value
            else:
                raise ValueError("choice")
        except ValueError:
            print(m["invalid"])


def safe_error(exc: Exception) -> str:
    from urllib.error import HTTPError

    if isinstance(exc, HTTPError):
        return f"HTTP {exc.code}"
    if isinstance(exc, (ValueError, RuntimeError)):
        message = re.sub(r"(https?://)[^/@\s]+@", r"\1[redacted]@", str(exc))
        return message[:800]
    return type(exc).__name__


def run(config: Config, execute: Callable) -> int:
    m = MESSAGES[config.lang]
    config.as_of = dt.datetime.now(dt.UTC).replace(microsecond=0)
    config.output.mkdir(parents=True, exist_ok=True)
    run_dir = Path(
        tempfile.mkdtemp(
            prefix="stools-" + dt.datetime.now(dt.UTC).strftime("%Y%m%dT%H%M%SZ-"),
            dir=config.output,
        )
    )
    report = {
        "format": "stools-download-report",
        "version": 1,
        "mode": config.mode,
        "period": config.period if config.mode == "updates" else None,
        "language": config.lang,
        "generated_at": dt.datetime.now(dt.UTC).isoformat(),
        "proxy": "direct" if config.no_proxy else "system",
        "warnings": [],
        "datasets": {},
    }
    if config.mode == "updates" and set(config.datasets) - {"trivy", "oval"}:
        report["warnings"].append(m["warning"])
    if "news" in config.datasets:
        report["warnings"].append(m["news_limit"])
    if (
        set(config.datasets) & {"epss", "kev", "exploitdb", "msf", "attack"}
        and config.mode == "updates"
    ):
        report["warnings"].append(m["snapshot"])
    if "trivy" in config.datasets:
        report["warnings"].append("База Trivy переносится целым снимком независимо от периода."
                                  if config.lang == "ru" else "Trivy DB is a full snapshot for any period.")
    if "oval" in config.datasets:
        report["warnings"].append("Бюллетени OVAL переносятся целым снимком."
                                  if config.lang == "ru" else "OVAL advisories are transferred as a full snapshot.")
    lock = threading.Lock()
    with (run_dir / "run.log").open("w", encoding="utf-8") as log:

        def progress(message: str) -> None:
            message = re.sub(r"(https?://)[^/@\s]+@", r"\1[redacted]@", message)
            with lock:
                log.write(
                    dt.datetime.now(dt.UTC).isoformat(timespec="seconds")
                    + " "
                    + message
                    + "\n"
                )
                log.flush()
                if not config.quiet:
                    print(message, flush=True)

        for warning in report["warnings"]:
            progress(warning)
        for name in config.datasets:
            progress(m["working"] + ": " + TITLES[name])
            try:
                report["datasets"][name] = execute(name, config, run_dir, progress)
            except (OSError, ValueError, RuntimeError) as exc:
                report["datasets"][name] = {"status": "error", "error": safe_error(exc)}
                progress(m["failed"] + ": " + name + ": " + safe_error(exc))
            except KeyboardInterrupt:
                report["datasets"][name] = {"status": "error", "error": "cancelled"}
                progress(m["cancelled"])
                break
            (run_dir / "report.json").write_text(
                json.dumps(report, ensure_ascii=False, indent=2), encoding="utf-8"
            )
        statuses = [value["status"] for value in report["datasets"].values()]
        code = (
            0
            if statuses and all(s == "ok" for s in statuses)
            else 2
            if any(s != "error" for s in statuses)
            else 1
        )
        report["exit_code"] = code
        (run_dir / "report.json").write_text(
            json.dumps(report, ensure_ascii=False, indent=2), encoding="utf-8"
        )
        progress(
            (
                m["finished"]
                if code == 0
                else m["partial"]
                if code == 2
                else m["failed_all"]
            )
            + ": "
            + str(run_dir)
        )
    return code


class ArgumentError(ValueError):
    pass


class Parser(argparse.ArgumentParser):
    def error(self, message):
        raise ArgumentError(message)


def main(
    argv: list[str] | None = None,
    *,
    execute=None,
    input_fn=input,
    interactive: bool | None = None,
) -> int:
    argv = list(sys.argv[1:] if argv is None else argv)
    language_parser = argparse.ArgumentParser(add_help=False)
    language_parser.add_argument("--lang", default="ru")
    try:
        language_args, _ = language_parser.parse_known_args(argv)
        lang = language_args.lang if language_args.lang in MESSAGES else "ru"
    except SystemExit:
        lang = "ru"
    m = MESSAGES[lang]
    parser = Parser(description=m["description"])
    parser.add_argument("--datasets", help="all / " + ",".join(DATASETS))
    parser.add_argument("--mode", choices=("full", "updates"))
    parser.add_argument("--period", choices=("1d", "7d", "3m"), help=m["period_prompt"])
    parser.add_argument(
        "--output", type=Path, default=Path("stools-downloads"), help=m["output"]
    )
    parser.add_argument("--lang", choices=("ru", "en"), default=lang, help=m["lang"])
    parser.add_argument("--quiet", action="store_true", help=m["quiet_help"])
    parser.add_argument("--no-proxy", action="store_true", help=m["direct"])
    try:
        args = parser.parse_args(argv)
        config = Config(
            selection(args.datasets or "all"),
            args.mode or "updates",
            args.period or "1d",
            args.output.expanduser(),
            args.lang,
            args.quiet,
            args.no_proxy,
        )
        if not (args.datasets or args.mode or args.quiet):
            if not (sys.stdin.isatty() if interactive is None else interactive):
                raise ArgumentError(m["terminal"])
            config = menu(config, input_fn)
            if config is None:
                return 0
        elif (
            not args.datasets
            or not args.mode
            or (args.mode == "updates" and not args.period)
        ):
            raise ArgumentError(m["arguments"])
        if execute is None:
            from offline_sources import execute_dataset

            execute = execute_dataset
        return run(config, execute)
    except (ArgumentError, ValueError, OSError, EOFError, KeyboardInterrupt) as exc:
        message = (
            str(exc)
            if isinstance(exc, ArgumentError)
            else m["invalid"] + ": " + safe_error(exc)
        )
        print(message, file=sys.stderr)
        return 1


if __name__ == "__main__":
    raise SystemExit(main())
