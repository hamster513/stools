import importlib
import json
import sys
from pathlib import Path

import pytest

ROOT = Path(__file__).resolve().parents[3]


@pytest.fixture
def cli(monkeypatch):
    monkeypatch.syspath_prepend(str(ROOT / "frontend/public/offline"))
    monkeypatch.syspath_prepend(str(ROOT / "backend/api/modules/vm/core"))
    sys.modules.pop("offline_download", None)
    return importlib.import_module("offline_download")


def test_quiet_requires_explicit_period_without_prompt(cli, tmp_path, capsys):
    calls = []
    result = cli.main(
        ["--datasets", "nvd", "--mode", "updates", "--quiet", "--output", str(tmp_path)],
        execute=lambda *_: calls.append("network"),
    )
    assert result == 1 and not calls
    assert "period" in capsys.readouterr().err.lower()


def test_quiet_exact_selection_and_warning_in_log(cli, tmp_path, capsys):
    calls = []

    def execute(name, config, run_dir, progress):
        calls.append((name, config.mode, config.period, config.lang))
        target = run_dir / (name + ".zip")
        target.write_bytes(b"fixture")
        progress("fixture downloaded")
        return {"status": "ok", "archive": target.name}

    result = cli.main(
        [
            "--datasets",
            "nvd,news",
            "--mode",
            "updates",
            "--period",
            "1d",
            "--lang",
            "en",
            "--quiet",
            "--output",
            str(tmp_path),
        ],
        execute=execute,
    )
    assert result == 0 and calls == [
        ("nvd", "updates", "1d", "en"),
        ("news", "updates", "1d", "en"),
    ]
    assert capsys.readouterr().out == ""
    runs = list(tmp_path.glob("stools-*"))
    assert len(runs) == 1
    report = json.loads((runs[0] / "report.json").read_text())
    assert report["period"] == "1d" and report["mode"] == "updates"
    assert "STools" in (runs[0] / "run.log").read_text()


def test_invalid_period_fails_before_output_or_network(cli, tmp_path):
    called = []
    assert (
        cli.main(
            [
                "--datasets",
                "all",
                "--mode",
                "updates",
                "--period",
                "4m",
                "--quiet",
                "--output",
                str(tmp_path),
            ],
            execute=lambda *_: called.append(1),
        )
        == 1
    )
    assert not called and not list(tmp_path.iterdir())


def test_partial_run_preserves_success_and_reports_error(cli, tmp_path, capsys):
    def execute(name, config, run_dir, progress):
        if name == "nvd":
            raise OSError("proxy-password-must-not-appear")
        (run_dir / "news.zip").write_bytes(b"fixture")
        return {"status": "ok", "archive": "news.zip"}

    args = ["--datasets", "nvd,news", "--mode", "full", "--quiet", "--output", str(tmp_path)]
    assert cli.main(args, execute=execute) == 2
    run = next(tmp_path.glob("stools-*"))
    data = (run / "report.json").read_text() + (run / "run.log").read_text()
    assert (run / "news.zip").exists() and "proxy-password" not in data
    assert "proxy-password" not in capsys.readouterr().err
    assert cli.main(args, execute=execute) == 2
    assert len(list(tmp_path.glob("stools-*"))) == 2


def test_menu_language_and_exact_dataset_selection(cli, tmp_path, capsys):
    answers = iter(["6", "en", "1", "nvd,ghsa", "3", "7d", "4", str(tmp_path), "0"])
    calls = []

    def execute(name, config, run_dir, progress):
        calls.append((name, config.period, config.lang))
        return {"status": "ok"}

    assert cli.main([], execute=execute, input_fn=lambda _: next(answers), interactive=True) == 0
    assert calls == [("nvd", "7d", "en"), ("ghsa", "7d", "en")]
    assert "Language" in capsys.readouterr().out


def test_no_stools_state_or_network_freshness_is_required(cli, tmp_path):
    calls = []
    assert (
        cli.main(
            [
                "--datasets",
                "ghsa",
                "--mode",
                "updates",
                "--period",
                "3m",
                "--quiet",
                "--output",
                str(tmp_path),
            ],
            execute=lambda *args: calls.append(args[0]) or {"status": "ok"},
        )
        == 0
    )
    assert calls == ["ghsa"]


def test_equals_language_option_controls_help(cli, capsys):
    with pytest.raises(SystemExit) as result:
        cli.main(["--lang=en", "--help"])
    assert result.value.code == 0
    assert cli.MESSAGES["en"]["description"] in capsys.readouterr().out
