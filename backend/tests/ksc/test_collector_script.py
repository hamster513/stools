"""Раздача скрипта, BOM, и прогон в контейнере PowerShell против поддельного KSC."""
from __future__ import annotations

import gzip
import json
import os
import re
import shutil
import socket
import subprocess
import sys
import time
from pathlib import Path

import pytest
from fastapi.testclient import TestClient

from api.modules.ksc.core.export import load_export
from tests.ksc.fake_ksc import MFA_SECRET, PASSWORD, USER, totp_code
from tests.ksc.synthetic import (
    BAIT_VALUES,
    assert_bait_hidden,
    assert_secrets_hidden,
    assert_storage_shapes,
    build_export,
    expected_policy_contents,
)

SCRIPT = Path("api/modules/ksc/collector/STools-KSC-Collector.ps1")
IMAGE = "mcr.microsoft.com/powershell:lts-alpine-3.20"


def test_collector_script_download(auth_client: TestClient) -> None:
    r = auth_client.get("/api/ksc/collector.ps1")
    assert r.status_code == 200 and "attachment" in r.headers["content-disposition"]
    assert "stools-ksc/1" in r.text and "Session.StartSession" in r.text and "KSCBasic" in r.text


def test_collector_script_has_utf8_bom(auth_client: TestClient) -> None:
    assert auth_client.get("/api/ksc/collector.ps1").content.startswith(b"\xef\xbb\xbf")


def _image_present() -> bool:
    if not shutil.which("docker"):
        return False
    return subprocess.run(["docker", "image", "inspect", IMAGE], capture_output=True, check=False).returncode == 0


def _run_script(tmp_path: Path, port: int, variant: str, config: dict[str, object] | None = None, script_dir: Path | None = None,
                extra_args: tuple[str, ...] = (), expect_ok: bool = True) -> Path:
    """Поднимает поддельный KSC на порту и прогоняет скрипт в контейнере; отдаёт файл выгрузки.

    С `config` скрипт получает только `-ConfigPath` (и `extra_args`): сервер, учётка, пароль и
    секрет второго фактора берутся из файла `<каталог прогона>/config.json`. `script_dir` —
    каталог с изменённой копией скрипта. `expect_ok=False` — прогон должен завершиться ошибкой."""
    env = {**os.environ, "STOOLS_FAKE_VARIANT": variant}
    server = subprocess.Popen([sys.executable, "-m", "tests.ksc.fake_ksc_http", str(port)], cwd=Path.cwd(), env=env)
    try:
        for _ in range(50):
            try:
                socket.create_connection(("127.0.0.1", port), timeout=0.2).close()
                break
            except OSError:
                time.sleep(0.1)
        out = tmp_path / (variant or "default")
        out.mkdir()
        docker = ["docker", "run", "--rm", "--add-host=host.docker.internal:host-gateway"]
        mounts = ["-v", f"{(script_dir or SCRIPT.resolve().parent)}:/script:ro", "-v", f"{out}:/out", IMAGE, "pwsh", "-File", "/script/STools-KSC-Collector.ps1"]
        if config is None:
            cmd = [*docker, "-e", f"STOOLS_KSC_PASSWORD={PASSWORD}", *mounts, "-Server", "host.docker.internal", "-Port", str(port),
                   "-Scheme", "http", "-User", USER, "-Internal", "-OutputPath", "/out/ksc.json.gz"]
        else:
            (out / "config.json").write_text(json.dumps({**config, "port": port}), encoding="utf-8")
            cmd = [*docker, *mounts, "-ConfigPath", "/out/config.json", *extra_args]
        run = subprocess.run(cmd, capture_output=True, text=True, timeout=300, check=False)
        assert (run.returncode == 0) is expect_ok, run.stdout + run.stderr
    finally:
        server.terminate()
    return out / "ksc.json.gz"


@pytest.mark.skipif(not _image_present(), reason=f"нужен docker и образ {IMAGE}")
def test_script_output_matches_online_format(tmp_path: Path) -> None:
    path = _run_script(tmp_path, 18299, "")
    export = load_export(path.read_bytes())
    expected = build_export()
    assert export.format == "stools-ksc/1" and export.server.name == "ksc01" and export.server.collector == "powershell"
    assert len(export.hosts) == len(expected["hosts"]) and {h["KLHST_WKS_DN"] for h in export.hosts} == {h["KLHST_WKS_DN"] for h in expected["hosts"]}
    assert set(export.host_products) == set(expected["host_products"]) and len(export.policies) == 3 and len(export.tasks) == 2 and len(export.licenses) == 1
    assert set(export.effective_policies) == {"0", "1", "2", "3", "4"} and export.static["KLADMSRV_SERVER_HOSTNAME"] == "ksc01"
    raw = json.loads(gzip.decompress(path.read_bytes()))
    assert raw["hosts"][0]["KLHST_WKS_LAST_VISIBLE"]["type"] == "datetime"  # обёртки KSC сохранены как есть
    assert export.role_assignments == expected["role_assignments"] and export.internal_users == expected["internal_users"]
    assert export.security == expected["security"]
    # из контейнера сертификата в файл идёт только CPublic — приватная часть остаётся на сервере
    assert list(export.server_certs) == ["1"] and list(export.server_certs["1"]) == ["CPublic"]
    assert export.secondary_servers == expected["secondary_servers"] and export.update_agents == expected["update_agents"]
    ws04 = next(h for h in export.hosts if h["KLHST_WKS_DN"] == "WS04")
    assert ws04["KLHST_WKS_RBT_REQUEST_REASON"] == 4 and "KLHST_WKS_OS_BUILD_NUMBER" in ws04
    assert export.policy_contents == expected_policy_contents()


@pytest.mark.skipif(not _image_present(), reason=f"нужен docker и образ {IMAGE}")
def test_script_survives_missing_fields(tmp_path: Path) -> None:
    """Set-StrictMode: обращение к отсутствующему свойству было бы фатальным."""
    export = load_export(_run_script(tmp_path, 18300, "sparse").read_bytes())
    assert export.server.name == "ksc01" and export.server.version == "" and export.licenses == []
    assert len(export.hosts) == len(build_export()["hosts"])
    ws01 = next(h for h in export.hosts if h["KLHST_WKS_DN"] == "WS01")
    assert "KLHST_WKS_STATUS" not in ws01 and "h-ws01" not in export.host_products  # без статуса агента продукты не спрашиваем


def test_fake_totp_matches_rfc6238() -> None:
    # Вектор из RFC 6238 (SHA1, T=59 с): 94287082 → шесть младших цифр.
    assert totp_code("GEZDGNBVGY3TQOJQGEZDGNBVGY3TQOJQ", at=59) == "287082"


@pytest.mark.skipif(not _image_present(), reason=f"нужен docker и образ {IMAGE}")
def test_script_passes_second_factor_with_config_file(tmp_path: Path) -> None:
    """KSC с двухфакторным входом: пароль даёт 401 + KSCMFA, сессию — только код TOTP.
    Всё, включая секрет второго фактора, скрипт берёт из файла настроек."""
    config = {"server": "host.docker.internal", "scheme": "http", "user": USER, "password": PASSWORD, "internal": True,
              "totp_secret": MFA_SECRET, "output_path": "/out/ksc.json.gz"}
    export = load_export(_run_script(tmp_path, 18301, "mfa", config).read_bytes())
    assert export.server.name == "ksc01" and len(export.hosts) == len(build_export()["hosts"])
    raw = gzip.decompress((tmp_path / "mfa" / "ksc.json.gz").read_bytes()).decode()
    assert PASSWORD not in raw and MFA_SECRET not in raw  # секреты в выгрузку не попадают
    assert (tmp_path / "mfa" / "config.json").exists()  # без -DeleteConfigAfterRun файл настроек остаётся


@pytest.mark.skipif(not _image_present(), reason=f"нужен docker и образ {IMAGE}")
def test_script_writes_config_template(tmp_path: Path) -> None:
    cmd = ["docker", "run", "--rm", "-v", f"{SCRIPT.resolve().parent}:/script:ro", "-v", f"{tmp_path}:/out", IMAGE,
           "pwsh", "-File", "/script/STools-KSC-Collector.ps1", "-InitConfig", "/out/ksc-config.json"]
    run = subprocess.run(cmd, capture_output=True, text=True, timeout=120, check=False)
    assert run.returncode == 0, run.stdout + run.stderr
    template = json.loads((tmp_path / "ksc-config.json").read_text(encoding="utf-8-sig"))
    assert set(template) == {"server", "port", "user", "password", "internal", "domain", "totp_secret", "skip_tls_check", "skip_products",
                             "skip_policy_contents", "page_size", "output_path", "delete_after_run"}
    assert template["port"] == 13299 and template["password"] == "" and template["totp_secret"] == "" and template["delete_after_run"] is False
    # Аудит M5: в файл лягут пароль и секрет второго фактора — доступ только владельцу (вне Windows — 600).
    assert (tmp_path / "ksc-config.json").stat().st_mode & 0o777 == 0o600


@pytest.mark.skipif(not _image_present(), reason=f"нужен docker и образ {IMAGE}")
def test_script_explains_broken_config_and_accepts_directory_output(tmp_path: Path) -> None:
    script = ["-v", f"{SCRIPT.resolve().parent}:/script:ro", "-v", f"{tmp_path}:/out", IMAGE, "pwsh", "-File", "/script/STools-KSC-Collector.ps1"]
    # Одиночная обратная черта перед кавычкой ломает JSON — скрипт должен сказать об этом по-человечески.
    (tmp_path / "bad.json").write_text('{"server": "x", "output_path": ".\\"}'.replace("\\\\", "\\"), encoding="utf-8")
    run = subprocess.run(["docker", "run", "--rm", *script, "-ConfigPath", "/out/bad.json", "-DeleteConfigAfterRun"], capture_output=True, text=True, timeout=120, check=False)
    assert run.returncode != 0 and "не разобран как JSON" in (run.stdout + run.stderr) and "удваивать" in (run.stdout + run.stderr)
    assert (tmp_path / "bad.json").exists()  # сбор не состоялся — файл настроек не удаляется
    # Каталог вместо файла: выгрузка ложится в него под именем по умолчанию.
    config = {"server": "host.docker.internal", "scheme": "http", "user": USER, "password": PASSWORD, "internal": True, "output_path": "/out/"}  # /out — каталог прогона
    with pytest.raises(FileNotFoundError):
        _run_script(tmp_path, 18302, "", config).read_bytes()  # ksc.json.gz там нет — имя по умолчанию другое
    files = list((tmp_path / "default").glob("ksc-ksc01-*.json.gz"))
    assert len(files) == 1 and load_export(files[0].read_bytes()).server.name == "ksc01"


@pytest.mark.skipif(not _image_present(), reason=f"нужен docker и образ {IMAGE}")
def test_script_reads_through_live_params_wrappers(tmp_path: Path) -> None:
    """Живой KSC заворачивает записи в {"type": "params"}: без чтения сквозь обёртку скрипт
    не запрашивал продукты хостов и брал политики только группы 0."""
    export = load_export(_run_script(tmp_path, 18303, "params").read_bytes())
    expected = build_export()
    assert len(export.hosts) == 14 and set(export.host_products) == set(expected["host_products"])
    assert set(export.host_components) == set(expected["host_components"])
    assert set(export.effective_policies) == {"0", "1", "2", "3", "4"} and export.server.name == "ksc01"
    assert len(export.role_assignments) == 3 and len(export.internal_users) == 2
    assert export.security == expected["security"] and list(export.server_certs["1"]) == ["CPublic"]
    assert export.secondary_servers == expected["secondary_servers"] and export.update_agents == expected["update_agents"]
    # задача приходит в обёртке params — статистика ложится внутрь неё, задача не теряется при разборе
    assert len(export.tasks) == 2
    assert all({"TASK_NAME", "TASK_INFO_PARAMS", "statistics"} <= set(t) for t in export.tasks)


@pytest.mark.skipif(not _image_present(), reason=f"нужен docker и образ {IMAGE}")
def test_script_survives_denied_sections(tmp_path: Path) -> None:
    """Отказ в правах на секции блока 1 не роняет сбор — секции пустые, остальное на месте."""
    export = load_export(_run_script(tmp_path, 18304, "denied").read_bytes())
    assert export.role_assignments == [] and export.internal_users == []
    assert export.security == {"two_factor_required_for_all": None}
    assert export.server_certs == {} and export.secondary_servers == [] and export.update_agents == []
    assert len(export.hosts) == len(build_export()["hosts"]) and len(export.policies) == 3


@pytest.mark.skipif(not _image_present(), reason=f"нужен docker и образ {IMAGE}")
def test_script_certs_empty_when_no_rights(tmp_path: Path) -> None:
    """Отказ в правах (403) на функции 2 — отказ на весь метод: секция пустая целиком,
    хотя функция 1 успела собраться раньше отказа."""
    export = load_export(_run_script(tmp_path, 18310, "denied_cert2").read_bytes())
    assert export.server_certs == {}
    assert len(export.server.warnings) == 1 and "сертификаты" in export.server.warnings[0]
    assert len(export.hosts) == len(build_export()["hosts"]) and len(export.policies) == 3


@pytest.mark.skipif(not _image_present(), reason=f"нужен docker и образ {IMAGE}")
def test_script_certs_keep_other_functions_on_method_error(tmp_path: Path) -> None:
    """PxgError на функции 2 — для этого назначения сертификата нет: сертификат функции 1 остаётся."""
    export = load_export(_run_script(tmp_path, 18320, "failed_cert2").read_bytes())
    assert list(export.server_certs) == ["1"] and list(export.server_certs["1"]) == ["CPublic"]
    assert len(export.server.warnings) == 1 and "функция 2" in export.server.warnings[0]
    assert len(export.hosts) == len(build_export()["hosts"]) and len(export.policies) == 3


@pytest.mark.skipif(not _image_present(), reason=f"нужен docker и образ {IMAGE}")
def test_script_and_online_policy_contents_match(tmp_path: Path) -> None:
    """PowerShell в контейнере и онлайн-Python против одного и того же поддельного KSC собирают
    одинаковую секцию policy_contents — оба сборщика читают содержимое политик одинаково."""
    port = 18330
    env = {**os.environ, "STOOLS_FAKE_VARIANT": ""}
    server = subprocess.Popen([sys.executable, "-m", "tests.ksc.fake_ksc_http", str(port)], cwd=Path.cwd(), env=env)
    try:
        for _ in range(50):
            try:
                socket.create_connection(("127.0.0.1", port), timeout=0.2).close()
                break
            except OSError:
                time.sleep(0.1)
        out = tmp_path / "policy_contents"
        out.mkdir()
        docker = ["docker", "run", "--rm", "--add-host=host.docker.internal:host-gateway", "-e", f"STOOLS_KSC_PASSWORD={PASSWORD}",
                  "-v", f"{SCRIPT.resolve().parent}:/script:ro", "-v", f"{out}:/out", IMAGE, "pwsh", "-File", "/script/STools-KSC-Collector.ps1",
                  "-Server", "host.docker.internal", "-Port", str(port), "-Scheme", "http", "-User", USER, "-Internal", "-OutputPath", "/out/ksc.json.gz"]
        run = subprocess.run(docker, capture_output=True, text=True, timeout=300, check=False)
        assert run.returncode == 0, run.stdout + run.stderr
        script_export = load_export((out / "ksc.json.gz").read_bytes())

        from api.modules.ksc.core.client import KscClient
        from api.modules.ksc.core.collector import collect

        with KscClient(f"http://127.0.0.1:{port}", USER, PASSWORD) as c:
            raw = collect(c, username=USER)
        online_export = load_export(json.dumps(raw).encode())
    finally:
        server.terminate()
    assert set(script_export.policy_contents) == {"1", "3"}
    assert script_export.policy_contents == online_export.policy_contents == expected_policy_contents()
    script_raw = json.loads(gzip.decompress((out / "ksc.json.gz").read_bytes()))["policy_contents"]
    assert_secrets_hidden(script_raw)
    assert_storage_shapes(script_raw)


@pytest.mark.skipif(not _image_present(), reason=f"нужен docker и образ {IMAGE}")
def test_script_and_online_policy_contents_match_raw_shape_with_params_wrappers(tmp_path: Path) -> None:
    """Вариант params: секции приходят обёрнутыми ({"type": "params", "value": …}, как у живого
    сервера) — сверяем сырой (несобранный) JSON policy_contents между скриптом и онлайн-сборщиком,
    а не разобранную форму (`load_export` снимает обёртки через strip_params и различие бы скрыла).
    Тем же прогоном проверяется политика с KLPOL_ACTIVE-типизированным нулём (fake_ksc.FakeKsc
    добавляет её в данные варианта params) — её быть не должно ни у скрипта, ни онлайн."""
    port = 18331
    env = {**os.environ, "STOOLS_FAKE_VARIANT": "params"}
    server = subprocess.Popen([sys.executable, "-m", "tests.ksc.fake_ksc_http", str(port)], cwd=Path.cwd(), env=env)
    try:
        for _ in range(50):
            try:
                socket.create_connection(("127.0.0.1", port), timeout=0.2).close()
                break
            except OSError:
                time.sleep(0.1)
        out = tmp_path / "policy_contents_params"
        out.mkdir()
        docker = ["docker", "run", "--rm", "--add-host=host.docker.internal:host-gateway", "-e", f"STOOLS_KSC_PASSWORD={PASSWORD}",
                  "-v", f"{SCRIPT.resolve().parent}:/script:ro", "-v", f"{out}:/out", IMAGE, "pwsh", "-File", "/script/STools-KSC-Collector.ps1",
                  "-Server", "host.docker.internal", "-Port", str(port), "-Scheme", "http", "-User", USER, "-Internal", "-OutputPath", "/out/ksc.json.gz"]
        run = subprocess.run(docker, capture_output=True, text=True, timeout=300, check=False)
        assert run.returncode == 0, run.stdout + run.stderr
        script_raw = json.loads(gzip.decompress((out / "ksc.json.gz").read_bytes()))["policy_contents"]

        from api.modules.ksc.core.client import KscClient
        from api.modules.ksc.core.collector import collect

        with KscClient(f"http://127.0.0.1:{port}", USER, PASSWORD) as c:
            online_raw = collect(c, username=USER)["policy_contents"]
    finally:
        server.terminate()
    assert set(script_raw) == {"1", "3"} and "9" not in script_raw
    assert script_raw == online_raw
    # секреты скрыты на месте, сквозь обёртки params; списки из одного элемента и пустые остаются
    # списками, вложенность глубже 20 уровней не обрезана
    assert_secrets_hidden(script_raw)
    assert_storage_shapes(script_raw)
    assert script_raw["1"]["sections"]["KLPRSS_Basic"]["type"] == "params"  # обёртки на месте


@pytest.mark.skipif(not _image_present(), reason=f"нужен docker и образ {IMAGE}")
def test_script_policy_contents_survives_denied_policy_and_section(tmp_path: Path) -> None:
    """Отказ (403) на политику 3 и PxgError на одну секцию политики 1 не роняют сбор остального."""
    export = load_export(_run_script(tmp_path, 18332, "policy_denied").read_bytes())
    assert "3" not in export.policy_contents
    assert any("policy_contents[3]" in w for w in export.server.warnings)
    pol1 = export.policy_contents["1"]
    assert pol1["errors"] and pol1["errors"][0].startswith("KLPRSS_Components:")
    assert set(pol1["sections"]) == {"KLPRSS_Basic", "KLPRSS_Password", "KLPRSS_Passwords", "KLPRSS_Secret", "KLPRSS_Deep"}


@pytest.mark.skipif(not _image_present(), reason=f"нужен docker и образ {IMAGE}")
def test_script_records_policies_skipped_by_limit(tmp_path: Path) -> None:
    """Копия скрипта с лимитом 1 политика: вторая записывается с `errors == ["лимит политик"]`
    и пустыми секциями (как у онлайн-сборщика), предупреждение одно."""
    script_dir = tmp_path / "script"
    script_dir.mkdir()
    text = SCRIPT.read_text(encoding="utf-8-sig")
    assert text.count("$PolicyContentsMaxPolicies = 200") == 1
    (script_dir / SCRIPT.name).write_text(text.replace("$PolicyContentsMaxPolicies = 200", "$PolicyContentsMaxPolicies = 1"), encoding="utf-8-sig")
    export = load_export(_run_script(tmp_path, 18340, "", script_dir=script_dir).read_bytes())
    assert set(export.policy_contents) == {"1", "3"} and export.policy_contents["1"]["sections"]
    assert export.policy_contents["3"] == {"product": "KES", "version": "12.0.0.0", "sections": {}, "errors": ["лимит политик"]}
    assert sum("политик больше лимита" in w for w in export.server.warnings) == 1


@pytest.mark.skipif(not _image_present(), reason=f"нужен docker и образ {IMAGE}")
def test_script_hides_secrets_sanitises_file_name_and_deletes_config(tmp_path: Path) -> None:
    """Аудит M4, L8, M5 одним прогоном: секреты под новыми маркерами, двоичное значение под обычным
    ключом и параметры задач скрыты; имя сервера «ksc 01/lab» идёт в имя файла как «ksc_01_lab»;
    ключ `delete_after_run` в файле настроек удаляет его после успешного сбора."""
    config = {"server": "host.docker.internal", "scheme": "http", "user": USER, "password": PASSWORD, "internal": True,
              "output_path": "/out/", "delete_after_run": True}
    run_dir = _run_script(tmp_path, 18350, "secrets", config).parent
    files = sorted(p.name for p in run_dir.iterdir())
    assert len(files) == 1 and re.fullmatch(r"ksc-ksc_01_lab-\d{8}-\d{4}\.json\.gz", files[0]), files  # config.json удалён
    data = (run_dir / files[0]).read_bytes()
    raw = gzip.decompress(data).decode("utf-8")
    assert not [v for v in BAIT_VALUES if v in raw]
    export = load_export(data)
    assert export.server.name == "ksc 01/lab"  # в самой выгрузке имя сервера как есть
    assert_bait_hidden(export)


@pytest.mark.skipif(not _image_present(), reason=f"нужен docker и образ {IMAGE}")
def test_script_delete_config_switch_only_after_success(tmp_path: Path) -> None:
    """-DeleteConfigAfterRun: вход отклонён — файл настроек остаётся; сбор прошёл — удалён."""
    base = {"server": "host.docker.internal", "scheme": "http", "user": USER, "internal": True, "output_path": "/out/ksc.json.gz"}
    (tmp_path / "bad").mkdir()
    failed = _run_script(tmp_path / "bad", 18351, "", {**base, "password": "wrong"}, extra_args=("-DeleteConfigAfterRun",), expect_ok=False).parent
    assert (failed / "config.json").exists() and not (failed / "ksc.json.gz").exists()
    (tmp_path / "ok").mkdir()
    done = _run_script(tmp_path / "ok", 18352, "", {**base, "password": PASSWORD}, extra_args=("-DeleteConfigAfterRun",))
    assert done.exists() and not (done.parent / "config.json").exists()


def _tls_type_source() -> str:
    text = SCRIPT.read_text(encoding="utf-8-sig")
    m = re.search(r'Add-Type -TypeDefinition @"\n(.*?)\n"@', text, re.DOTALL)
    assert m is not None
    return m.group(1)


@pytest.mark.skipif(not _image_present(), reason=f"нужен docker и образ {IMAGE}")
def test_tls_callback_trusts_only_the_ksc_host(tmp_path: Path) -> None:
    """Аудит M3: обработчик сертификата для Windows PowerShell 5.1 (компилируется тот же код, что в
    скрипте) пропускает без проверки только адрес KSC, остальные — прежнему обработчику или
    стандартной проверке; Restore возвращает прежний обработчик."""
    (tmp_path / "KscTls.cs").write_text(_tls_type_source(), encoding="utf-8")
    probe = r"""
Set-StrictMode -Version Latest
$ErrorActionPreference = "Stop"
Add-Type -TypeDefinition (Get-Content -Raw /t/KscTls.cs)
$bad = [System.Net.Security.SslPolicyErrors]::RemoteCertificateChainErrors
$ok = [System.Net.Security.SslPolicyErrors]::None
$ksc = [System.Net.WebRequest]::Create("https://KSC01.corp.local:13299/api/v1.0/")
$other = [System.Net.WebRequest]::Create("https://evil.example/")
$prev = [System.Net.ServicePointManager]::ServerCertificateValidationCallback
[STools.KscTls]::Enable("ksc01.corp.local")
$r = [ordered]@{
  hooked = $null -ne [System.Net.ServicePointManager]::ServerCertificateValidationCallback
  ksc = [STools.KscTls]::Validate($ksc, $null, $null, $bad)
  ksc_name = [STools.KscTls]::Validate("ksc01.corp.local", $null, $null, $bad)
  other_bad = [STools.KscTls]::Validate($other, $null, $null, $bad)
  other_ok = [STools.KscTls]::Validate($other, $null, $null, $ok)
  unknown_sender = [STools.KscTls]::Validate($null, $null, $null, $bad)
}
[STools.KscTls]::Restore()
$r.restored = [object]::ReferenceEquals($prev, [System.Net.ServicePointManager]::ServerCertificateValidationCallback)
$r | ConvertTo-Json -Compress
"""
    (tmp_path / "probe.ps1").write_text(probe, encoding="utf-8")
    run = subprocess.run(["docker", "run", "--rm", "-v", f"{tmp_path}:/t:ro", IMAGE, "pwsh", "-File", "/t/probe.ps1"],
                         capture_output=True, text=True, timeout=120, check=False)
    assert run.returncode == 0, run.stdout + run.stderr
    assert json.loads(run.stdout.strip().splitlines()[-1]) == {
        "hooked": True, "ksc": True, "ksc_name": True, "other_bad": False, "other_ok": True, "unknown_sender": False, "restored": True,
    }


@pytest.mark.skipif(not _image_present(), reason=f"нужен docker и образ {IMAGE}")
def test_script_restores_tls_callback_after_success_and_failure(tmp_path: Path) -> None:
    """Ветка Windows PowerShell 5.1 (включена в копии скрипта): после сбора и после отказа во входе
    в процессе остаётся прежний обработчик сертификата, а не обработчик скрипта."""
    script_dir = tmp_path / "script"
    script_dir.mkdir()
    text = SCRIPT.read_text(encoding="utf-8-sig")
    hook = "$tlsHook = $SkipTlsCheck -and $PSVersionTable.PSVersion.Major -lt 6"
    assert text.count(hook) == 1
    (script_dir / SCRIPT.name).write_text(text.replace(hook, "$tlsHook = [bool]$SkipTlsCheck"), encoding="utf-8-sig")
    port = 18353
    server = subprocess.Popen([sys.executable, "-m", "tests.ksc.fake_ksc_http", str(port)], cwd=Path.cwd(), env={**os.environ, "STOOLS_FAKE_VARIANT": ""})
    try:
        for _ in range(50):
            try:
                socket.create_connection(("127.0.0.1", port), timeout=0.2).close()
                break
            except OSError:
                time.sleep(0.1)
        out = tmp_path / "out"
        out.mkdir()
        args = f"-Server host.docker.internal -Port {port} -Scheme http -User {USER} -Internal -SkipTlsCheck"
        probe = f"""
$prev = [System.Net.Security.RemoteCertificateValidationCallback]{{ param($s, $c, $ch, $e) $false }}
[System.Net.ServicePointManager]::ServerCertificateValidationCallback = $prev
$env:STOOLS_KSC_PASSWORD = "{PASSWORD}"
& /script/{SCRIPT.name} {args} -OutputPath /out/ok.json.gz *> $null
$afterOk = [object]::ReferenceEquals($prev, [System.Net.ServicePointManager]::ServerCertificateValidationCallback)
$env:STOOLS_KSC_PASSWORD = "wrong"
$failed = $false
try {{ & /script/{SCRIPT.name} {args} -OutputPath /out/bad.json.gz *> $null }} catch {{ $failed = $true }}
$afterFail = [object]::ReferenceEquals($prev, [System.Net.ServicePointManager]::ServerCertificateValidationCallback)
[ordered]@{{ compiled = [bool]("STools.KscTls" -as [type]); after_ok = $afterOk; failed = $failed; after_fail = $afterFail }} | ConvertTo-Json -Compress
"""
        docker = ["docker", "run", "--rm", "--add-host=host.docker.internal:host-gateway", "-v", f"{script_dir}:/script:ro", "-v", f"{out}:/out",
                  IMAGE, "pwsh", "-Command", probe]
        run = subprocess.run(docker, capture_output=True, text=True, timeout=300, check=False)
    finally:
        server.terminate()
    assert run.returncode == 0, run.stdout + run.stderr
    assert json.loads(run.stdout.strip().splitlines()[-1]) == {"compiled": True, "after_ok": True, "failed": True, "after_fail": True}
    assert (out / "ok.json.gz").exists() and not (out / "bad.json.gz").exists()


def test_init_config_grants_modify_to_domain_qualified_user() -> None:
    """Windows: право (M) — чтение, запись и удаление (иначе `-DeleteConfigAfterRun`
    не удалит файл после /inheritance:r), учётка с доменом — имя без домена
    icacls может разрешить в одноимённую локальную. Ветку icacls в контейнере
    Linux не прогнать, поэтому проверяется текст скрипта."""
    text = SCRIPT.read_text(encoding="utf-8-sig")
    assert '/grant:r "$($env:USERDOMAIN)\\$($env:USERNAME):(M)"' in text
    assert "(R,W)" not in text


@pytest.mark.skipif(not _image_present(), reason=f"нужен docker и образ {IMAGE}")
def test_init_config_aborts_when_permissions_cannot_be_set(tmp_path: Path) -> None:
    """Не удалось закрыть доступ к файлу — скрипт падает, а не пишет «шаблон записан»."""
    fakebin = tmp_path / "fakebin"
    fakebin.mkdir()
    fake_chmod = fakebin / "chmod"
    fake_chmod.write_text("#!/bin/sh\nexit 1\n")
    fake_chmod.chmod(0o755)
    cmd = ["docker", "run", "--rm", "-v", f"{SCRIPT.resolve().parent}:/script:ro", "-v", f"{tmp_path}:/out",
           "-e", "PATH=/out/fakebin:/usr/local/sbin:/usr/local/bin:/usr/sbin:/usr/bin:/sbin:/bin:/opt/microsoft/powershell/7",
           IMAGE, "pwsh", "-File", "/script/STools-KSC-Collector.ps1", "-InitConfig", "/out/ksc-config.json"]
    run = subprocess.run(cmd, capture_output=True, text=True, timeout=120, check=False)
    assert run.returncode != 0, run.stdout + run.stderr
    assert "Не удалось закрыть доступ к файлу настроек" in run.stdout + run.stderr
    assert "Шаблон записан" not in run.stdout
