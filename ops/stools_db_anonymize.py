#!/usr/bin/env python3
"""Anonymize a trusted STools pg_dump in an isolated disposable PostgreSQL.

Python 3.7.3+, Docker CLI; see docs/database-anonymization.md.
Copy this file with stools_db.py, stools_db_clone.py and stools_db_masking.py.
"""

from __future__ import annotations

import argparse
import hashlib
import json
import os
import re
import shutil
import signal
import stat
import subprocess
import sys
import tempfile
import time
import uuid
from contextlib import contextmanager
from datetime import datetime, timezone
from pathlib import Path

from stools_db import BackupError, Postgres, backup, digest, identifier, read_manifest
from stools_db_clone import (
    SOURCE,
    TARGET,
    catalog,
    clone,
    counts,
    create_database,
    sequence_values,
)
from stools_db_masking import MaskError, load_config

LABEL = "stools.db-anonymize.job"


def docker(*args):
    try:
        result = subprocess.run(
            ["docker", *args],
            capture_output=True,
            check=False,
            timeout=60,
        )
    except (OSError, subprocess.TimeoutExpired):
        raise MaskError("Docker недоступен или не ответил вовремя.") from None
    if result.returncode:
        raise MaskError(
            "Операция Docker не выполнена; исходные данные и вывод процесса скрыты. Проверьте Docker и свободное место."
        )
    return result.stdout.decode("utf-8").strip()


def inspect(kind, name):
    try:
        result = subprocess.run(
            ["docker", kind, "inspect", name],
            capture_output=True,
            check=False,
            timeout=15,
        )
    except (OSError, subprocess.TimeoutExpired):
        raise MaskError("Не удалось проверить временные ресурсы Docker.") from None
    if result.returncode:
        error = result.stderr.decode("utf-8", errors="replace").lower()
        if any(
            marker in error
            for marker in (
                "no such object:",
                "no such container:",
                "no such volume:",
                "no such image:",
            )
        ):
            return None
        raise MaskError(
            "Docker не подтвердил наличие или отсутствие ресурса; проверьте доступность Docker."
        )
    return json.loads(result.stdout)[0]


def cleanup(job, name, volume):
    # A second Ctrl+C must not interrupt removal of the original data volume.
    previous = {
        sig: signal.signal(sig, signal.SIG_IGN)
        for sig in (signal.SIGINT, signal.SIGTERM)
    }
    errors = []
    try:
        for kind, resource in (("container", name), ("volume", volume)):
            try:
                data = inspect(kind, resource)
                if data is None:
                    continue
                labels = (
                    data["Config"].get("Labels")
                    if kind == "container"
                    else data.get("Labels")
                )
                if (labels or {}).get(LABEL) != job:
                    raise MaskError("Метка ресурса не совпала.")
                docker("rm", "-fv", resource) if kind == "container" else docker(
                    "volume", "rm", resource
                )
            except (MaskError, OSError):
                errors.append(resource)
        if errors:
            raise MaskError(
                "Очистка не подтверждена для: "
                + ", ".join(errors)
                + ". Проверьте Docker и удалите только эти временные ресурсы с меткой "
                + LABEL
                + "."
            )
        print("Временный контейнер PostgreSQL и его том удалены.", flush=True)
    finally:
        for sig, handler in previous.items():
            signal.signal(sig, handler)


@contextmanager
def postgres(image):
    job = uuid.uuid4().hex
    name = "stools-anonymize-" + job[:16]
    volume = name + "-data"
    resources_started = False
    try:
        if inspect("image", image) is None:
            raise MaskError(
                "Нужен локальный образ PostgreSQL. Загрузите его заранее: docker pull <образ из --postgres-image>."
            )
        resources_started = True
        docker("volume", "create", "--label", LABEL + "=" + job, volume)
        docker(
            "run",
            "-d",
            "--pull=never",
            "--name",
            name,
            "--label",
            LABEL + "=" + job,
            "--network=none",
            "--log-driver=none",
            "--user=postgres",
            "--cap-drop=ALL",
            "--security-opt=no-new-privileges:true",
            "--mount",
            "type=volume,source=" + volume + ",target=/var/lib/postgresql/data",
            "-e",
            "PGDATA=/var/lib/postgresql/data/work",
            "-e",
            "POSTGRES_HOST_AUTH_METHOD=trust",
            "-e",
            "POSTGRES_DB=postgres",
            "-e",
            "PGCLIENTENCODING=UTF8",
            image,
        )
        for _ in range(120):
            ready = subprocess.run(
                [
                    "docker",
                    "exec",
                    name,
                    "pg_isready",
                    "-U",
                    "postgres",
                    "-d",
                    "postgres",
                ],
                stdout=subprocess.DEVNULL,
                stderr=subprocess.DEVNULL,
                check=False,
            )
            if ready.returncode == 0:
                break
            state = inspect("container", name)
            if not state or not state["State"]["Running"]:
                raise MaskError(
                    "Временный PostgreSQL не запустился; проверьте образ и место на диске."
                )
            time.sleep(0.5)
        else:
            raise MaskError("Временный PostgreSQL не стал готов за 60 секунд.")
        live = inspect("container", name)
        if (
            live["HostConfig"]["NetworkMode"] != "none"
            or live["HostConfig"].get("PortBindings")
            or live["HostConfig"]["LogConfig"]["Type"] != "none"
        ):
            raise MaskError("Изоляция временного PostgreSQL не подтверждена.")
        if any(m["Type"] != "volume" for m in live["Mounts"]):
            raise MaskError(
                "Недопустимое подключение файлов хоста к временному PostgreSQL."
            )
        print(
            "Временный PostgreSQL запущен без сети и опубликованных портов.", flush=True
        )
        yield Postgres(name)
    finally:
        if resources_started:
            cleanup(job, name, volume)


def input_backup(path):
    path = Path(path)
    if path.is_symlink():
        raise MaskError("Входной путь не должен быть символической ссылкой.")
    metadata = read_manifest(path) if path.is_dir() else None
    source = path / "database.dump" if metadata else path
    if source.is_symlink() or not source.is_file():
        raise MaskError("Укажите файл pg_dump -Fc или каталог бэкапа stools_db.py.")
    return source, metadata


def check_archive(pg, stream, metadata):
    info = os.fstat(stream.fileno())
    if not stat.S_ISREG(info.st_mode) or stream.read(5) != b"PGDMP":
        raise MaskError(
            "Поддерживается custom-дамп pg_dump -Fc. Текстовый SQL и физическая копия PGDATA не поддерживаются."
        )
    stream.seek(0)
    checksum = digest(stream)
    if metadata and (
        info.st_size != metadata["bytes"] or checksum != metadata["sha256"]
    ):
        raise MaskError("Дамп не совпадает с manifest.json по размеру или SHA-256.")
    stream.seek(0)
    listing = pg.run("pg_restore", "--list", source=stream)
    match = re.search(r"Dumped from database version:\s*(\d+)", listing)
    major = pg.version() // 10000
    if (
        major < 15
        or (metadata and metadata["server_version_num"] // 10000 != major)
        or (match and int(match[1]) != major)
    ):
        raise MaskError(
            "Основная версия PostgreSQL должна совпадать с исходной БД (поддерживаются 15+); задайте подходящий --postgres-image."
        )
    stream.seek(0)
    pg.run("pg_restore", "--file=/dev/null", source=stream)
    stream.seek(0)
    return checksum, (info.st_size, info.st_mtime_ns, info.st_ino)


def create_source_from_archive(pg, stream):
    # The archive retains CREATE DATABASE even when pg_dump was called without -C.
    stream.seek(0)
    listing = pg.run("pg_restore", "--list", "--create", source=stream)
    entries = [
        line
        for line in listing.splitlines()
        if re.match(r"^\d+; \d+ \d+ DATABASE - ", line)
    ]
    if len(entries) != 1:
        raise MaskError(
            "В дампе нет однозначного описания БД; используйте каталог с manifest.json."
        )
    pg.run(
        "sh",
        "-ec",
        "umask 077; cat > /tmp/stools-database.list",
        text=entries[0] + "\n",
    )
    stream.seek(0)
    ddl = pg.run(
        "pg_restore",
        "--create",
        "--schema-only",
        "--no-owner",
        "--no-privileges",
        "--no-tablespaces",
        "--file=-",
        "--use-list=/tmp/stools-database.list",
        source=stream,
    )
    statement = re.search(
        r'^CREATE DATABASE (?:"(?:[^"]|"")*"|[A-Za-z_][A-Za-z_0-9$]*) WITH ((?:[^;\'"]|\'(?:[^\']|\'\')*\'|"(?:[^"]|"")*")*);$',
        ddl,
        re.MULTILINE,
    )
    if not statement or len(ddl) > 65536:
        raise MaskError(
            "Не удалось безопасно прочитать encoding/locale из дампа; нужен каталог с manifest.json."
        )
    pg.sql(
        "CREATE DATABASE " + identifier(SOURCE) + " WITH " + statement.group(1) + ";"
    )
    stream.seek(0)


def write_private(path, text):
    with path.open("x", encoding="utf-8") as target:
        os.chmod(str(path), 0o600)
        target.write(text)
        target.flush()
        os.fsync(target.fileno())


def publish(bundle, output):
    # Exclusive mkdir avoids POSIX rename replacing a directory created by another job.
    output.mkdir(mode=0o700)
    owned = output.stat()
    try:
        for source in sorted(bundle.iterdir(), key=lambda p: p.name == "manifest.json"):
            source.rename(output / source.name)
    except BaseException:
        current = output.lstat()
        if (current.st_dev, current.st_ino) == (owned.st_dev, owned.st_ino):
            shutil.rmtree(str(output))
        raise


def run(
    source_path, config_path, output_path, postgres_image=None, source_secret_env=None
):
    rules = load_config(config_path)
    config_path = Path(config_path)
    config_hash = hashlib.sha256(config_path.read_bytes()).hexdigest()
    source, metadata = input_backup(source_path)
    output = Path(output_path)
    if output.exists() or output.is_symlink():
        raise MaskError("Выходной каталог уже существует; перезапись запрещена.")
    output.parent.mkdir(parents=True, exist_ok=True)
    original = source.resolve()
    if output.resolve() == original or (
        Path(source_path).is_dir()
        and Path(source_path).resolve() in output.resolve().parents
    ):
        raise MaskError("Результат должен находиться отдельно от исходного бэкапа.")
    image = postgres_image or (
        f"postgres:{metadata['server_version_num'] // 10000 if metadata else 16}-alpine"
    )
    if not isinstance(image, str) or not re.fullmatch(
        r"[A-Za-z0-9][A-Za-z0-9_./:@-]{0,250}", image
    ):
        raise MaskError("Некорректное имя образа PostgreSQL.")
    source_secret = os.environ.get(source_secret_env) if source_secret_env else None
    stage = Path(tempfile.mkdtemp(prefix=".stools-anonymize-", dir=str(output.parent)))
    os.chmod(str(stage), 0o700)
    bundle = stage / "backup"
    try:
        with source.open("rb") as stream, postgres(image) as pg:
            _, source_state = check_archive(pg, stream, metadata)
            if metadata:
                create_database(pg, SOURCE, metadata["database"])
            else:
                create_source_from_archive(pg, stream)
            print("Восстановление полного исходного бэкапа...", flush=True)
            pg.run(
                "pg_restore",
                "--exit-on-error",
                "--single-transaction",
                "--no-owner",
                "--no-privileges",
                "--no-tablespaces",
                "--dbname=" + SOURCE,
                source=stream,
                output=subprocess.DEVNULL,
            )
            current = os.fstat(stream.fileno())
            if (current.st_size, current.st_mtime_ns, current.st_ino) != source_state:
                raise MaskError("Исходный дамп изменился во время чтения.")
            report, target_secret, tables, sequences = clone(
                pg, rules, stage, source_secret
            )
            print("Создание обезличенного бэкапа...", flush=True)
            backup(pg, bundle, TARGET)
            # Reuse the source DB's space for a genuine restore test; the input file is untouched.
            pg.run("dropdb", SOURCE)
            create_database(pg, SOURCE, pg.info(TARGET))
            print("Проверка восстановления нового бэкапа...", flush=True)
            with (bundle / "database.dump").open("rb") as clean:
                pg.run(
                    "pg_restore",
                    "--exit-on-error",
                    "--single-transaction",
                    "--no-owner",
                    "--no-privileges",
                    "--no-tablespaces",
                    "--dbname=" + SOURCE,
                    source=clean,
                    output=subprocess.DEVNULL,
                )
            if (
                catalog(pg, SOURCE) != tables
                or counts(pg, SOURCE, tables) != report["tables"]
                or sequence_values(pg, SOURCE) != sequences
            ):
                raise MaskError(
                    "Пробное восстановление не подтвердило схему, строки или последовательности."
                )
            if hashlib.sha256(config_path.read_bytes()).hexdigest() != config_hash:
                raise MaskError("Конфиг изменился во время обработки.")
            report.update(
                {
                    "format": "stools-db-anonymize-report/1",
                    "created_at": datetime.now(timezone.utc).isoformat(),
                    "config_sha256": config_hash,
                    "restore_verified": True,
                    "scope": "explicit-config-and-stand-credential-reset",
                    "physical_size_preserved": False,
                    "source_configuration_included": False,
                }
            )
            write_private(
                bundle / "anonymization.json",
                json.dumps(report, ensure_ascii=False, indent=2) + "\n",
            )
            # Fresh key, unrelated to production; needed for preserved encrypted configurations.
            write_private(
                bundle / "stand.env", "STOOLS_SESSION_SECRET=" + target_secret + "\n"
            )
        # Publish only after the isolated container AND its data volume are gone.
        if output.exists() or output.is_symlink():
            raise MaskError(
                "Выходной путь появился во время обработки; результат не перезаписан."
            )
        for schema in stage.glob("*.sql"):
            schema.unlink()
        publish(bundle, output)
        print(
            f"Готово: {report['table_count']} таблиц, {report['rows']} строк; восстановление проверено. Правила замен не включены в бэкап.",
            flush=True,
        )
        return report
    finally:
        try:
            shutil.rmtree(str(stage))
        except OSError:
            raise MaskError(
                "Не удалось удалить временную папку "
                + str(stage)
                + "; удалите её после проверки прав и диска."
            ) from None


def main():
    parser = argparse.ArgumentParser(
        description="Обезличить полный pg_dump в отдельном PostgreSQL по внешнему конфигу замен."
    )
    parser.add_argument(
        "source", type=Path, help="database.dump (pg_dump -Fc) или каталог stools_db.py"
    )
    parser.add_argument(
        "--config",
        required=True,
        type=Path,
        help="отдельный JSON-конфиг from/to; в бэкап не попадает",
    )
    parser.add_argument(
        "-o",
        "--output",
        required=True,
        type=Path,
        help="новый каталог для обезличенного бэкапа",
    )
    parser.add_argument(
        "--postgres-image", help="локальный образ той же основной версии PostgreSQL"
    )
    parser.add_argument(
        "--source-secret-env",
        help="имя переменной окружения с исходным ключом, если нужно сохранить зашифрованные конфигурации",
    )
    args = parser.parse_args()

    def interrupted(signum, frame):
        raise KeyboardInterrupt

    old = signal.signal(signal.SIGTERM, interrupted)
    try:
        run(
            args.source,
            args.config,
            args.output,
            args.postgres_image,
            args.source_secret_env,
        )
        return 0
    except (MaskError, BackupError) as error:
        print("Ошибка: " + str(error), file=sys.stderr)
        return 1
    except KeyboardInterrupt:
        print(
            "Обработка отменена. Готовый бэкап не опубликован; исходный файл не изменён.",
            file=sys.stderr,
        )
        return 130
    except Exception as error:  # noqa: BLE001 — avoid printing sensitive driver/parser exception text
        print(
            "Ошибка операции ("
            + type(error).__name__
            + "); содержимое данных скрыто. Готовый бэкап не опубликован.",
            file=sys.stderr,
        )
        return 1
    finally:
        signal.signal(signal.SIGTERM, old)


if __name__ == "__main__":
    sys.exit(main())
