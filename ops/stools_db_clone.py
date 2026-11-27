"""Stream a restored database into a transformed clone; PostgreSQL validates the result."""

from __future__ import annotations

import base64
import csv
import hashlib
import io
import json
import os
import re
import secrets
import subprocess
import tempfile
from itertools import islice

from stools_db import BackupError, identifier, literal
from stools_db_masking import SECRET, MaskError, dumps, loads

SOURCE = "stools_source"
TARGET = "stools_anonymized"

CATALOG = """SELECT coalesce(json_agg(x ORDER BY x.schema,x.name),'[]') FROM (
SELECT n.nspname AS schema,c.relname AS name,c.relkind AS kind,
 (SELECT coalesce(json_agg(json_build_object('name',a.attname,
 'type',bt.typname,'category',bt.typcategory,'element',et.typname,
 'generated',a.attgenerated,'identity',a.attidentity) ORDER BY a.attnum),'[]')
 FROM pg_attribute a JOIN pg_type t ON t.oid=a.atttypid
 JOIN pg_type bt ON bt.oid=CASE WHEN t.typbasetype=0 THEN t.oid ELSE t.typbasetype END
 LEFT JOIN pg_type et ON et.oid=bt.typelem
 WHERE a.attrelid=c.oid AND a.attnum>0 AND NOT a.attisdropped) AS columns
FROM pg_class c JOIN pg_namespace n ON n.oid=c.relnamespace
WHERE n.nspname NOT LIKE 'pg_%' AND n.nspname<>'information_schema'
 AND c.relkind IN ('r','p','f','m')) x"""


def qualified(table):
    return identifier(table["schema"]) + "." + identifier(table["name"])


def catalog(pg, database):
    pg.phase(f"Чтение каталога таблиц ({database})", announce=False)
    rows = json.loads(pg.sql(CATALOG, database))
    if any(row["kind"] != "r" for row in rows):
        raise MaskError(
            "Разделённые/внешние таблицы или materialized views требуют отдельного обработчика; экспорт остановлен."
        )
    if int(pg.sql("SELECT count(*) FROM pg_inherits", database)):
        raise MaskError(
            "Наследование таблиц не поддерживается; строки не будут пропущены молча."
        )
    if int(pg.sql("SELECT count(*) FROM pg_largeobject_metadata", database)):
        raise MaskError(
            "В БД есть PostgreSQL large objects: непрозрачное содержимое нельзя выдать как обезличенное."
        )
    return rows


def counts(pg, database, tables):
    pg.phase(f"Сверка числа строк ({database})", announce=False)
    if not tables:
        return {}
    queries = [
        "SELECT "
        + literal(qualified(t))
        + " AS name, count(*) AS n FROM "
        + qualified(t)
        for t in tables
    ]
    return json.loads(
        pg.sql(
            "SELECT json_object_agg(name,n) FROM ("
            + " UNION ALL ".join(queries)
            + ") x",
            database,
        )
    )


def sequence_values(pg, database):
    pg.phase(f"Чтение списка последовательностей ({database})", announce=False)
    names = json.loads(
        pg.sql(
            "SELECT coalesce(json_agg(json_build_array(n.nspname,c.relname) ORDER BY n.nspname,c.relname),'[]') FROM pg_class c JOIN pg_namespace n ON n.oid=c.relnamespace WHERE c.relkind='S' AND n.nspname NOT LIKE 'pg_%' AND n.nspname<>'information_schema'",
            database,
        )
    )
    result = {}
    for schema, name in names:
        full = identifier(schema) + "." + identifier(name)
        pg.phase(f"Чтение последовательности {full} ({database})", announce=False)
        result[full] = json.loads(
            pg.sql(
                "SELECT json_build_array(last_value::text,is_called) FROM "
                + full
                + " LIMIT 1",
                database,
            )
        )
    return result


def create_database(pg, name, metadata):
    args = [
        "--template=template0",
        "--encoding=" + metadata["encoding"],
        "--lc-collate=" + metadata["collate"],
        "--lc-ctype=" + metadata["ctype"],
    ]
    provider = metadata.get("locale_provider", "c")
    if provider not in ("c", "i"):
        raise MaskError(
            "Неподдерживаемый провайдер locale PostgreSQL; доступны libc и ICU."
        )
    args.append("--locale-provider=" + ("icu" if provider == "i" else "libc"))
    if provider == "i":
        args.append("--icu-locale=" + metadata["locale"])
    pg.run("createdb", *args, name)


def _fernet(secret):
    try:
        from cryptography.fernet import Fernet
        from cryptography.hazmat.primitives import hashes
        from cryptography.hazmat.primitives.kdf.hkdf import HKDF
    except ImportError:
        raise MaskError(
            "Для зашифрованных исходных конфигураций нужен пакет cryptography; обычные поля обрабатываются без него."
        ) from None
    key = HKDF(
        algorithm=hashes.SHA256(), length=32, salt=None, info=b"stools-secrets-v1"
    ).derive(secret.encode("utf-8"))
    return Fernet(base64.urlsafe_b64encode(key))


class Values:
    def __init__(self, rules, source_secret=None):
        self.rules = rules
        self.source_secret = source_secret
        self.target_secret = secrets.token_hex(32)
        self.originals = {}
        self.reencrypted = 0
        self.credentials_reset = 0
        self.operational_disabled = 0

    def encrypted_original(self, value):
        if value in self.originals:
            return self.originals[value][0]
        if not value.startswith("enc:"):
            cleaned = self.rules.walk(value)
            self.originals[value] = (
                cleaned,
                hashlib.sha256(cleaned.encode("utf-8")).hexdigest(),
            )
            return cleaned
        if not value.startswith("enc:v1:") or not self.source_secret:
            raise MaskError(
                "Для сохранения зашифрованных исходных конфигураций задайте исходный STOOLS_SESSION_SECRET через --source-secret-env; ключ не передаётся в аргументах и не выводится."
            )
        try:
            plain = (
                _fernet(self.source_secret)
                .decrypt(value[len("enc:v1:") :].encode("ascii"))
                .decode("utf-8")
            )
        except MaskError:
            raise
        except Exception:  # noqa: BLE001 — optional crypto backends may include input in exceptions
            raise MaskError(
                "Не удалось расшифровать исходную конфигурацию; проверьте ключ и версию. Оригинал не будет пропущен в результат."
            ) from None
        cleaned = self.rules.walk(plain)
        self.reencrypted += 1
        result = "enc:v1:" + _fernet(self.target_secret).encrypt(
            cleaned.encode("utf-8")
        ).decode("ascii")
        self.originals[value] = (
            result,
            hashlib.sha256(cleaned.encode("utf-8")).hexdigest(),
        )
        return result

    def setting(self, row, value):
        key = row.get("key", "")
        if key == "siem_finding_key":
            # A deduplication salt, not a login credential; decisions reference its hashes.
            return value
        if key == "mail.password" or (key.startswith("llm.") and key.endswith("_key")):
            self.credentials_reset += bool(value)
            return ""
        if SECRET.fullmatch(key):
            self.credentials_reset += bool(value)
            return dumps("") if value.startswith(chr(34)) else ""
        if not value.strip():
            return value
        parsed = loads(value)
        cleaned = self.rules.walk(parsed, secrets=True)

        # These are application execution controls, never AD/KSC policy flags.
        def disable(item):
            if isinstance(item, dict):
                for k, v in list(item.items()):
                    if k in (
                        "enabled",
                        "nightly_enabled",
                        "auto_sync",
                        "auto_sync_enabled",
                    ) and isinstance(v, bool):
                        if v:
                            self.operational_disabled += 1
                        item[k] = False
                    elif isinstance(v, (dict, list)):
                        disable(v)
            elif isinstance(item, list):
                for v in item:
                    disable(v)

        if any(
            token in key.lower()
            for token in (
                "mail",
                "oidc",
                "collector",
                "connection",
                "hunting.settings",
                "siem_th",
                "llm",
                "notifications",
                "monitoring",
            )
        ):
            disable(cleaned)
        return dumps(cleaned)

    def cell(self, table, column, value, row, *, schema=None):
        if value is None:
            return None
        name, kind = column["name"], column["type"]
        if table == "app_user" and name == "is_active":
            self.operational_disabled += value == "t"
            return "f"
        if (
            table in ("platform_schedule", "radar_nettrace_config")
            and name == "enabled"
        ):
            self.operational_disabled += value == "t"
            return "f"
        if (
            table in ("platform_sync_run", "platform_sync_step")
            and name == "status"
            and value in ("queued", "pending", "starting", "running")
        ):
            self.operational_disabled += 1
            return "cancelled"
        if table in ("session", "oidc_login_state") and name in (
            "token",
            "state",
            "nonce",
            "code_verifier",
        ):
            self.credentials_reset += 1
            return hashlib.sha256(
                (self.target_secret + "\0" + value).encode()
            ).hexdigest()
        if table == "app_setting" and name == "value_json":
            return self.setting(row, value)
        if table == "toolbox_settings" and name == "key":
            self.credentials_reset += 1
            return "\\x" + secrets.token_hex(32)
        if (
            table == "radar_snapshot"
            and name == "sha256"
            and row.get("original_encrypted")
        ):
            try:
                self.encrypted_original(row["original_encrypted"])
            except MaskError as error:
                error.context.append(
                    'Исходное поле для контрольной суммы — "original_encrypted".'
                )
                raise
            return self.originals[row["original_encrypted"]][1]
        if name == "original_encrypted":
            return self.encrypted_original(value)
        if SECRET.fullmatch(name):
            self.credentials_reset += bool(value)
            return None if table == "app_user" and name == "password_hash" else ""
        if kind == "bytea":
            if value not in ("", "\\x"):
                raise MaskError(
                    "Неизвестное двоичное поле: его нельзя молча оставить в обезличенной базе."
                )
            return value
        if column["category"] == "A":
            return self.rules.array(value, column["element"])
        if kind in ("json", "jsonb") or name.endswith("_json"):
            return self.rules.json(value, secrets=True) if value.strip() else value
        if kind == "xml":
            return self.rules.xml(value, secrets=True)
        if column["category"] == "S" or kind in (
            "tsvector",
            "tsquery",
            "uuid",
            "inet",
            "cidr",
            "macaddr",
            "macaddr8",
        ):
            if value.startswith("enc:"):
                raise MaskError(
                    "Неизвестное зашифрованное поле: нельзя гарантировать отсутствие исходных данных."
                )
            advisory_prose = (
                table == "vm_ref_ghsa"
                and schema == "public"
                and kind == "text"
                and name in ("summary", "description")
            )
            return self.rules.walk(value, name, advisory_prose=advisory_prose)
        if column["category"] in ("B", "N", "D", "T", "E"):
            return value
        raise MaskError(
            "Неподдерживаемый тип SQL-столбца; непрозрачные данные не экспортируются."
        )


def copy_text(value):
    if value is None:
        return "\\N"
    return (
        value.replace("\\", "\\\\")
        .replace("\t", "\\t")
        .replace("\n", "\\n")
        .replace("\r", "\\r")
    )


def copy_table(pg, table, values):
    columns = [c for c in table["columns"] if not c["generated"]]
    if not columns:
        raise MaskError("Таблица без записываемых столбцов пока не поддерживается.")
    expressions = []
    for c in columns:
        name = identifier(c["name"])
        expressions.append(
            "CASE WHEN "
            + name
            + " IS NULL THEN NULL ELSE json_build_object('dims',array_dims("
            + name
            + "),'values',array_to_json("
            + name
            + "))::text END"
            if c["category"] == "A"
            else name
        )
    nulls = (
        "array_to_string(ARRAY["
        + ",".join("(" + identifier(c["name"]) + " IS NULL)::int" for c in columns)
        + "],'')"
    )
    read = (
        "COPY (SELECT "
        + ",".join(expressions + [nulls])
        + " FROM ONLY "
        + qualified(table)
        + ") TO STDOUT WITH (FORMAT csv)"
    )
    write = (
        "COPY "
        + qualified(table)
        + "("
        + ",".join(identifier(c["name"]) for c in columns)
        + ") FROM STDIN WITH (FORMAT text)"
    )
    reader = writer = None
    count = 0
    with (
        tempfile.TemporaryFile() as reader_errors,
        tempfile.TemporaryFile() as writer_errors,
    ):
        try:
            reader = subprocess.Popen(
                pg.command(
                    "psql",
                    "-X",
                    "-q",
                    "-v",
                    "ON_ERROR_STOP=1",
                    "--dbname=" + SOURCE,
                    "-c",
                    read,
                ),
                stdout=subprocess.PIPE,
                stderr=reader_errors,
            )
            writer = subprocess.Popen(
                pg.command(
                    "psql",
                    "-X",
                    "-q",
                    "-v",
                    "ON_ERROR_STOP=1",
                    "--dbname=" + TARGET,
                    "-c",
                    write,
                ),
                stdin=subprocess.PIPE,
                stdout=subprocess.DEVNULL,
                stderr=writer_errors,
            )
            csv.field_size_limit(1024**3)
            with io.TextIOWrapper(
                reader.stdout, encoding="utf-8", newline=""
            ) as stream:
                for cells in csv.reader(stream):
                    flags = cells.pop()
                    if (
                        len(cells) != len(columns)
                        or len(flags) != len(columns)
                        or set(flags) - {"0", "1"}
                    ):
                        raise MaskError(f"Некорректная строка COPY {count + 1}.")
                    raw = [
                        None if flag == "1" else value
                        for flag, value in zip(flags, cells)
                    ]
                    row = dict(zip((c["name"] for c in columns), raw))
                    values.originals.clear()
                    transformed = []
                    for col, value in zip(columns, raw):
                        try:
                            transformed.append(
                                values.cell(
                                    table["name"],
                                    col,
                                    value,
                                    row,
                                    schema=table["schema"],
                                )
                            )
                        except MaskError as error:
                            position = f"Столбец {identifier(col['name'])}, строка COPY {count + 1}"
                            if row.get("id") is not None and any(
                                c["name"] == "id"
                                and c["type"] in ("int2", "int4", "int8")
                                for c in columns
                            ):
                                position += f", id={int(row['id'])}"
                            error.context.append(position + ".")
                            raise
                    writer.stdin.write(
                        ("\t".join(copy_text(v) for v in transformed) + "\n").encode(
                            "utf-8"
                        )
                    )
                    count += 1
            writer.stdin.close()
            if reader.wait():
                raise pg.failure("psql (чтение COPY)", reader.returncode, reader_errors)
            if writer.wait():
                raise pg.failure("psql (запись COPY)", writer.returncode, writer_errors)
            return count
        except BrokenPipeError:
            if writer is not None:
                try:
                    status = writer.wait(timeout=5)
                except subprocess.TimeoutExpired:
                    status = None
                if status:
                    raise pg.failure(
                        "psql (запись COPY)", status, writer_errors
                    ) from None
            raise MaskError(
                "Поток записи COPY закрылся до завершения переноса."
            ) from None
        except (UnicodeError, csv.Error):
            raise MaskError(
                "Перенос строки не завершён; исходные данные и SQL-ошибка скрыты."
            ) from None
        finally:
            for process in (reader, writer):
                if process is not None:
                    if process.poll() is None:
                        process.terminate()
                        try:
                            process.wait(timeout=5)
                        except subprocess.TimeoutExpired:
                            process.kill()
                            process.wait()
                    for stream in (process.stdin, process.stdout):
                        if stream is not None:
                            try:
                                stream.close()
                            except (BrokenPipeError, OSError):
                                pass


def schema_section(pg, section, work, rules):
    description = (
        "таблицы и типы" if section == "pre-data" else "индексы, ограничения и триггеры"
    )
    pg.phase(f"Схема PostgreSQL ({section}) — {description}")
    path = work / (section + ".sql")
    with path.open("wb") as target:
        os.chmod(str(path), 0o600)
        pg.run(
            "pg_dump",
            "--schema-only",
            "--section=" + section,
            "--no-owner",
            "--no-privileges",
            "--no-tablespaces",
            "--dbname=" + SOURCE,
            output=target,
        )
    if path.stat().st_size > 128 * 1024**2:
        raise MaskError("SQL-схема больше 128 МиБ; требуется отдельная проверка.")
    sql = path.read_text(encoding="utf-8")
    try:
        if rules.text(sql) != sql:
            raise MaskError(
                "Конфиг затрагивает SQL-схему или её значения по умолчанию; автоматическое изменение структуры запрещено."
            )
    except MaskError as error:
        error.context.append(f"Проверка SQL-схемы PostgreSQL ({section}).")
        raise
    try:
        with path.open("rb") as source:
            pg.run(
                "psql",
                "-X",
                "-q",
                "-v",
                "ON_ERROR_STOP=1",
                "--dbname=" + TARGET,
                "-f",
                "-",
                source=source,
                output=subprocess.DEVNULL,
            )
    except BackupError as error:
        if not error.sql_line:
            raise
        # Use pg_dump's object header at the failing line; never echo the statement.
        obj = None
        with path.open(encoding="utf-8") as source:
            for line in islice(source, error.sql_line):
                if line.startswith("-- Name: "):
                    obj = re.fullmatch(
                        r"-- Name: ([\w.-]{1,63}(?: [\w.-]{1,63})?); Type: ([A-Z ]{1,32}); Schema: ([\w.-]{1,63}); Owner: [^\r\n]*",
                        line.rstrip("\r\n"),
                        re.ASCII,
                    )
        if not obj:
            raise
        name, kind, schema = obj.groups()
        context = f'Объект {section}.sql — {kind} "{name}", схема "{schema}".'
        pg.note(context)
        raise BackupError(f"{error}\n{context}", sql_line=error.sql_line) from None


def clone(pg, rules, work, source_secret=None):
    pg.phase("Подготовка обезличенной базы")
    tables = catalog(pg, SOURCE)
    before = counts(pg, SOURCE, tables)
    sequences = sequence_values(pg, SOURCE)
    pg.phase("Создание базы назначения", announce=False)
    create_database(pg, TARGET, pg.info(SOURCE))
    schema_section(pg, "pre-data", work, rules)
    values = Values(rules, source_secret)
    for number, table in enumerate(tables, 1):
        name = qualified(table)
        pg.phase(f"Обезличивание: таблица {number}/{len(tables)} {name}")
        try:
            copied = copy_table(pg, table, values) if before[name] else 0
            if copied != before[name]:
                raise MaskError("Количество перенесённых строк не совпало с исходным.")
            pg.note(f"Скопировано строк из {name}: {copied}")
        except MaskError as error:
            error.context.append(f"Таблица {name} ({number}/{len(tables)}).")
            raise
    if not rules.changed_values:
        raise MaskError(
            "Ни одно исходное значение из конфига не найдено: выдавать эту копию как обезличенную нельзя."
        )
    pg.phase("Восстановление значений последовательностей")
    for name, (value, called) in sequences.items():
        pg.phase(f"Установка значения последовательности {name}", announce=False)
        pg.sql(
            "SELECT pg_catalog.setval("
            + literal(name)
            + ", "
            + str(int(value))
            + ", "
            + ("true" if called else "false")
            + ")",
            TARGET,
        )
    schema_section(pg, "post-data", work, rules)
    pg.phase("Сверка схемы, числа строк и последовательностей")
    after_tables = catalog(pg, TARGET)
    if (
        tables != after_tables
        or before != counts(pg, TARGET, after_tables)
        or sequences != sequence_values(pg, TARGET)
    ):
        raise MaskError("Схема, количество строк или последовательности изменились.")
    # Explicitly validate NOT VALID constraints too; the output must not hide broken references.
    pg.phase("Проверка ограничений NOT VALID")
    constraints = json.loads(
        pg.sql(
            "SELECT coalesce(json_agg(json_build_array(n.nspname,c.relname,k.conname)),'[]') FROM pg_constraint k JOIN pg_class c ON c.oid=k.conrelid JOIN pg_namespace n ON n.oid=c.relnamespace WHERE n.nspname NOT LIKE 'pg_%' AND k.contype IN ('f','c') AND NOT k.convalidated",
            TARGET,
        )
    )
    for schema, table, name in constraints:
        pg.phase(
            f"VALIDATE CONSTRAINT {identifier(name)} для {identifier(schema)}.{identifier(table)}",
            announce=False,
        )
        pg.sql(
            "ALTER TABLE "
            + identifier(schema)
            + "."
            + identifier(table)
            + " VALIDATE CONSTRAINT "
            + identifier(name),
            TARGET,
        )
    pg.phase("Сбор статистики PostgreSQL (ANALYZE)")
    pg.sql("ANALYZE", TARGET)
    return (
        {
            "tables": before,
            "rows": sum(before.values()),
            "table_count": len(tables),
            "changed_values": rules.changed_values,
            "credentials_reset": values.credentials_reset,
            "operational_disabled": values.operational_disabled,
            "reencrypted_payloads": values.reencrypted,
        },
        values.target_secret,
        tables,
        sequences,
    )
