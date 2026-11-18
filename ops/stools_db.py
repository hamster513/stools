#!/usr/bin/env python3
"""Back up/verify/restore one STools PostgreSQL database through Docker.

Requires Python 3.10+ and Docker; PostgreSQL tools run inside the DB container.
See docs/database-backup.md. No application services are started or stopped.
"""
from __future__ import annotations

import argparse
from contextlib import contextmanager
from datetime import datetime, timezone
import hashlib
import json
import os
from pathlib import Path
import re
import stat
import subprocess
import sys
import uuid

FORMAT = 'stools-postgres-backup/1'
ENV = '''export PGUSER="${POSTGRES_USER:-postgres}"
export PGDATABASE="${POSTGRES_DB:-${POSTGRES_USER:-postgres}}"
export PGPASSWORD="${POSTGRES_PASSWORD:-}"
export PGHOST=/var/run/postgresql PGAPPNAME=stools-db
exec "$@"
'''


class BackupError(Exception):
    pass


def database_name(value: str) -> str:
    if not isinstance(value, str) or not re.fullmatch(r'[A-Za-z0-9_][A-Za-z0-9_.-]{0,62}', value):
        raise BackupError('Имя БД: 1–63 латинских буквы, цифры, _, точка или дефис; начало не с дефиса.')
    return value


def identifier(value: str) -> str:
    return '"' + database_name(value) + '"'


def literal(value: str) -> str:
    return "'" + value.replace("'", "''") + "'"


class Postgres:
    def __init__(self, container: str):
        if not re.fullmatch(r'[A-Za-z0-9][A-Za-z0-9_.-]*', container):
            raise BackupError('Некорректное имя Docker-контейнера.')
        self.container = container

    def command(self, *args: str) -> list[str]:
        return ['docker', 'exec', '-i', self.container, 'sh', '-ec', ENV, 'stools-db', *args]

    def run(self, *args: str, source=None, output=None, text: str | None = None) -> str:
        result = subprocess.run(self.command(*args), stdin=source, input=text.encode() if text is not None else None,
                                stdout=output if output is not None else subprocess.PIPE, stderr=subprocess.PIPE)
        if result.returncode:
            # PostgreSQL errors can contain a whole failing row, passwords or user SQL.
            raise BackupError(f'{args[0]} завершился с кодом {result.returncode}; содержимое SQL-ошибки скрыто.')
        return result.stdout.decode().strip() if output is None else ''

    def sql(self, query: str, database: str = 'postgres') -> str:
        return self.run('psql', '-X', '-qAt', '-v', 'ON_ERROR_STOP=1', '--dbname=' + database_name(database), text=query)

    def default_database(self) -> str:
        return database_name(self.run('sh', '-c', 'printf "%s" "$PGDATABASE"'))

    def version(self) -> int:
        return int(self.sql("SHOW server_version_num"))

    def info(self, database: str) -> dict | None:
        value = self.sql("""SELECT json_build_object(
'name', datname, 'oid', oid::bigint, 'allow_connections', datallowconn,
'encoding', pg_encoding_to_char(encoding), 'collate', datcollate, 'ctype', datctype,
'locale_provider', coalesce(to_jsonb(d)->>'datlocprovider', 'c'),
'locale', coalesce(to_jsonb(d)->>'daticulocale', to_jsonb(d)->>'datlocale'))
FROM pg_database d WHERE datname = """ + literal(database_name(database)) + ' LIMIT 1')
        return json.loads(value) if value else None

    def connections(self, database: str) -> int:
        return int(self.sql('SELECT count(*) FROM pg_stat_activity WHERE datname = '
                            + literal(database_name(database)) + ' AND pid <> pg_backend_pid()'))


def digest(stream) -> str:
    result = hashlib.sha256()
    for block in iter(lambda: stream.read(1024 * 1024), b''):
        result.update(block)
    return result.hexdigest()


def read_manifest(directory: Path) -> dict:
    path = directory / 'manifest.json'
    if path.is_symlink() or not path.is_file() or path.stat().st_size > 65536:
        raise BackupError('Нет корректного manifest.json: копия неполная или формат не поддерживается.')
    try:
        meta = json.loads(path.read_text(encoding='utf-8'))
        valid = (meta['format'] == FORMAT and type(meta['bytes']) is int and meta['bytes'] > 5
                 and re.fullmatch(r'[0-9a-f]{64}', meta['sha256'])
                 and type(meta['server_version_num']) is int and meta['server_version_num'] >= 100000)
        db = meta['database']
        database_name(db['name'])
        for field in ('encoding', 'collate', 'ctype', 'locale_provider'):
            if not isinstance(db[field], str) or not db[field] or len(db[field]) > 256 or '\x00' in db[field]:
                valid = False
        if db['locale_provider'] not in ('c', 'i'):
            valid = False
        if db['locale_provider'] == 'i' and (not isinstance(db['locale'], str) or not db['locale'] or len(db['locale']) > 256 or '\x00' in db['locale']):
            valid = False
        if not valid:
            raise ValueError
    except (KeyError, TypeError, ValueError, UnicodeError, RecursionError) as exc:
        raise BackupError('Некорректный manifest.json.') from exc
    return meta


@contextmanager
def verified_backup(pg: Postgres, directory: Path):
    meta = read_manifest(directory)
    path = directory / 'database.dump'
    if path.is_symlink() or not path.is_file():
        raise BackupError('Нет обычного файла database.dump.')
    with path.open('rb') as stream:
        if not stat.S_ISREG(os.fstat(stream.fileno()).st_mode) or os.fstat(stream.fileno()).st_size != meta['bytes']:
            raise BackupError('Размер дампа не совпадает с manifest.json.')
        if digest(stream) != meta['sha256']:
            raise BackupError('SHA-256 не совпадает: копия повреждена или изменена.')
        stream.seek(0)
        # Read/decompress the complete archive, not merely its table of contents.
        pg.run('pg_restore', '--file=/dev/null', source=stream)
        stream.seek(0)
        yield meta, stream


def backup(pg: Postgres, directory: Path, database: str | None) -> dict:
    directory.mkdir(mode=0o700, parents=True, exist_ok=False)
    database = database_name(database or pg.default_database())
    info = pg.info(database)
    if info is None:
        raise BackupError('Исходная база не существует.')
    version = pg.version()
    partial = directory / 'database.dump.partial'
    with partial.open('xb') as output:
        os.chmod(partial, 0o600)
        pg.run('pg_dump', '--format=custom', '--no-tablespaces', '--lock-wait-timeout=60000',
               '--dbname=' + database, output=output)
        output.flush()
        os.fsync(output.fileno())
    with partial.open('rb') as stream:
        checksum = digest(stream)
        stream.seek(0)
        pg.run('pg_restore', '--file=/dev/null', source=stream)
    partial.rename(directory / 'database.dump')
    meta = {'format': FORMAT, 'created_at': datetime.now(timezone.utc).isoformat(),
            'database': {k: v for k, v in info.items() if k not in ('oid', 'allow_connections')},
            'server_version_num': version, 'bytes': (directory / 'database.dump').stat().st_size, 'sha256': checksum}
    temporary = directory / 'manifest.json.partial'
    with temporary.open('x', encoding='utf-8') as output:
        os.chmod(temporary, 0o600)
        json.dump(meta, output, ensure_ascii=False, indent=2)
        output.write('\n')
        output.flush()
        os.fsync(output.fileno())
    temporary.rename(directory / 'manifest.json')
    with_dir = os.open(directory, os.O_RDONLY)
    try:
        os.fsync(with_dir)
    finally:
        os.close(with_dir)
    return {'backup': str(directory.resolve()), 'database': database, 'bytes': meta['bytes'], 'sha256': checksum}


def restore(pg: Postgres, directory: Path, database: str | None, confirmation: str) -> dict:
    target = database_name(database or pg.default_database())
    if target in ('postgres', 'template0', 'template1'):
        raise BackupError('Системную БД заменять нельзя; выберите БД STools через --database.')
    if confirmation != target:
        raise BackupError('--confirm-database должен точно совпадать с именем целевой БД.')
    original = pg.info(target)
    if pg.connections(target):
        raise BackupError('К целевой БД подключены клиенты. Остановите API и другие приложения и повторите.')
    with verified_backup(pg, directory) as (meta, stream):
        if pg.version() // 10000 != meta['server_version_num'] // 10000:
            raise BackupError('Для этого скрипта нужна одинаковая основная версия PostgreSQL источника и приёмника.')
        stamp = datetime.now(timezone.utc).strftime('%Y%m%dT%H%M%SZ') + '_' + uuid.uuid4().hex[:8]
        staging = 'stools_restore_' + stamp
        previous = 'stools_before_' + stamp if original else None
        db = meta['database']
        options = ['--template=template0', '--encoding=' + db['encoding'],
                   '--lc-collate=' + db['collate'], '--lc-ctype=' + db['ctype'],
                   '--locale-provider=' + ('icu' if db['locale_provider'] == 'i' else 'libc')]
        if db['locale_provider'] == 'i':
            options.append('--icu-locale=' + db['locale'])
        print(f'Контейнер: {pg.container}; целевая БД: {target}; временная БД: {staging}', file=sys.stderr)
        pg.run('createdb', *options, staging)
        try:
            pg.sql(f'REVOKE CONNECT ON DATABASE {identifier(staging)} FROM PUBLIC')
            pg.run('pg_restore', '--exit-on-error', '--single-transaction', '--no-owner', '--no-privileges',
                   '--no-tablespaces', '--dbname=' + staging, source=stream)
            if pg.connections(target):
                raise BackupError('Появились подключения к целевой БД; переключение отменено.')
            expected_oid = str(original['oid']) if original else 'NULL'
            sql = f"""BEGIN;
SET LOCAL lock_timeout = '10s';
DO $stools$ BEGIN
IF (SELECT oid::bigint FROM pg_database WHERE datname = {literal(target)}) IS DISTINCT FROM {expected_oid}::bigint
THEN RAISE EXCEPTION 'Target changed during restore'; END IF;
END $stools$;
"""
            if previous:
                sql += f'ALTER DATABASE {identifier(target)} ALLOW_CONNECTIONS false;\n'
                sql += f'ALTER DATABASE {identifier(target)} RENAME TO {identifier(previous)};\n'
            sql += f'ALTER DATABASE {identifier(staging)} RENAME TO {identifier(target)};\nCOMMIT;'
            pg.sql(sql)
        except (BackupError, OSError, KeyboardInterrupt):
            print(f'Автоматический запуск приложений не выполнялся. Проверьте имена БД; временная: {staging}; '
                  f'резерв прежней: {previous or "не было"}. Базы автоматически не удаляются.', file=sys.stderr)
            raise
    return {'database': target, 'previous_database': previous,
            'next_step': 'Восстановите связанные файлы /data и исходный ключ, затем запустите ту же версию STools.'}


def main() -> int:
    os.umask(0o077)
    parser = argparse.ArgumentParser(description=__doc__, formatter_class=argparse.RawDescriptionHelpFormatter)
    actions = parser.add_subparsers(dest='action', required=True)
    for action in ('backup', 'verify', 'restore'):
        command = actions.add_parser(action)
        command.add_argument('directory', type=Path, help='новый каталог копии для backup; существующий для verify/restore')
        command.add_argument('--container', default='stools-db-1' if action != 'restore' else None,
                             required=action == 'restore', help='контейнер PostgreSQL (для restore задаётся явно)')
        if action != 'verify':
            command.add_argument('--database', help='по умолчанию POSTGRES_DB выбранного контейнера')
        if action == 'restore':
            command.add_argument('--confirm-database', required=True, help='точное имя заменяемой БД')
    args = parser.parse_args()
    try:
        pg = Postgres(args.container)
        if args.action == 'backup':
            result = backup(pg, args.directory, args.database)
        elif args.action == 'restore':
            result = restore(pg, args.directory, args.database, args.confirm_database)
        else:
            with verified_backup(pg, args.directory) as (meta, _):
                result = {'status': 'verified', 'database': meta['database']['name'], 'bytes': meta['bytes']}
        print(json.dumps(result, ensure_ascii=False, indent=2))
        return 0
    except KeyboardInterrupt:
        print('Прервано. Перед повтором проверьте состояние БД и неполной копии.', file=sys.stderr)
        return 130
    except (BackupError, OSError, ValueError) as exc:
        print(f'Ошибка: {exc}', file=sys.stderr)
        return 1


if __name__ == '__main__':
    raise SystemExit(main())
