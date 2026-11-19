#!/bin/sh
# Запуск на Linux-хосте Docker: sh diagnose_harbor_runtime.sh [контейнер_PostgreSQL [контейнер_API]]
# Снимок БД только для чтения, затем GET к настроенному Harbor из контейнера API.
set -euC
umask 077

db_container=${1:-stools-db-1}
api_container=${2:-stools-api-1}
report="harbor-runtime-$(date -u +%Y%m%dT%H%M%SZ)-$$.txt"
result=0
started=$(date -u '+%Y-%m-%dT%H:%M:%SZ')
printf 'Harbor runtime v2 | %s\n' "$started" >"$report"
printf 'Читаю снимок STools. Отчёт: %s\n' "$report"

if docker exec -i "$db_container" sh -c '
    db_user=${POSTGRES_USER:-postgres}
    exec psql -X -w -v ON_ERROR_STOP=1 -U "$db_user" -d "${POSTGRES_DB:-$db_user}"
' >>"$report" 2>&1 <<'STOOLS_RUNTIME_SQL'
\pset pager off
\pset null '(нет)'
BEGIN ISOLATION LEVEL REPEATABLE READ READ ONLY;
SET LOCAL statement_timeout = '45s';

\echo 1. Свежесть снимка Docker и последней синхронизации Harbor
SELECT now() AS checked_at, s.collected_at AS docker_last_ok, s.attempted_at AS docker_last_try,
       nullif(s.error, '') AS docker_last_error,
       (SELECT max(finished_at) FROM vm_image_sync) AS harbor_last_sync
FROM (VALUES (1)) AS current(id) LEFT JOIN vm_docker_snapshot s USING (id)
LIMIT 1;

\echo 2. Образы Harbor по проектам. running совпадает с фильтром интерфейса
WITH observed AS (
    SELECT image_id, bool_or(status = 'running') AS running
    FROM vm_docker_image WHERE image_id <> '' GROUP BY image_id
), per_image AS (
    SELECT i.id, i.project, i.artifact_kind NOT IN ('helm','other') AS eligible,
           coalesce(json_array_length(i.runtime_ids),0) > 0 AS mapped,
           nullif(i.runtime_error, '') AS map_error,
           bool_or(d.image_id IS NOT NULL) AS seen, bool_or(d.running) AS running
    FROM vm_image i
    LEFT JOIN LATERAL json_array_elements_text(i.runtime_ids) AS r(ref) ON true
    LEFT JOIN observed d ON d.image_id = r.ref
    GROUP BY i.id
)
SELECT CASE WHEN grouping(project) = 1 THEN '[все проекты]' ELSE project END AS project,
       count(*) AS catalog, count(*) FILTER (WHERE eligible) AS eligible,
       count(*) FILTER (WHERE eligible AND mapped) AS with_ids,
       count(*) FILTER (WHERE eligible AND map_error IS NOT NULL) AS map_errors,
       max(map_error) FILTER (WHERE eligible) AS example_error,
       count(*) FILTER (WHERE eligible AND seen) AS seen_in_mp,
       count(*) FILTER (WHERE eligible AND running AND EXISTS (
           SELECT 1 FROM vm_docker_snapshot WHERE id = 1 AND collected_at IS NOT NULL)) AS running
FROM per_image GROUP BY GROUPING SETS ((), (project))
ORDER BY grouping(project) DESC, running DESC, catalog DESC, project LIMIT 31;

\echo 3. Хосты и контейнеры в сохранённом снимке MaxPatrol
WITH verified AS (
    SELECT DISTINCT r.ref FROM vm_image i CROSS JOIN LATERAL json_array_elements_text(i.runtime_ids) AS r(ref)
    WHERE i.artifact_kind NOT IN ('helm','other')
), inventory AS (
    SELECT d.id, d.image_id, h->>'hostname' AS hostname, h->>'ip' AS ip, c->>'status' AS status
    FROM vm_docker_image d
    CROSS JOIN LATERAL json_array_elements(d.details->'hosts') AS hosts(h)
    LEFT JOIN LATERAL json_array_elements(h->'containers') AS containers(c) ON true
)
SELECT count(DISTINCT (hostname,ip)) AS inventory_hosts,
       count(DISTINCT (hostname,ip)) FILTER (WHERE status = 'running') AS running_hosts,
       count(DISTINCT (hostname,ip)) FILTER (WHERE status = 'running' AND v.ref IS NOT NULL) AS running_hosts_matched,
       count(DISTINCT (hostname,ip)) FILTER (WHERE status = 'running')
       - count(DISTINCT (hostname,ip)) FILTER (WHERE status = 'running' AND v.ref IS NOT NULL) AS running_hosts_without_match,
       count(DISTINCT id) FILTER (WHERE status = 'running') AS running_image_records,
       count(DISTINCT id) FILTER (WHERE status = 'running' AND image_id = '') AS running_no_id,
       count(DISTINCT id) FILTER (WHERE status = 'running' AND image_id <> ''
              AND image_id !~ '^sha256:[0-9a-f]{64}$') AS running_other_id_format,
       count(*) FILTER (WHERE status IS NOT NULL) AS container_records,
       count(*) FILTER (WHERE lower(btrim(status)) = 'running' AND status <> 'running') AS running_case_variants
FROM inventory LEFT JOIN verified v ON v.ref = inventory.image_id;

\echo 4. Образы с running и ID без точного совпадения. Имена используются только для диагностики
WITH verified AS (
    SELECT DISTINCT r.ref FROM vm_image i CROSS JOIN LATERAL json_array_elements_text(i.runtime_ids) AS r(ref)
    WHERE i.artifact_kind NOT IN ('helm','other')
), repos AS (
    SELECT DISTINCT split_part(regexp_replace(lower(btrim(registry_url)),'^https?://',''), '/', 1) AS registry,
           project || '/' || repository AS path FROM vm_image WHERE registry_url <> ''
), registries AS (
    SELECT DISTINCT registry FROM repos
), refs AS (
    SELECT d.id, split_part(regexp_replace(lower(btrim(coalesce(r->>'registry',''))),'^https?://',''), '/', 1) AS registry,
           btrim(coalesce(r->>'repo',''), '/') AS path
    FROM vm_docker_image d
    LEFT JOIN LATERAL json_array_elements(d.details->'references') AS refs(r) ON true
    WHERE d.status = 'running' AND d.image_id <> ''
      AND NOT EXISTS (SELECT 1 FROM verified v WHERE v.ref = d.image_id)
), classified AS (
    SELECT x.id, grouping(x.registry) AS combined, x.registry,
           bool_or(x.registry <> '') AS has_registry, bool_or(g.registry IS NOT NULL) AS known_registry,
           bool_or(p.path IS NOT NULL) AS known_repo
    FROM refs x LEFT JOIN registries g ON g.registry = x.registry
    LEFT JOIN repos p ON p.registry = x.registry AND p.path = CASE
       WHEN left(x.path,length(x.registry)+1)=x.registry||'/' THEN substr(x.path,length(x.registry)+2)
       ELSE x.path END
    GROUP BY GROUPING SETS ((x.id), (x.id, x.registry))
), totals AS (
    SELECT * FROM classified
    UNION ALL SELECT NULL, 1, NULL, false, false, false WHERE NOT EXISTS (SELECT 1 FROM classified)
)
SELECT CASE WHEN combined = 1 THEN '[все реестры]' WHEN registry = '' THEN '[не указан]'
            WHEN registry ~ '^([a-z0-9_.-]+|\[[0-9a-f:]+\])(:[0-9]{1,5})?$' THEN left(registry,255)
            ELSE '[нестандартное имя скрыто]' END AS registry_in_mp,
       count(id) AS unmatched_ids, count(*) FILTER (WHERE known_repo) AS same_registry_and_repo,
       count(*) FILTER (WHERE known_registry AND NOT known_repo) AS same_registry_other_repo,
       count(*) FILTER (WHERE has_registry AND NOT known_registry) AS other_registry_spelling,
       count(id) FILTER (WHERE NOT has_registry) AS registry_unspecified
FROM totals GROUP BY combined, registry
ORDER BY combined DESC, unmatched_ids DESC, registry LIMIT 31;
\echo Итог считает образ один раз. Один образ с несколькими именами реестров может входить в несколько строк.

ROLLBACK;
STOOLS_RUNTIME_SQL
then
    :
else
    result=$?
    printf 'Сводка PostgreSQL недоступна (код %s). Продолжаю проверку через API.\n' "$result" >>"$report"
fi

printf 'Проверяю доступ робота к манифестам. Результаты по мере готовности пишутся в %s\n' "$report"
if docker exec -i "$api_container" python -u - >>"$report" 2>&1 <<'HARBOR_PROBE_PY'
import base64
import json
import logging
import re
import signal
import sys
from collections import Counter
from datetime import datetime, timezone
from unittest.mock import patch

from sqlalchemy import text

from api.db.base import get_sessionmaker
from api.limits import read_limited
from api.modules.vm.core import registry_manifests
from api.modules.vm.core.harbor import HarborClient, HarborError, _enc, _project_path, make_harbor_client
from api.modules.vm.services.harbor_settings import load_harbor
from api.modules.vm.services.harbor_sync import public_url

SAMPLES = """
    WITH images AS (
        SELECT project, repository, digest, pushed_at,
               CASE WHEN runtime_error <> '' THEN runtime_error
                    WHEN json_array_length(runtime_ids) > 0 THEN 'MAPPED' ELSE 'NO_ID' END AS saved
        FROM vm_image WHERE artifact_kind NOT IN ('helm','other') AND registry_url = :origin
          AND (:all_projects OR project = ANY(CAST(:projects AS text[])))
    ), samples AS (
        SELECT DISTINCT ON (project, saved) project, saved, repository, digest,
               count(*) OVER (PARTITION BY project, saved) AS images
        FROM images ORDER BY project, saved, pushed_at DESC NULLS LAST, repository, digest
    )
    SELECT *, count(*) OVER () AS groups_total FROM samples
    ORDER BY project NOT IN ('sea','ccr','diasoft_products','share'), project, saved LIMIT 64
"""
REPO_NAME = re.compile(r"[A-Za-z0-9]+(?:[._-]+[A-Za-z0-9]+)*(?:/[A-Za-z0-9]+(?:[._-]+[A-Za-z0-9]+)*)*")


def pull_grant(token_body, name):
    # Поле access — подсказка. Фактический доступ устанавливает GET манифеста.
    try:
        payload = json.loads(token_body)
        token = payload.get("token") or payload.get("access_token")
        _, claims, _ = token.split(".")
        access = json.loads(base64.urlsafe_b64decode(claims + "=" * (-len(claims) % 4)))["access"]
        if not isinstance(access, list):
            return "неизвестно"
        for item in access:
            if item.get("type") == "repository" and item.get("name") == name:
                if isinstance(item.get("actions"), list) and {"pull", "*"}.intersection(item["actions"]):
                    return "да"
        return "не выдан"
    except (ValueError, KeyError, TypeError, AttributeError):
        return "неизвестно"


def denial(response, body):
    # Только известные признаки и идентификатор запроса. Текст сервера может содержать секрет.
    try:
        entry = json.loads(body[:65536])["errors"][0]
        code = entry.get("code")
        message = str(entry.get("message", "")).lower()
    except (ValueError, KeyError, IndexError, TypeError, AttributeError):
        code, message = "", ""
    known = {"UNAUTHORIZED", "DENIED", "FORBIDDEN", "INSUFFICIENT_SCOPE", "MANIFEST_UNKNOWN",
             "NAME_UNKNOWN", "NOT_FOUND", "PROJECTPOLICYVIOLATION", "PRECONDITION_FAILED", "TOOMANYREQUESTS"}
    reason = "ответ без известного кода"
    if isinstance(code, str) and code in known:
        reason = code
    if response.status_code == 412:
        if any(word in message for word in ("without vulnerability scanning", "not scanned", "not been scanned", "no scan")):
            reason += " / отсутствует результат сканирования"
        elif any(word in message for word in ("not signed", "unsigned", "signature", "content trust", "cosign")):
            reason += " / требование подписи"
        elif re.search(r"\bwith \d+ vulnerabilit|vulnerability severity", message):
            reason += " / ограничение по уязвимостям"
    request_id = response.headers.get("X-Request-Id") or response.headers.get("X-Correlation-Id", "")
    if re.fullmatch(r"[a-fA-F0-9-]{8,64}", request_id):
        reason += " id=" + request_id
    return reason


def probe_sample(client, project, repository, digest):
    name = f"{project}/{repository}"
    path = f"{_project_path(project)}/repositories/{_enc(repository)}/artifacts/{digest}"
    try:
        client._get(path)
        metadata = 200
    except HarborError as exc:
        metadata = exc.status or exc.kind

    trace = dict(first="—", token="—", pull="—", manifest="—", level="—", detail="")

    def inspect(response, limit):
        body = read_limited(response, limit)
        path = response.request.url.path
        if path.endswith("/service/token"):
            trace["token"] = response.status_code
            if response.status_code == 200:
                trace["pull"] = pull_grant(body, name)
        else:
            if trace["first"] == "—":
                trace["first"] = response.status_code
            trace["manifest"] = response.status_code
            trace["level"] = "корневой" if path.rsplit("/", 1)[-1] == digest else "дочерний"
        trace["detail"] = denial(response, body) if response.status_code >= 400 else ""
        return body

    # Наблюдаем ответы в отдельном процессе диагностики. Весь обмен и сверку digest ведёт клиент STools.
    with patch.object(registry_manifests, "read_limited", inspect):
        try:
            ids = client.runtime_image_ids(project, repository, digest)
            verdict = "OK"
            result = f"OK ({len(ids)} проверенных ID)"
        except HarborError as exc:
            verdict = result = exc.kind
            if exc.__cause__ is not None:
                result += " / " + type(exc.__cause__).__name__
    now = datetime.now(timezone.utc).strftime("%H:%M:%SZ")
    print(f"  {now} metadata={metadata} первый_manifest={trace['first']} token={trace['token']} "
          f"pull={trace['pull']} manifest={trace['manifest']} ({trace['level']}) "
          f"итог={result} {trace['detail']}".rstrip())
    return verdict


def print_policy(client, project):
    try:
        raw, _ = client._get(_project_path(project), resource_name=True)
        metadata = raw["metadata"]
        fields = []
        for key in ("prevent_vul", "severity", "enable_content_trust", "enable_content_trust_cosign"):
            value = str(metadata.get(key)).lower()
            allowed = {"true", "false", "low", "medium", "high", "critical", "none", "negligible", "unknown"}
            fields.append(f"{key}={value if key in metadata and value in allowed else 'не указано'}")
        print("  Политика проекта:", " ".join(fields))
    except HarborError as exc:
        print("  Чтение политики проекта:", exc.status or exc.kind)
    except (KeyError, TypeError, AttributeError):
        print("  Настройки политики отсутствуют в ответе.")


def main():
    print("\n5. Проверка текущего доступа к Harbor из API STools")
    with get_sessionmaker()() as db:
        db.execute(text("SET TRANSACTION ISOLATION LEVEL REPEATABLE READ, READ ONLY"))
        db.execute(text("SET LOCAL statement_timeout = '45s'"))
        conn = load_harbor(db).unsealed()
        if not conn.configured:
            print("Подключение Harbor в этой БД не настроено.")
            return 2
        origin = public_url(conn.url)
        rows = db.execute(text(SAMPLES), {"origin": origin, "projects": conn.projects,
                                          "all_projects": not conn.projects}).all()
    robot = conn.robot_name if re.fullmatch(r"[\w$@.+-]{1,128}", conn.robot_name) else "[имя скрыто]"
    print(f"Harbor={origin} робот={robot} TLS verify={conn.verify_tls}")
    if not rows:
        print("В каталоге нет подходящих образов настроенного реестра и выбранных проектов.")
        return 2
    total = rows[0].groups_total
    print(f"По одному образу на проект и сохранённый результат. Выбрано {len(rows)} из {total} групп.")
    print("metadata — карточка артефакта. pull — действие в выданном токене. "
          "OK — манифесты прочитаны, digest проверены. Первый 401 может быть обычным запросом авторизации.")
    checked_policies = set()
    results = Counter()
    with make_harbor_client(conn, timeout=10.0) as http:
        for row in rows:
            name = f"{row.project}/{row.repository}"
            if (not REPO_NAME.fullmatch(name) or "/" in row.project
                    or not registry_manifests.DIGEST.fullmatch(row.digest)):
                print("  Пример пропущен: некорректное имя репозитория или digest.")
                results["INVALID_SAMPLE"] += 1
                continue
            saved = row.saved if re.fullmatch(r"[A-Z0-9_]{1,64}", row.saved) else "[другая ошибка]"
            print(f"{name} {row.digest} | в БД={saved} образов={row.images}")
            client = HarborClient(conn, http)  # проверяем каждую группу с пустым кэшем токенов
            verdict = probe_sample(client, row.project, row.repository, row.digest)
            results[verdict] += 1
            if verdict == "MANIFEST_HTTP_412" and row.project not in checked_policies:
                print_policy(client, row.project)
                checked_policies.add(row.project)
    print("Итого по проверенным примерам:", ", ".join(f"{k}={v}" for k, v in sorted(results.items())))
    if len(rows) < total:
        print(f"За пределом 64 примеров осталось групп: {total - len(rows)}.")
    if results["MANIFEST_UNAVAILABLE"]:
        print("Есть примеры без ответа реестра или с превышением лимита ответа. Проверка доступа по ним неполная.")
    if len(rows) < total or results["MANIFEST_UNAVAILABLE"] or results["INVALID_SAMPLE"]:
        return 2
    return 0


if __name__ == "__main__":
    logging.disable(logging.CRITICAL)

    class ProbeDeadline(Exception):
        pass

    def stop_at_deadline(*_):
        raise ProbeDeadline

    signal.signal(signal.SIGALRM, stop_at_deadline)
    signal.alarm(300)
    try:
        sys.exit(main())
    except ProbeDeadline:
        print("Достигнут лимит 5 минут. Уже проверенные примеры сохранены.")
        sys.exit(2)
    except Exception as exc:
        print("Проверка прервана:", type(exc).__name__)
        sys.exit(2)
HARBOR_PROBE_PY
then
    :
else
    result=$?
    printf 'Живая проверка завершилась с кодом %s.\n' "$result" >>"$report"
fi

# Если Harbor рядом, ищем причину непояснённого 412 по идентификатору только этого GET.
if awk '/итог=MANIFEST_HTTP_412/ && !/ограничение по уязвимостям|требование подписи|отсутствует результат сканирования/ { found=1 } END { exit !found }' "$report"; then
    core_container=${HARBOR_CORE_CONTAINER:-harbor-core}
    if [ "$(docker inspect --format '{{.State.Running}}' "$core_container" 2>/dev/null || :)" = true ]; then
        docker logs --since "$started" --tail 20 "$core_container" 2>&1 | awk '
          FILENAME != "-" {
            if ($0 ~ /итог=MANIFEST_HTTP_412/)
              for (i=1; i<=NF; i++) if ($i ~ /^id=[a-fA-F0-9-]+$/) ids[tolower(substr($i,4))]=1
            next
          }
          {
            line=tolower($0)
            for (id in ids) if (index(line,id)) {
              if (line ~ /without vulnerability scanning|not scanned|not been scanned/) why[id]="отсутствует результат сканирования"
              else if (line ~ /not signed|unsigned|signature|cosign/) why[id]="требование подписи"
              else if (line ~ /with [0-9]+ vulnerabilit|vulnerability severity/) why[id]="ограничение по уязвимостям"
            }
          }
          END {
            for (id in why) { print "Журнал Harbor core, id=" id, why[id]; found=1 }
            if (!found) print "В доступных 20 строках локального Harbor core причина 412 не установлена."
          }' "$report" - >>"$report"
    else
        printf 'Локальный журнал Harbor core недоступен. Для поиска на сервере Harbor в отчёте приведены UTC, репозиторий, digest и ID запроса, если его вернул сервер.\n' >>"$report"
    fi
fi
if [ "$result" -eq 0 ]; then
    printf 'Готово. Отчёт: %s\n' "$report"
else
    printf 'Проверка выполнена частично. Отчёт: %s\n' "$report" >&2
fi
exit "$result"
