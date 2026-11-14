#!/bin/sh
# Скачать справочники модуля VM STools одним архивом для сети без интернета.
#
# Качает EPSS, NVD (по годам), ExploitDB, Metasploit, размётку CTID ATT&CK и каталог
# CISA KEV в OUT.zip; GitHub Advisory Database — в OUT-ghsa.zip. Каждый архив загружается в STools: «Настройки и данные →
# Справочники → Загрузить архив». Справочник узнаётся по имени файла — имена не меняйте.
#
# Нужны curl и zip (или python3). Прокси curl берёт сам из https_proxy / HTTPS_PROXY.
# Настройки — переменными окружения:
#   OUT=refs.zip            основной архив; GHSA — refs-ghsa.zip (по умолчанию имя с датой)
#   Только GHSA: используется OUT. Каждый результат должен быть не больше 500 МиБ.
#   NVD_YEARS="2024 2025"   ограничить годы NVD (по умолчанию все, с 2002)
#   ALL_YEARS=1             NVD за все годы (то же, что по умолчанию; перекрывает NVD_YEARS)
#   SKIP="epss msf"         не качать: epss nvd exploitdb msf attack kev ghsa
#   MODE=updates STATE=state.json — только обновления; нужны Python 3 и git (GHSA).
#   STATE экспортируется в STools и обновляется после создания каждого нового OUT.
#   CACHE=/path/cache — необязательный каталог кеша. Архивы передавать по порядку.
# Пример: NVD_YEARS="2024 2025" SKIP=msf sh download-references.sh
set -u

OUT="${OUT:-vm-references-$(date +%Y%m%d).zip}"
# zip сам дописал бы «.zip» к имени без него — тогда напечатанный путь не совпал бы с файлом.
case "$OUT" in
  *.zip|*.ZIP) ;;
  *) OUT="$OUT.zip" ;;
esac
SKIP=$(printf '%s' "${SKIP:-}" | tr ',;' '  ')
# Для тестов: все файлы с одного адреса, имена те же.
BASE="${VM_REFS_BASE:-}"
GH=https://raw.githubusercontent.com
# Можно уменьшить потолок для своей среды; повысить серверный предел нельзя.
LIMIT=${VM_REFS_MAX_BUNDLE_BYTES:-524288000}
case "$LIMIT" in ''|*[!0-9]*) echo "неверный лимит архива" >&2; exit 1 ;; esac
if [ "$LIMIT" -lt 1 ] || [ "$LIMIT" -gt 524288000 ]; then
  echo "лимит архива должен быть от 1 до 524288000 байт" >&2; exit 1
fi

for s in $SKIP; do
  case "$s" in
    epss|nvd|exploitdb|msf|attack|kev|ghsa) ;;
    *) echo "неизвестный справочник в SKIP: $s (есть: epss nvd exploitdb msf attack kev ghsa)" >&2; exit 1 ;;
  esac
done

# Обновления используют тот же Python-код, что и онлайн-проверка STools.
case "${MODE:-full}" in
  full) ;;
  updates)
    if [ -z "${STATE:-}" ]; then echo "MODE=updates требует STATE — экспорт состояния из STools" >&2; exit 1; fi
    if ! command -v python3 >/dev/null 2>&1; then echo "для обновлений нужен Python 3" >&2; exit 1; fi
    script_dir=$(CDPATH= cd -- "$(dirname -- "$0")" && pwd) || exit 1
    helper="$script_dir/ref_updates.py"
    if [ ! -f "$helper" ]; then echo "нет ref_updates.py — распакуйте весь комплект скриптов STools" >&2; exit 1; fi
    set --
    for source in epss nvd exploitdb msf attack kev ghsa; do
      case " $SKIP " in *" $source "*) ;; *) set -- "$@" "$source" ;; esac
    done
    if [ "$#" -eq 0 ]; then echo "не выбран ни один справочник" >&2; exit 1; fi
    if [ -n "${CACHE:-}" ]; then set -- "$@" --cache "$CACHE"; fi
    exec python3 "$helper" --state "$STATE" --out "$OUT" --max-bytes "$LIMIT" --sources "$@"
    ;;
  *) echo "MODE должен быть full или updates" >&2; exit 1 ;;
esac

# Инструменты — до скачивания: иначе ленты скачаны, а упаковать их нечем.
if ! command -v curl >/dev/null 2>&1; then
  echo "нужен curl" >&2
  exit 1
fi
if ! command -v zip >/dev/null 2>&1 && ! command -v python3 >/dev/null 2>&1; then
  echo "нужен zip или python3 — архив собрать нечем" >&2
  exit 1
fi
# Значение не печатается: в адресе прокси бывают логин и пароль.
if [ -n "${https_proxy:-}${HTTPS_PROXY:-}" ]; then
  echo "прокси: из переменных окружения"
else
  echo "прокси: нет"
fi

this_year=$(date +%Y)
YEARS="${NVD_YEARS:-}"
[ "${ALL_YEARS:-}" = 1 ] && YEARS=""
if [ -z "$YEARS" ]; then
  y=2002
  while [ "$y" -le "$this_year" ]; do YEARS="$YEARS $y"; y=$((y + 1)); done
fi

tmp=$(mktemp -d "${TMPDIR:-/tmp}/stools-refs.XXXXXX") || exit 1
trap 'rm -rf "$tmp"' EXIT
trap 'exit 130' INT TERM

packed=""
failed=""
skipped=""

# fetch <справочник> <имя файла> <ссылка>
fetch() {
  case " $SKIP " in
    *" $1 "*) skipped="$skipped $2"; return 0 ;;
  esac
  url=$3
  # «&» в имени CTID кодируется в адресе, а файл сохраняется под буквальным именем.
  [ -n "$BASE" ] && url="$BASE/$(printf '%s' "$2" | sed 's/&/%26/g')"
  echo "→ $2"
  # NVD отдаёт ленты медленно и рвёт соединение после простоя (curl: 18, «partial file»), а
  # --retry такой обрыв не повторяет. Поэтому до 4 попыток с докачкой с места обрыва (-C -);
  # --speed-time/--speed-limit прерывают попытку при простое дольше 2 минут, а не по общему времени.
  ok=0; attempt=1
  while [ $attempt -le 4 ]; do
    [ $attempt -gt 1 ] && echo "  повтор $((attempt - 1)) из 3 (докачка)"
    if curl -fL -C - --connect-timeout 20 --speed-limit 1024 --speed-time 120 -A 'STools-references/1' -o "$tmp/$2.part" "$url"; then
      ok=1; break
    fi
    attempt=$((attempt + 1))
  done
  if [ $ok -eq 1 ]; then
    mv "$tmp/$2.part" "$tmp/$2"
    packed="$packed $2"
  else
    rm -f "$tmp/$2.part"
    echo "! $2: не скачан" >&2
    failed="$failed $2"
  fi
}

# Ссылки — те же, что у кнопок «Скачать» в STools. Ссылка CTID закреплена за версией размётки.
fetch epss epss_scores-current.csv.gz https://epss.empiricalsecurity.com/epss_scores-current.csv.gz
for y in $YEARS; do
  fetch nvd "nvdcve-2.0-$y.json.gz" "https://nvd.nist.gov/feeds/json/cve/2.0/nvdcve-2.0-$y.json.gz"
done
fetch exploitdb files_exploits.csv https://gitlab.com/exploit-database/exploitdb/-/raw/main/files_exploits.csv
fetch msf modules_metadata_base.json "$GH/rapid7/metasploit-framework/master/db/modules_metadata_base.json"
fetch attack kev-07.28.2025_attack-16.1-enterprise.json \
  "$GH/center-for-threat-informed-defense/mappings-explorer/main/mappings/kev/attack-16.1/kev-07.28.2025/enterprise/kev-07.28.2025_attack-16.1-enterprise.json"
fetch attack 'Att&ckToCveMappings.csv' \
  "$GH/center-for-threat-informed-defense/mappings-explorer/main/src/mapex_convert/mappings/Att%26ckToCveMappings.csv"
fetch kev known_exploited_vulnerabilities.json https://www.cisa.gov/sites/default/files/feeds/known_exploited_vulnerabilities.json
fetch ghsa advisory-database.zip https://codeload.github.com/github/advisory-database/zip/refs/heads/main

echo
[ -n "$skipped" ] && echo "пропущено по SKIP:$skipped"
[ -n "$failed" ] && echo "не вошло:$failed" >&2
if [ -z "$packed" ]; then
  echo "ни один справочник не скачан, архив не создан" >&2
  exit 1
fi

# GHSA содержит сотни тысяч имён внутри ZIP. Повторное DEFLATE существенно
# уменьшает его метаданные, но native zip по умолчанию хранит .zip без сжатия.
pack_archive() {
  pack_target=$1
  shift
  rm -f "$pack_target"
  if command -v zip >/dev/null 2>&1; then
    zip -j -q -9 -n '' "$pack_target" "$@" || return 1
  else
    echo "zip не найден, архив собирает python3"
    python3 -c '
import os, sys, zipfile
with zipfile.ZipFile(sys.argv[1], "w", zipfile.ZIP_DEFLATED) as zf:
    for path in sys.argv[2:]:
        zf.write(path, os.path.basename(path))
' "$pack_target" "$@" || return 1
  fi
  pack_bytes=$(wc -c < "$pack_target")
  if [ "$pack_bytes" -gt "$LIMIT" ]; then
    rm -f "$pack_target"
    echo "! $pack_target: превышен лимит архива ($LIMIT байт); ограничьте NVD_YEARS" >&2
    return 1
  fi
  echo "архив: $pack_target"
}

# Отдельный архив GHSA сохраняет совместимость с лимитом загрузки 500 МиБ.
set --
for file in "$tmp"/*; do
  [ "${file##*/}" = "advisory-database.zip" ] || set -- "$@" "$file"
done
code=0
if [ "$#" -gt 0 ]; then
  pack_archive "$OUT" "$@" || code=1
fi
if [ -f "$tmp/advisory-database.zip" ]; then
  ghsa_out="$OUT"
  [ "$#" -gt 0 ] && ghsa_out="${OUT%.*}-ghsa.zip"
  pack_archive "$ghsa_out" "$tmp/advisory-database.zip" || code=1
fi
echo "скачано:$packed"
echo "загрузите каждый созданный архив по очереди в STools: Настройки и данные → Справочники → Загрузить архив"
exit "$code"
