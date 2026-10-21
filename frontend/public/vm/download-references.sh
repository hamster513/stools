#!/bin/sh
# Скачать справочники модуля VM STools одним архивом для сети без интернета.
#
# Качает EPSS, NVD (по годам), ExploitDB, Metasploit, размётку CTID ATT&CK и каталог
# CISA KEV и складывает их в один zip. Архив загружается в STools: «Настройки и данные →
# Справочники → Загрузить архив». Справочник узнаётся по имени файла — имена не меняйте.
#
# Нужны curl и zip (или python3). Прокси curl берёт сам из https_proxy / HTTPS_PROXY.
# Настройки — переменными окружения:
#   OUT=refs.zip            путь к архиву (по умолчанию vm-references-ГГГГММДД.zip)
#   NVD_YEARS="2024 2025"   годы NVD (по умолчанию последние пять — архив укладывается в 500 МБ)
#   ALL_YEARS=1             NVD за все годы, с 2002
#   SKIP="epss msf"         не качать: epss nvd exploitdb msf attack kev
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

for s in $SKIP; do
  case "$s" in
    epss|nvd|exploitdb|msf|attack|kev) ;;
    *) echo "неизвестный справочник в SKIP: $s (есть: epss nvd exploitdb msf attack kev)" >&2; exit 1 ;;
  esac
done

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
if [ "${ALL_YEARS:-}" = 1 ]; then
  first=2002
  YEARS=""
else
  first=$((this_year - 4))
  YEARS="${NVD_YEARS:-}"
fi
if [ -z "$YEARS" ]; then
  y=$first
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

echo
[ -n "$skipped" ] && echo "пропущено по SKIP:$skipped"
[ -n "$failed" ] && echo "не вошло:$failed" >&2
if [ -z "$packed" ]; then
  echo "ни один справочник не скачан, архив не создан" >&2
  exit 1
fi

# Существующий архив zip дополнил бы, а не заменил.
rm -f "$OUT"
if command -v zip >/dev/null 2>&1; then
  # -j: плоский архив, без пути временной папки.
  zip -j -q "$OUT" "$tmp"/* || exit 1
else
  echo "zip не найден, архив собирает python3"
  python3 -c '
import os, sys, zipfile
with zipfile.ZipFile(sys.argv[1], "w", zipfile.ZIP_DEFLATED) as zf:
    for path in sys.argv[2:]:
        zf.write(path, os.path.basename(path))
' "$OUT" "$tmp"/* || exit 1
fi
echo "вошло:$packed"
echo "архив: $OUT"
echo "загрузите его в STools: Настройки и данные → Справочники → Загрузить архив"
