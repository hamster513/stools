#!/bin/sh
# Скачать все четыре справочника модуля VM для сети без интернета.
# Результат — каталог с файлами, которые грузятся через «Настройки и
# данные → Справочники → загрузить файл». NVD — по годам, по умолчанию
# с 2002 по текущий; задайте свои: NVD_YEARS="2023 2024 2025".
set -eu

OUT="${1:-vm-references-$(date +%Y%m%d)}"
mkdir -p "$OUT/nvd"
echo "→ EPSS";       curl -fL -o "$OUT/epss_scores-current.csv.gz" https://epss.empiricalsecurity.com/epss_scores-current.csv.gz
echo "→ ExploitDB";  curl -fL -o "$OUT/files_exploits.csv" https://gitlab.com/exploit-database/exploitdb/-/raw/main/files_exploits.csv
echo "→ Metasploit"; curl -fL -o "$OUT/modules_metadata_base.json" https://raw.githubusercontent.com/rapid7/metasploit-framework/master/db/modules_metadata_base.json
YEARS="${NVD_YEARS:-$(seq 2002 "$(date +%Y)")}"
for y in $YEARS; do
  echo "→ NVD $y"; curl -fL -o "$OUT/nvd/nvdcve-2.0-$y.json.gz" "https://nvd.nist.gov/feeds/json/cve/2.0/nvdcve-2.0-$y.json.gz"
done
echo "готово: $OUT"
