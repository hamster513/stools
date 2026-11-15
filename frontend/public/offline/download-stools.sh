#!/bin/sh
# STools unified downloader. Run without arguments for the menu.
set -eu
script_dir=$(CDPATH= cd -- "$(dirname -- "$0")" && pwd)
if command -v python3 >/dev/null 2>&1; then
  python=python3
elif command -v python >/dev/null 2>&1; then
  python=python
else
  echo 'Нужен Python 3.11+ / Python 3.11+ is required.' >&2
  exit 1
fi
if ! "$python" -c 'import sys; sys.exit(0 if sys.version_info >= (3, 11) else 1)'; then
  echo 'Нужен Python 3.11+ / Python 3.11+ is required.' >&2
  exit 1
fi
exec "$python" "$script_dir/offline_download.py" "$@"
