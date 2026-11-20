#!/bin/sh
# Import the transferred ZIP on the disconnected Linux server.
set -eu
if [ "$#" -lt 1 ] || [ "$#" -gt 2 ]; then
    echo "Usage: sh update-trivy-db.sh ARCHIVE.zip [API_CONTAINER]" >&2
    exit 2
fi
if [ ! -f "$1" ]; then
    echo "ZIP file not found: $1" >&2
    exit 2
fi
exec docker exec -i "${2:-stools-api-1}" python -m api.cli import-trivy-db < "$1"
