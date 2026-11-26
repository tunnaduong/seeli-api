#!/usr/bin/env bash
# Uploads every photo under DIR to the R2 bucket, keeping the "<userId>/<momentId>.jpg" keys.
# Run from the worker folder. Usage: scripts/upload-photos.sh DIR --local|--remote
set -euo pipefail
dir="$(cd "$1" && pwd)"; where="$2"
n=0
while read -r key; do
  npx wrangler r2 object put "seeli-photos/$key" --file "$dir/$key" --content-type image/jpeg "$where" >/dev/null
  n=$((n + 1))
done < <(cd "$dir" && find . -type f -name '*.jpg' | sed 's|^\./||')
echo "uploaded: $n"
