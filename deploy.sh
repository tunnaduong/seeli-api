#!/usr/bin/env bash
# Run on the server (or from the aaPanel Webhook plugin) to update and restart the API.
# Usage: bash deploy.sh            (in the project folder)
set -euo pipefail
cd "$(dirname "$0")"
echo "========== $(date) =========="

if [ -d .git ]; then
  git fetch origin
  git reset --hard origin/main
fi

if [ ! -f .env ]; then
  cp .env.example .env
  sed -i "s/^JWT_SECRET=.*/JWT_SECRET=$(openssl rand -hex 32)/" .env
  echo "Created .env with a fresh JWT_SECRET — set PUBLIC_URL in it."
fi

# Admin page password: generated once, never printed. Read it with: sudo grep ADMIN_PASSWORD .env
if ! grep -qE '^ADMIN_PASSWORD=.+' .env; then
  sed -i '/^ADMIN_PASSWORD=/d' .env
  echo "ADMIN_PASSWORD=$(openssl rand -base64 24 | tr -d '/+=' | cut -c1-24)" >> .env
  echo "Generated ADMIN_PASSWORD in .env (see it with: sudo grep ADMIN_PASSWORD .env)"
fi
chmod 600 .env

mkdir -p data secrets
chmod 700 secrets
chown -R 1000:1000 secrets 2>/dev/null || sudo chown -R 1000:1000 secrets
# The container runs as the "node" user (uid 1000).
chown -R 1000:1000 data 2>/dev/null || sudo chown -R 1000:1000 data

docker compose up -d --build
docker image prune -f >/dev/null

for i in $(seq 1 20); do
  if curl -fs "http://127.0.0.1:$(grep -E '^HOST_PORT=' .env | cut -d= -f2 || echo 8790)/v1/health" >/dev/null; then
    echo "SEELI API is up."
    exit 0
  fi
  sleep 2
done
echo "API did not become healthy — check: docker compose logs seeli-api" >&2
exit 1
