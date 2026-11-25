#!/usr/bin/env bash
# Creates the n8n credentials and imports the 5 workflows (fixed IDs => tool links just work).
# Prerequisites: `docker compose up -d` is running AND you have created the n8n owner account
# in the browser once (http://localhost:5678).  Safe to re-run (overwrites by ID).
set -euo pipefail
cd "$(dirname "$0")/.."
[ -f .env ] || { echo "Missing .env (cp .env.example .env and fill it in)"; exit 1; }
set -a; . ./.env; set +a

dc() { docker compose "$@"; }

echo "==> validating workflow files"
python3 scripts/validate_workflows.py

echo "==> importing credentials (MongoDB, Postgres, SSH, Ollama, optional Gemini)"
python3 scripts/make_credentials.py | dc exec -T n8n sh -c 'umask 077; cat > /tmp/asm-creds.json'
dc exec -T n8n n8n import:credentials --input=/tmp/asm-creds.json
dc exec -T n8n rm -f /tmp/asm-creds.json

echo "==> importing workflows"
dc exec -T n8n n8n import:workflow --separate --input=/workflows

cat <<MSG

Done. Open n8n -> Workflows -> "ASM - 0. Orchestrator (chat agent)" -> Open chat.
(If the Ollama model is missing: docker compose exec ollama ollama pull llama3.1:8b)
MSG
