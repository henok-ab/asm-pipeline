#!/usr/bin/env python3
"""Print an n8n credentials-import JSON array built from the environment (.env).

Used by setup-n8n.sh:   python3 scripts/make_credentials.py | docker compose exec -T n8n ... import:credentials
The credential IDs below are referenced by the workflows in workflows/*.json - do not change one
without changing the other (scripts/validate_workflows.py checks this).
"""
import json
import os
import sys
from urllib.parse import quote_plus


def need(name):
    v = os.environ.get(name, "")
    if not v:
        sys.exit(f"make_credentials.py: {name} is not set (check .env)")
    return v


key_path = os.path.expanduser(need("SCANNER_SSH_KEY_FILE"))
try:
    private_key = open(key_path).read()
except OSError as e:
    sys.exit(f"make_credentials.py: cannot read SCANNER_SSH_KEY_FILE ({e})")

mongo_user = os.environ.get("MONGO_APP_USER", "asm_app")
mongo_uri = (
    f"mongodb://{quote_plus(mongo_user)}:{quote_plus(need('MONGO_APP_PASSWORD'))}"
    f"@mongo:27017/asm?authSource=asm"
)

creds = [
    {
        "id": "asmMongoDb000001",
        "name": "ASM MongoDB",
        "type": "mongoDb",
        "data": {"configurationType": "connectionString", "connectionString": mongo_uri, "database": "asm"},
    },
    {
        "id": "asmPostgres00001",
        "name": "ASM Postgres",
        "type": "postgres",
        "data": {
            "host": "postgres",
            "database": os.environ.get("POSTGRES_DB", "n8n"),
            "user": os.environ.get("POSTGRES_USER", "n8n"),
            "password": need("POSTGRES_PASSWORD"),
            "port": 5432,
            "maxConnections": 100,
            "allowUnauthorizedCerts": False,
            "ssl": "disable",
            "sshTunnel": False,
        },
    },
    {
        "id": "asmSshKey0000001",
        "name": "ASM Scanner SSH",
        "type": "sshPrivateKey",
        "data": {
            "host": need("SCANNER_HOST"),
            "port": int(os.environ.get("SCANNER_PORT", "22")),
            "username": os.environ.get("SCANNER_USER", "asm"),
            "privateKey": private_key,
            "passphrase": "",
        },
    },
    {
        "id": "asmOllama0000001",
        "name": "ASM Ollama",
        "type": "ollamaApi",
        "data": {"baseUrl": os.environ.get("OLLAMA_BASE_URL", "http://ollama:11434")},
    },
]
# Optional Gemini credential: only import it when an API key is configured.
gemini_api_key = os.environ.get("GEMINI_API_KEY", "").strip()
if gemini_api_key:
    creds.append({
        "id": "asmGemini0000001",
        "name": "ASM Gemini",
        "type": "googlePalmApi",
        "data": {
            "host": "https://generativelanguage.googleapis.com",
            "apiKey": gemini_api_key,
        },
    })

json.dump(creds, sys.stdout)
