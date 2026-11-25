# Autonomous Attack Surface Management (ASM) Pipeline

An **n8n AI agent** that discovers, verifies and stores the external exposure of a domain, using only free / open-source tooling:

> *"Scan example.com"* → agent checks MongoDB history → asks you to **approve** → subdomain discovery → live-host validation → HTTP/TLS fingerprinting → targeted nmap → Nuclei → results upserted into MongoDB → *"example.com is **EXPOSED** because …"*

* **Control plane** (Docker): n8n, PostgreSQL (n8n DB + AI chat memory), MongoDB, optional Ollama (local LLM, no paid API key).
* **Scanner** (any Debian/Ubuntu VM): subfinder, assetfinder, shuffledns/massdns, dnsx, httpx, nmap, nuclei — driven over SSH.
* **Safety first**: scope allow-list + a human approval gate enforced in code, not by the LLM.

> **Only scan systems you own or have written permission to test.** The pipeline refuses anything not on the scope allow-list, but authorisation is *your* responsibility.

New to the design? Read **[docs/DESIGN.md](docs/DESIGN.md)** after the setup. This README is the practical guide.

---

## 1. Architecture at a glance

```
                       ┌─────────────────────────── Docker host ────────────────────────────┐
                       │                                                                      │
  You (n8n chat) ────► │  n8n ──► Approval Interceptor ──► AI Agent ◄──► Ollama (LLM)         │
                       │              │  "APPROVE x.com"       │  ▲                          │
                       │              ▼                        │  └── PostgreSQL (chat memory)│
                       │        MongoDB.approvals              │                              │
                       │                                       ▼  4 tools (sub-workflows)     │
                       │   ┌────────────┬────────────┬──────────────┬──────────────────┐      │
                       │   │ 1 DB query │ 2 Discovery│ 3 Fingerprint│ 4 Vulnerability  │      │
                       │   └─────┬──────┴─────┬──────┴──────┬───────┴────────┬─────────┘      │
                       │         │            │ SSH         │ SSH            │ SSH            │
                       │         ▼            │             │                │                │
                       │     MongoDB  ◄───────┴─ upserts ───┴────────────────┘                │
                       │  domains · scan_runs · scope · approvals                              │
                       └──────────────────────────────────┼───────────────────────────────────┘
                                                          │ ssh (key, forced command)
                                              ┌───────────▼────────────┐
                                              │ Remote Linux scanner   │ ───► Internet / target
                                              │ /opt/asm/bin/asm-*.sh  │
                                              │ subfinder assetfinder  │
                                              │ shuffledns dnsx httpx  │
                                              │ nmap nuclei            │
                                              └────────────────────────┘
```

### What happens in one scan

| # | Stage | Where | Task step |
|---|-------|-------|-----------|
| 1 | You mention a domain in chat | n8n Chat Trigger | 1 |
| 2 | Agent calls **`check_previous_scans`** (last scan time, counts, stored verdict) | MongoDB | 2 |
| 3 | Agent asks you to reply exactly **`APPROVE <domain>`**; a deterministic node records the approval (30 min, single use) | n8n + MongoDB | 3 |
| 4 | **`run_discovery`**: scope check → approval check → SSH `asm-discover.sh` → dedupe → **upsert** | sub-workflow 2 | 4, 5 |
| 5 | **`run_fingerprinting`**: SSH `asm-fingerprint.sh` (httpx tech+TLS, nmap on public non-CDN IPs) → update `http`, `tls`, `port_scanning` | sub-workflow 3 | 6, 8 |
| 6 | **`run_vulnerability_scan`**: SSH `asm-vuln.sh` (nuclei) → update `nuclei`, close the scan, compute verdict | sub-workflow 4 | 7, 8 |
| 7 | Agent answers: **verdict + why + assets + services + findings** | agent | — |

---

## 2. Repository layout

```
asm-pipeline/
├── README.md                    ← you are here
├── docker-compose.yml           n8n + postgres + mongo (+ ollama, mongo-express profiles)
├── .env.example                 all settings/secrets in one place
├── docs/
│   ├── DESIGN.md                design deep-dive (diagrams, data model, gates, scoring)
│   ├── REPORT_TEMPLATE.md       template for the "validation on an authorised domain" report
│   └── SAMPLE_REPORT.md         what generate_report.py produces (from FAKE test data)
├── mongo/init-mongo.js          creates app user, collections, indexes (runs on first start)
├── workflows/                   import these into n8n (fixed IDs so tool links work)
│   ├── 00_orchestrator.json     chat trigger, approval interceptor, AI agent, memory, 4 tools
│   ├── 01_db_query.json         tool: check_previous_scans
│   ├── 02_discovery.json        tool: run_discovery
│   ├── 03_fingerprint.json      tool: run_fingerprinting
│   └── 04_vulnerability.json    tool: run_vulnerability_scan
├── scanner/                     copy to the scanner VM
│   ├── install-scanner.sh       one-shot provisioning (tools, user, SSH key, cron)
│   ├── asm.conf.example         tuning knobs (ports, rates, severity, brute force…)
│   ├── resolvers.txt
│   └── scripts/                 asm-discover.sh, asm-fingerprint.sh, asm-vuln.sh,
│                                asm_normalize.py, asm-ssh-gate.sh, asm-selfcheck.sh, asm-common.sh
├── scripts/                     operator helpers (run on the Docker host)
│   ├── setup-n8n.sh             creates credentials + imports workflows
│   ├── add-scope.sh             authorise / list / remove domains
│   ├── generate_report.py       Markdown report from MongoDB
│   ├── validate_workflows.py    static checks on the workflow JSON
│   ├── make_credentials.py      builds the n8n credential import file from .env
│   └── query-examples.md        useful mongosh queries
└── tests/run.sh                 offline end-to-end test (stub tools, no network)
```

---

## 3. Prerequisites

| Need | Details |
|------|---------|
| Docker host | Docker Engine + Compose v2, ~4 GB RAM (+8 GB and ideally a GPU if you run Ollama locally). Linux/macOS/WSL2. |
| Scanner VM | Debian 12 / Ubuntu 22.04+ , 2 vCPU / 2 GB RAM / 20 GB disk is plenty. **Public IP with unfiltered outbound** (DNS, 80/443 and the scan ports). A cheap VPS is ideal: it keeps scan traffic off your corporate IP. Root access for the one-time install. |
| Network | Docker host → scanner: TCP 22. Scanner → internet. Nothing needs to be exposed *inbound* to the Docker host. |
| LLM | Either Ollama (included) **or** any API-key model supported by n8n (OpenAI, Anthropic, …). The model must support **tool calling**. |
| Authorisation | Written permission for every domain you will scan. |

---

## 4. Setup (≈ 30 minutes)

### Step 0 — Configure secrets

```bash
cd asm-pipeline
cp .env.example .env
# Fill in passwords (letters+digits only):   openssl rand -hex 24
# Fill in N8N_ENCRYPTION_KEY:                openssl rand -hex 32
```

Also fill in `SCANNER_HOST` (scanner IP/DNS). Leave the rest at defaults for now.

### Step 1 — Start the control plane

```bash
docker compose up -d                    # n8n + postgres + mongo
docker compose ps                       # wait until all are "healthy"/"running"
```

* n8n UI: <http://localhost:5678> → **create the owner account now** (required before importing).
* MongoDB was initialised from `mongo/init-mongo.js` (user, collections, unique indexes).

Verify MongoDB:

```bash
set -a; . ./.env; set +a
docker compose exec mongo mongosh -u "$MONGO_APP_USER" -p "$MONGO_APP_PASSWORD" \
  --authenticationDatabase asm asm --eval 'db.getCollectionNames()'
# → [ 'approvals', 'domains', 'scan_runs', 'scope' ]
```

### Step 2 — LLM (choose one)

**A. Local, free (Ollama):**

```bash
docker compose --profile ollama up -d
docker compose exec ollama ollama pull llama3.1:8b      # needs tool-calling support
```

`llama3.1:8b` works but small models are the weakest link for multi-step tool use; if your hardware allows, `qwen2.5:14b` or larger is noticeably more reliable (change the model name in the **Ollama Chat Model** node). To use an Ollama already running on the Docker host, set `OLLAMA_BASE_URL=http://host.docker.internal:11434` in `.env`.

**B. Paid API:** after import, delete the **Ollama Chat Model** node in the orchestrator and attach an OpenAI/Anthropic/etc. *Chat Model* node to the agent's "Chat Model" connector. Nothing else changes.

> Even a weak LLM cannot start an unapproved or out-of-scope scan: the tools enforce both checks themselves.

### Step 3 — Provision the scanner VM

On the **Docker host**, create the SSH key n8n will use:

```bash
mkdir -p secrets
ssh-keygen -t ed25519 -f ./secrets/n8n_scanner_ed25519 -N "" -C "n8n-asm"
```

Copy the `scanner/` folder to the VM and run the installer as root:

```bash
scp -r scanner you@SCANNER_HOST:~/
scp secrets/n8n_scanner_ed25519.pub you@SCANNER_HOST:~/n8n.pub
ssh you@SCANNER_HOST
sudo N8N_PUBKEY="$(cat ~/n8n.pub)" bash ~/scanner/install-scanner.sh
```

The installer: installs packages + Go, builds subfinder/assetfinder/shuffledns/dnsx/httpx/nuclei into `/opt/asm/bin`, builds massdns, downloads a 5 000-word subdomain list, downloads Nuclei templates (and refreshes them daily), creates the unprivileged `asm` user, and installs n8n's public key **with a forced command** (`asm-ssh-gate.sh`) so that key can only run the three pipeline scripts. It finishes with a self-check.

If a `go install` fails with a Go-version message, re-run with a newer toolchain: `sudo GO_VERSION=1.25.0 N8N_PUBKEY=… bash install-scanner.sh`.

### Step 4 — Test the SSH path from the Docker host

```bash
set -a; . ./.env; set +a
ssh -i ./secrets/n8n_scanner_ed25519 -p "${SCANNER_PORT:-22}" "$SCANNER_USER@$SCANNER_HOST" /opt/asm/bin/asm-selfcheck.sh
```

Every required tool must show `[ok]` (shuffledns/massdns are optional). A command other than the three pipeline scripts should be rejected with `command not allowed`:

```bash
ssh -i ./secrets/n8n_scanner_ed25519 "$SCANNER_USER@$SCANNER_HOST" id     # → asm-ssh-gate: command not allowed
```

### Step 5 — Import credentials and workflows into n8n

```bash
scripts/setup-n8n.sh
```

This validates the workflow files, creates four credentials (**ASM MongoDB, ASM Postgres, ASM Scanner SSH, ASM Ollama**) from your `.env`, and imports the five workflows with fixed IDs.

<details><summary>Manual alternative (if the script cannot be used)</summary>

1. In n8n create the four credentials with exactly these names: `ASM MongoDB` (MongoDB, connection string `mongodb://asm_app:<pw>@mongo:27017/asm?authSource=asm`, database `asm`), `ASM Postgres` (host `postgres`), `ASM Scanner SSH` (SSH, private-key auth), `ASM Ollama` (base URL).
2. *Workflows → Import from file* for each of the five JSON files.
3. Open each imported workflow and, wherever a node shows a credential warning, select the matching credential.
4. In the orchestrator, open each of the four tool nodes and make sure the **Workflow** field points to the matching sub-workflow.
</details>

### Step 6 — Authorise your target

Nothing can be scanned until the domain is in the allow-list:

```bash
scripts/add-scope.sh example.com "Owner: Jane Doe — authorisation ref SEC-123, 2026-11-22"
scripts/add-scope.sh --list
```

Subdomains of an authorised domain are automatically in scope.

### Step 7 — Run your first scan

Open **ASM - 0. Orchestrator (chat agent)** in n8n and click **Open chat** (no need to activate the workflow).

```
You:    scan example.com
Agent:  [calls check_previous_scans]  example.com has never been scanned. … Reply exactly: APPROVE example.com
You:    APPROVE example.com
Agent:  [run_discovery → run_fingerprinting → run_vulnerability_scan]
        Verdict: EXPOSED — … (reasons, assets, services, Nuclei findings, next steps)
```

A full scan of a small domain typically takes 5–30 minutes (Nuclei dominates). The chat stays "thinking" meanwhile; watch progress in n8n **Executions**.

> Do **not** activate the chat trigger as a *public* chat URL without authentication — anybody reaching it could talk to a scanning agent. The trigger ships with `public: false`.

---

## 5. Looking at the results

```bash
# Browse in a web UI (http://localhost:8081, login from .env)
docker compose --profile ui up -d

# or query directly — see scripts/query-examples.md
docker compose exec mongo mongosh -u "$MONGO_APP_USER" -p "$MONGO_APP_PASSWORD" --authenticationDatabase asm asm
> db.domains.find({root_domain:"example.com", status:"live"}, {host:1, "http.services.status_code":1})
```

Each host is **one document** in `domains`, built up stage by stage:

```jsonc
{
  "host": "api.example.com",  "root_domain": "example.com",
  "first_seen": ISODate(…), "last_seen": ISODate(…), "last_scan_id": "scan-…",
  "status": "live",                       // live | resolved | unresolved
  "dns":  { "a": [...], "aaaa": [...], "cname": [...], "dangling_cname": false },
  "http": { "services": [{ "url", "status_code", "title", "webserver", "tech": [...], "cdn" }] },
  "tls":  { "certificates": [{ "port", "version", "issuer_cn", "not_after", "days_to_expiry", "expired", "self_signed", … }] },
  "port_scanning": { "ips": [{ "ip", "cdn", "scanned", "skip_reason", "open_ports": [{ "port", "service", "product", "version" }] }] },
  "nuclei": { "findings": [{ "template_id", "name", "severity", "matched_at", "cve": [] }], "counts": { "critical": 0, … } }
}
```

`scan_runs` keeps one document per approved scan (who/when approved, stages, final **summary + verdict**) → use it for trend analysis.

---

## 6. The validation run (deliverable)

1. Pick a domain you are authorised to test (e.g. one you own, or a deliberately vulnerable lab domain).
2. Add it to scope (Step 6) and run the chat flow (Step 7).
3. Generate the report from what is actually in MongoDB:

   ```bash
   python3 scripts/generate_report.py yourdomain.tld > reports/yourdomain.tld.md
   ```

   It lists discovered assets, exposed services, TLS observations, Nuclei findings, scan history and the verdict. Add your own commentary using `docs/REPORT_TEMPLATE.md` as a guide.
4. Re-run once more later: the second run must show **no duplicate hosts** and `new_assets: 0` if nothing changed (idempotency), and a second row in the trend table.

`docs/SAMPLE_REPORT.md` shows the report format. **It was produced from fake offline test data, not a real scan.**

### Acceptance criteria → where they are met

| Criterion | Mechanism |
|-----------|-----------|
| Agent checks history before scanning | System prompt rule #1 + `check_previous_scans` tool (reads `scan_runs` + `domains`) |
| Starts only after explicit approval | `Approval Interceptor` (code, not LLM) writes a single-use 30-min approval only for the exact message `APPROVE <domain>`; `run_discovery` refuses without it; later stages refuse without an approved running scan |
| Deduplicated, idempotent updates | Unique index on `domains.host` + `update … upsert` keyed by `host`; `first_seen` carried over; per-stage `$set` of only that stage's sections |
| Structured asset + service data per live host | `dns`, `http`, `tls`, `port_scanning`, `nuclei` sections (see §5) |
| Final answer says whether exposed and why | `verdict` + `reasons[]` computed deterministically from stored data; agent must relay them |

---

## 7. Configuration knobs

| What | Where |
|------|-------|
| Brute-force subdomains (shuffledns), ports, rates, nuclei severity/tags, host cap | `/opt/asm/etc/asm.conf` on the scanner (see `scanner/asm.conf.example`) |
| Approval lifetime (30 min) | `TTL_MIN` in the **Approval Interceptor** node; text in Gate error messages |
| Scan staleness window (6 h) | `Gate` nodes in sub-workflows 3 and 4 |
| Risky-port lists and scoring | `HIGH_RISK` / `MEDIUM_RISK` / `LOW_RISK` in the summary Code nodes (workflows 1 and 4 — keep both identical) |
| LLM model / provider | **Ollama Chat Model** node |
| Add a domain / remove it | `scripts/add-scope.sh` |
| Pin n8n version | `N8N_VERSION` in `.env` |

---

## 8. Troubleshooting

| Symptom | Likely cause / fix |
|---------|--------------------|
| `setup-n8n.sh`: "no owner/user" error on import | Create the n8n owner account in the browser first, then re-run. |
| A node shows *credential not set* | Credential names/IDs differ: re-run `setup-n8n.sh`, or select the credential manually. |
| Agent never calls tools / answers with made-up text | Model too small or without tool support. Use a bigger/tool-capable model. |
| Agent says it is waiting for approval after you typed APPROVE | The message must be *exactly* `APPROVE example.com` (nothing else in the message). |
| Tool error `REFUSED: … not in the authorised scope` | `scripts/add-scope.sh <domain> "<note>"`. |
| Tool error `REFUSED: no valid user approval` | Approvals are single-use and expire after 30 min — type `APPROVE <domain>` again. |
| `Discovery script failed (exit 3): required tool missing` | Run `/opt/asm/bin/asm-selfcheck.sh` on the scanner; re-run installer. |
| `httpx` self-check warns it is the Python CLI | `pip`-installed `httpx` shadows it; scripts prepend `/opt/asm/bin`, but remove the Python one if you can. |
| SSH node: "command not allowed" | The forced-command gate only allows the exact commands the workflows send. Don't edit SSH node commands (or edit `asm-ssh-gate.sh` too). |
| SSH node: auth failure | Public key not in `/home/asm/.ssh/authorized_keys`; check `SCANNER_*` in `.env` and re-run `setup-n8n.sh`. |
| Scan "stuck" at stage `discovery_done` etc. | A tool call failed mid-way. A `running` scan older than 6 h is treated as abandoned; just approve and start again. |
| Empty results for a real domain | Outbound DNS/HTTP blocked on the scanner; check `asm-discover.sh <domain>` manually on the VM (JSON on stdout, logs on stderr). |
| Very slow Nuclei | Lower `ASM_NUCLEI_RATE`/severity, or raise `ASM_NUCLEI_MAX_SECONDS`; partial results are kept on timeout. |
| Postgres memory table missing | n8n creates `n8n_chat_histories` on first use; ensure the **ASM Postgres** credential works. |

Run any scanner script by hand to debug:

```bash
sudo -u asm /opt/asm/bin/asm-discover.sh example.com | python3 -m json.tool | head
printf 'www.example.com\n' | sudo -u asm /opt/asm/bin/asm-fingerprint.sh --stdin | python3 -m json.tool | head -40
```

---

## 9. What has and has not been verified

**Verified offline** (`tests/run.sh`, no network, no Docker): shell/Python syntax; the three scanner scripts end-to-end with *stub* tools (host filtering, wildcard/case dedupe, CDN/private-IP skipping, nmap-XML and nuclei-JSONL normalisation, SSH-gate allow-list); every Code node's JavaScript; the sub-workflow logic and gates against an in-memory MongoDB fake — no-approval refusal, out-of-scope refusal, single-use approvals, stage ordering, idempotent re-scan with preserved `first_seen`, correct sections stored, deterministic verdict.

**Not verified here — please check on your first run:**

* Live behaviour of **n8n itself** with these workflow files (node parameter schemas for the MongoDB, SSH, Tool-Workflow and Agent nodes follow recent n8n 1.x releases; very new or old versions may need a node re-selected). Pinning `N8N_VERSION` after your first good run is recommended.
* The **real tools' flags/JSON** against current releases (subfinder, dnsx, httpx, nmap, nuclei change over time). Scripts tolerate missing fields and keep partial results, and `asm_normalize.py` is the only place to adapt if a JSON field is renamed.
* Quality of the **LLM's orchestration** with your chosen model.
* The scan of a **real, authorised domain** — that report is for you to produce (Section 6).

---

## 10. Limitations and ideas for next steps

* Scans run synchronously inside one chat turn; for very large domains move to a queue/webhook-callback pattern (the stages are already separate workflows).
* Hosts that disappear are not deleted; use `last_seen`/`last_scan_id` to age them out.
* Only HTTP(S) URLs go to Nuclei; non-web services are covered by nmap detection and the risk list only.
* IPv6 is recorded but not port-scanned.
* Scheduling / continuous monitoring is deliberately out of scope (it would need a separate, pre-authorised approval model); trend data in `scan_runs` is ready for it.
* Add notifications (Slack/email) after the vulnerability stage, or a dashboard on top of `scan_runs` and `domains`.
