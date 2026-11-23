#!/usr/bin/env bash
# Shared helpers for the ASM scanner scripts. Source this file; do not execute it.
# Contract for all asm-*.sh scripts:
#   * stdout  -> exactly ONE line of JSON (consumed by n8n)
#   * stderr  -> human-readable logs
#   * exit 0 on success, non-zero on fatal error

ASM_HOME="${ASM_HOME:-/opt/asm}"
# Our bin dir first: ProjectDiscovery's `httpx` must win over the Python `httpx` CLI.
export PATH="$ASM_HOME/bin:/usr/local/bin:/usr/bin:/bin:$PATH"

# shellcheck disable=SC1091
[ -f "$ASM_HOME/etc/asm.conf" ] && . "$ASM_HOME/etc/asm.conf"

: "${ASM_RESOLVERS:=$ASM_HOME/etc/resolvers.txt}"
: "${ASM_WORDLIST:=$ASM_HOME/wordlists/subdomains-top5000.txt}"
: "${ASM_BRUTEFORCE:=0}"
: "${ASM_SHUFFLEDNS_THREADS:=50}"
: "${ASM_HTTPX_THREADS:=40}"
: "${ASM_HTTPX_PORTS_DISCOVERY:=80,443,8080,8443}"
: "${ASM_HTTPX_PORTS_FINGERPRINT:=80,443,3000,5000,8000,8008,8080,8081,8443,8888,9000,9443}"
: "${ASM_NMAP_PORTS:=21,22,23,25,53,80,110,111,135,139,143,389,443,445,465,587,993,995,1433,1521,2049,2375,2376,3000,3306,3389,5000,5432,5601,5900,5984,6379,8000,8080,8081,8443,8888,9000,9090,9200,9300,11211,27017}"
: "${ASM_NMAP_MAX_RATE:=200}"
: "${ASM_NMAP_SKIP_CDN:=1}"
: "${ASM_NUCLEI_SEVERITY:=low,medium,high,critical}"
: "${ASM_NUCLEI_RATE:=50}"
: "${ASM_NUCLEI_CONC:=25}"
: "${ASM_NUCLEI_EXCLUDE_TAGS:=dos,fuzz,bruteforce,intrusive}"
: "${ASM_NUCLEI_MAX_SECONDS:=3600}"
: "${ASM_MAX_HOSTS:=500}"

ASM_DOMAIN_RE='^([a-z0-9]([a-z0-9-]{0,61}[a-z0-9])?\.)+[a-z]{2,63}$'
ASM_URL_RE='^https?://[a-z0-9.-]+(:[0-9]{1,5})?$'

log()  { printf '[asm %s] %s\n' "$(date -u +%H:%M:%S)" "$*" >&2; }
now()  { date -u +%Y-%m-%dT%H:%M:%SZ; }
have() { command -v "$1" >/dev/null 2>&1; }
die()  { log "ERROR: $*"; exit "${2:-1}"; }
warn() { log "WARN: $*"; [ -n "${WORK:-}" ] && printf '%s\n' "$*" >> "$WORK/warnings.txt"; return 0; }
valid_domain() { [[ "$1" =~ $ASM_DOMAIN_RE ]] && [ "${#1}" -le 253 ]; }
