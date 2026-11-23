#!/usr/bin/env bash
# asm-fingerprint.sh --stdin      (one hostname per line on stdin)
# httpx full fingerprint (+TLS) then targeted nmap on non-CDN public IPs.
set -uo pipefail
. "$(dirname "$(readlink -f "$0")")/asm-common.sh"

[ "${1:-}" = "--stdin" ] || die "usage: asm-fingerprint.sh --stdin" 2
for t in httpx python3; do have "$t" || die "required tool missing: $t" 3; done

mkdir -p "$ASM_HOME/runs"
WORK="$(mktemp -d "$ASM_HOME/runs/fingerprint.XXXXXX")"
trap 'rm -rf "$WORK"' EXIT
: > "$WORK/warnings.txt"; : > "$WORK/httpx.jsonl"
STARTED="$(now)"

# Strict allow-list on every input line (defence in depth; n8n validates too).
tr -d '\r' | tr '[:upper:]' '[:lower:]' | grep -E "$ASM_DOMAIN_RE" | sort -u \
  | head -n "$ASM_MAX_HOSTS" > "$WORK/hosts.txt" || true
log "fingerprint targets: $(wc -l < "$WORK/hosts.txt")"

if [ -s "$WORK/hosts.txt" ]; then
  timeout 1800 httpx -l "$WORK/hosts.txt" -silent -j -nc -duc \
    -ports "$ASM_HTTPX_PORTS_FINGERPRINT" -status-code -title -web-server -tech-detect \
    -content-type -content-length -ip -cname -cdn -tls-grab -follow-redirects \
    -timeout 10 -retries 1 -threads "$ASM_HTTPX_THREADS" \
    > "$WORK/httpx.jsonl" 2> "$WORK/httpx.err" || warn "httpx exited non-zero (partial results kept)"

  python3 "$ASM_HOME/bin/asm_normalize.py" fp-plan "$WORK" --skip-cdn "$ASM_NMAP_SKIP_CDN"

  if [ -s "$WORK/nmap_targets.txt" ]; then
    if have nmap; then
      log "nmap on $(wc -l < "$WORK/nmap_targets.txt") public non-CDN IPs"
      timeout 3600 nmap -Pn -sT -sV --version-light --open -T3 --max-retries 2 \
        --host-timeout 10m --max-rate "$ASM_NMAP_MAX_RATE" -p "$ASM_NMAP_PORTS" \
        -iL "$WORK/nmap_targets.txt" -oX "$WORK/nmap.xml" > /dev/null 2> "$WORK/nmap.err" \
        || warn "nmap exited non-zero (partial results kept)"
    else warn "nmap not installed; port_scanning skipped"; fi
  fi
fi

python3 "$ASM_HOME/bin/asm_normalize.py" fp-final "$WORK" \
  --started "$STARTED" --finished "$(now)" --ports "$ASM_NMAP_PORTS"
