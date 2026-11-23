#!/usr/bin/env bash
# asm-vuln.sh --stdin      (one http(s)://host[:port] URL per line on stdin)
# Runs nuclei with a conservative profile (no DoS/fuzz/bruteforce/intrusive templates).
set -uo pipefail
. "$(dirname "$(readlink -f "$0")")/asm-common.sh"

[ "${1:-}" = "--stdin" ] || die "usage: asm-vuln.sh --stdin" 2
for t in nuclei python3; do have "$t" || die "required tool missing: $t" 3; done

mkdir -p "$ASM_HOME/runs"
WORK="$(mktemp -d "$ASM_HOME/runs/vuln.XXXXXX")"
trap 'rm -rf "$WORK"' EXIT
: > "$WORK/warnings.txt"; : > "$WORK/nuclei.jsonl"
STARTED="$(now)"

tr -d '\r' | tr '[:upper:]' '[:lower:]' | grep -E "$ASM_URL_RE" | sort -u \
  | head -n "$ASM_MAX_HOSTS" > "$WORK/targets.txt" || true
log "nuclei targets: $(wc -l < "$WORK/targets.txt")"

TV="$(nuclei -templates-version 2>&1 | grep -oE 'v?[0-9]+\.[0-9]+\.[0-9]+' | head -n1 || true)"

if [ -s "$WORK/targets.txt" ]; then
  timeout "$ASM_NUCLEI_MAX_SECONDS" nuclei -l "$WORK/targets.txt" -jsonl -silent -nc -duc \
    -severity "$ASM_NUCLEI_SEVERITY" -exclude-tags "$ASM_NUCLEI_EXCLUDE_TAGS" \
    -rate-limit "$ASM_NUCLEI_RATE" -c "$ASM_NUCLEI_CONC" -timeout 10 -retries 1 \
    -o "$WORK/nuclei.jsonl" 2> "$WORK/nuclei.err" || warn "nuclei exited non-zero or timed out (partial results kept)"
fi

python3 "$ASM_HOME/bin/asm_normalize.py" vuln "$WORK" \
  --started "$STARTED" --finished "$(now)" --severity "$ASM_NUCLEI_SEVERITY" --templates-version "${TV:-}"
