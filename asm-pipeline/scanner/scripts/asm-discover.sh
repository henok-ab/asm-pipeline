#!/usr/bin/env bash
# asm-discover.sh <domain> [--brute]
# Subdomain enumeration -> DNS resolution -> live HTTP probing.
# Tools: subfinder, assetfinder, (shuffledns+massdns), dnsx, httpx.
set -uo pipefail
. "$(dirname "$(readlink -f "$0")")/asm-common.sh"

DOMAIN="$(printf '%s' "${1:-}" | tr '[:upper:]' '[:lower:]')"
BRUTE="$ASM_BRUTEFORCE"; [ "${2:-}" = "--brute" ] && BRUTE=1
valid_domain "$DOMAIN" || die "invalid domain '$DOMAIN'" 2
for t in dnsx httpx python3; do have "$t" || die "required tool missing: $t" 3; done
have subfinder || have assetfinder || die "need at least one of subfinder/assetfinder" 3

mkdir -p "$ASM_HOME/runs"
WORK="$(mktemp -d "$ASM_HOME/runs/discover.XXXXXX")"
trap 'rm -rf "$WORK"' EXIT
: > "$WORK/warnings.txt"
STARTED="$(now)"
ESC="${DOMAIN//./\\.}"
log "discovery start: $DOMAIN (bruteforce=$BRUTE)"

# --- 1. passive + (optional) active subdomain enumeration -------------------
: > "$WORK/subfinder.txt"; : > "$WORK/assetfinder.txt"; : > "$WORK/shuffledns.txt"

if have subfinder; then
  timeout 900 subfinder -d "$DOMAIN" -silent > "$WORK/subfinder.txt" 2> "$WORK/subfinder.err" \
    || warn "subfinder exited non-zero (partial results kept)"
else warn "subfinder not installed"; fi

if have assetfinder; then
  timeout 300 assetfinder --subs-only "$DOMAIN" > "$WORK/assetfinder.txt" 2> "$WORK/assetfinder.err" \
    || warn "assetfinder exited non-zero (partial results kept)"
else warn "assetfinder not installed"; fi

if [ "$BRUTE" = "1" ]; then
  if have shuffledns && have massdns && [ -s "$ASM_WORDLIST" ] && [ -s "$ASM_RESOLVERS" ]; then
    log "shuffledns brute-force with $(wc -l < "$ASM_WORDLIST") words"
    timeout 1800 shuffledns -d "$DOMAIN" -w "$ASM_WORDLIST" -r "$ASM_RESOLVERS" \
      -mode bruteforce -t "$ASM_SHUFFLEDNS_THREADS" -silent > "$WORK/shuffledns.txt" 2> "$WORK/shuffledns.err" \
      || warn "shuffledns exited non-zero (partial results kept)"
  else
    warn "bruteforce requested but shuffledns/massdns/wordlist/resolvers unavailable"
  fi
fi

# --- 2. merge, scope-filter, dedupe, cap ------------------------------------
{ echo "$DOMAIN"; cat "$WORK/subfinder.txt" "$WORK/assetfinder.txt" "$WORK/shuffledns.txt"; } \
  | tr -d '\r' | tr '[:upper:]' '[:lower:]' | sed -e 's/^\*\.//' -e 's/\.$//' \
  | grep -E "^([a-z0-9-]+\.)*${ESC}$" | sort -u > "$WORK/all.sorted"
{ echo "$DOMAIN"; grep -vx "$DOMAIN" "$WORK/all.sorted" | head -n "$((ASM_MAX_HOSTS - 1))"; } > "$WORK/all.txt"
log "candidate hosts: $(wc -l < "$WORK/all.txt")"

# --- 3. DNS resolution (wildcard-filtered) ----------------------------------
RES_ARGS=(); [ -s "$ASM_RESOLVERS" ] && RES_ARGS=(-r "$ASM_RESOLVERS")
timeout 900 dnsx -l "$WORK/all.txt" -a -aaaa -cname -resp -j -silent -retry 2 -wd "$DOMAIN" \
  "${RES_ARGS[@]}" > "$WORK/dnsx.jsonl" 2> "$WORK/dnsx.err" || warn "dnsx exited non-zero"

python3 "$ASM_HOME/bin/asm_normalize.py" resolved "$WORK" || true
log "hosts with A/AAAA: $(wc -l < "$WORK/resolved.txt" 2>/dev/null || echo 0)"

# --- 4. live HTTP probe ------------------------------------------------------
: > "$WORK/httpx.jsonl"
if [ -s "$WORK/resolved.txt" ]; then
  timeout 1200 httpx -l "$WORK/resolved.txt" -silent -j -nc -duc \
    -ports "$ASM_HTTPX_PORTS_DISCOVERY" -status-code -title -web-server \
    -timeout 8 -retries 1 -threads "$ASM_HTTPX_THREADS" \
    > "$WORK/httpx.jsonl" 2> "$WORK/httpx.err" || warn "httpx exited non-zero (partial results kept)"
fi

# --- 5. normalise -> single JSON line on stdout -----------------------------
python3 "$ASM_HOME/bin/asm_normalize.py" discover "$WORK" \
  --domain "$DOMAIN" --started "$STARTED" --finished "$(now)" --bruteforce "$BRUTE"
