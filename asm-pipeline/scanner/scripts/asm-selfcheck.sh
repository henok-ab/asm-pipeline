#!/usr/bin/env bash
# asm-selfcheck.sh — verify the scanner is ready. Exit 0 only if all REQUIRED tools exist.
. "$(dirname "$(readlink -f "$0")")/asm-common.sh"
rc=0
chk() { # name required(1/0)
  if have "$1"; then printf '  [ok]      %-12s %s\n' "$1" "$(command -v "$1")"
  elif [ "$2" = 1 ]; then printf '  [MISSING] %-12s (required)\n' "$1"; rc=1
  else printf '  [absent]  %-12s (optional)\n' "$1"; fi
}
echo "ASM_HOME=$ASM_HOME"
for t in subfinder assetfinder dnsx httpx nmap nuclei python3; do chk "$t" 1; done
for t in shuffledns massdns; do chk "$t" 0; done
[ -s "$ASM_RESOLVERS" ] && echo "  [ok]      resolvers    $ASM_RESOLVERS" || { echo "  [MISSING] resolvers file"; rc=1; }
[ -s "$ASM_WORDLIST" ]  && echo "  [ok]      wordlist     $ASM_WORDLIST" || echo "  [absent]  wordlist (bruteforce disabled)"
if httpx -version 2>&1 | grep -qi projectdiscovery; then echo "  [ok]      httpx is the ProjectDiscovery build"
else echo "  [WARN]    httpx may be the Python CLI, not ProjectDiscovery"; rc=1; fi
exit $rc
