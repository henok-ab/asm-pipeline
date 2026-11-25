#!/usr/bin/env bash
# Builds a throw-away fake scanner (ASM_HOME) with STUB subfinder/dnsx/httpx/nmap/nuclei so the real
# asm-*.sh scripts + n8n workflow logic can be tested offline, without touching any network.
# Usage: make_stubs.sh <target-dir>
set -euo pipefail
T="${1:?usage: make_stubs.sh <target-dir>}"
REPO="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
rm -rf "$T" && mkdir -p "$T/bin" "$T/etc" "$T/runs"
cp "$REPO"/scanner/scripts/*.sh "$REPO"/scanner/scripts/*.py "$T/bin/"
cd "$T/bin"
cat > subfinder <<'EOF'
#!/bin/bash
printf '%s\n' www.example.com api.example.com dev.example.com old.example.com WWW.EXAMPLE.COM '*.wild.example.com' evil.other.com
EOF
cat > assetfinder <<'EOF'
#!/bin/bash
printf '%s\n' www.example.com cdn.example.com mail.example.net
EOF
cat > dnsx <<'EOF'
#!/bin/bash
while [ $# -gt 0 ]; do [ "$1" = "-l" ] && L="$2"; shift; done
while read -r h; do
 case "$h" in
  old.example.com) echo "{\"host\":\"$h\",\"cname\":[\"gone.herokuapp.com\"],\"status_code\":\"NOERROR\"}";;
  dev.example.com) echo "{\"host\":\"$h\",\"a\":[\"10.0.0.5\"],\"status_code\":\"NOERROR\"}";;
  cdn.example.com) echo "{\"host\":\"$h\",\"a\":[\"104.16.1.1\"],\"status_code\":\"NOERROR\"}";;
  api.example.com) echo "{\"host\":\"$h\",\"a\":[\"34.1.1.10\"],\"status_code\":\"NOERROR\"}";;
  wild.example.com) ;;
  *) echo "{\"host\":\"$h\",\"a\":[\"34.1.1.20\"],\"aaaa\":[\"2001:db8::1\"],\"status_code\":\"NOERROR\"}";;
 esac
done < "$L"
EOF
cat > httpx <<'EOF'
#!/bin/bash
[ "$1" = "-version" ] && { echo "Current Version: v1.6.0 projectdiscovery.io" >&2; exit 0; }
FP=0; while [ $# -gt 0 ]; do [ "$1" = "-l" ] && L="$2"; [ "$1" = "-tls-grab" ] && FP=1; shift; done
while read -r h; do
  case "$h" in dev.example.com) continue;; esac
  IP=34.1.1.20; CDN=false; [ "$h" = api.example.com ] && IP=34.1.1.10; [ "$h" = cdn.example.com ] && { IP=104.16.1.1; CDN=true; }
  if [ $FP = 1 ]; then
   echo "{\"input\":\"$h\",\"url\":\"https://$h\",\"scheme\":\"https\",\"port\":\"443\",\"status_code\":200,\"title\":\"Hello $h\",\"webserver\":\"nginx\",\"tech\":[\"Nginx\",\"React\"],\"content_type\":\"text/html\",\"content_length\":1234,\"a\":[\"$IP\"],\"cdn\":$CDN,\"cdn_name\":\"cloudflare\",\"tls\":{\"tls_version\":\"tls13\",\"cipher\":\"TLS_AES_128_GCM_SHA256\",\"not_before\":\"2024-01-01T00:00:00Z\",\"not_after\":\"2024-03-01T00:00:00Z\",\"subject_cn\":\"$h\",\"subject_an\":[\"$h\"],\"issuer_cn\":\"R3\",\"issuer_org\":[\"Let's Encrypt\"],\"self_signed\":false,\"mismatched\":false,\"fingerprint_hash\":{\"sha256\":\"abc$h\"}}}"
   echo "{\"input\":\"$h\",\"url\":\"http://$h:8080\",\"scheme\":\"http\",\"port\":\"8080\",\"status_code\":403,\"title\":\"\",\"webserver\":\"Apache\",\"a\":[\"$IP\"],\"cdn\":$CDN}"
  else
   echo "{\"input\":\"$h\",\"url\":\"https://$h\",\"scheme\":\"https\",\"port\":\"443\",\"status_code\":200,\"title\":\"Hello\",\"webserver\":\"nginx\"}"
  fi
done < "$L"
EOF
cat > nmap <<'EOF'
#!/bin/bash
while [ $# -gt 0 ]; do [ "$1" = "-iL" ] && L="$2"; [ "$1" = "-oX" ] && X="$2"; shift; done
{ echo '<?xml version="1.0"?><nmaprun>'
while read -r ip; do
 echo "<host><address addr=\"$ip\" addrtype=\"ipv4\"/><ports>"
 echo '<port protocol="tcp" portid="443"><state state="open"/><service name="https" product="nginx" version="1.24.0" tunnel="ssl"><cpe>cpe:/a:nginx:nginx:1.24.0</cpe></service></port>'
 [ "$ip" = 34.1.1.10 ] && echo '<port protocol="tcp" portid="6379"><state state="open"/><service name="redis" product="Redis key-value store" version="6.0.16"/></port><port protocol="tcp" portid="22"><state state="open"/><service name="ssh" product="OpenSSH" version="8.9"/></port><port protocol="tcp" portid="25"><state state="closed"/></port>'
 echo "</ports></host>"
done < "$L"; echo '</nmaprun>'; } > "$X"
EOF
cat > nuclei <<'EOF'
#!/bin/bash
[ "$1" = "-templates-version" ] && { echo "[INF] Current nuclei-templates version: v10.1.2 (/root/nuclei-templates)"; exit 0; }
while [ $# -gt 0 ]; do [ "$1" = "-o" ] && O="$2"; shift; done
cat > "$O" <<'J'
{"template-id":"redis-exposed","info":{"name":"Redis Unauth","severity":"critical","tags":["redis","unauth"],"description":"Redis without auth","reference":["https://x"],"classification":{"cve-id":null}},"type":"tcp","host":"api.example.com","matched-at":"https://api.example.com:8080/x","timestamp":"2024-02-01T00:00:00Z"}
{"template-id":"redis-exposed","info":{"name":"Redis Unauth","severity":"critical","tags":"redis,unauth"},"type":"tcp","host":"api.example.com","matched-at":"https://api.example.com:8080/x"}
{"template-id":"git-config","info":{"name":"Git config","severity":"medium","tags":["exposure"],"classification":{"cve-id":["cve-2000-1"],"cvss-score":5.3}},"type":"http","host":"https://www.example.com","matched-at":"https://www.example.com/.git/config"}
{"template-id":"tech-detect","info":{"name":"Tech","severity":"info"},"type":"http","host":"https://www.example.com","matched-at":"www.example.com:443"}
J
EOF
chmod +x *
cp "$REPO/scanner/resolvers.txt" "$T/etc/"
