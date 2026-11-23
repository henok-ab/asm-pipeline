#!/usr/bin/env bash
#
# install-scanner.sh — provision a Debian/Ubuntu VM as the ASM "remote scanner".
#
# Run as root ON THE SCANNER HOST, from this directory:
#
#   sudo N8N_PUBKEY="ssh-ed25519 AAAA... n8n-asm" ./install-scanner.sh
#
# Optional environment:
#   GO_VERSION=1.24.4      Go toolchain used to build the ProjectDiscovery tools
#   ASM_USER=asm           unprivileged account n8n logs in as
#   N8N_PUBKEY="..."       public key (single line) n8n will use; installed with a
#                          forced command (asm-ssh-gate.sh) + `restrict`
#   ASM_RESTRICT_KEY=0     skip the forced-command hardening (not recommended)
#
# Idempotent: safe to re-run to upgrade tools.
set -euo pipefail

GO_VERSION="${GO_VERSION:-1.24.4}"
ASM_USER="${ASM_USER:-asm}"
ASM_HOME="/opt/asm"            # fixed: the SSH gate and workflows reference this path
N8N_PUBKEY="${N8N_PUBKEY:-}"
ASM_RESTRICT_KEY="${ASM_RESTRICT_KEY:-1}"
HERE="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"

say()  { printf '\n\033[1;34m==> %s\033[0m\n' "$*"; }
warn() { printf '\033[1;33m[warn]\033[0m %s\n' "$*" >&2; }

[ "$(id -u)" -eq 0 ] || { echo "Run as root (sudo)." >&2; exit 1; }
# shellcheck disable=SC1091
. /etc/os-release
case "${ID:-}" in ubuntu|debian) ;; *) warn "Untested distro '${ID:-unknown}' (Ubuntu 22.04/24.04 or Debian 12 recommended)";; esac

say "1/8 System packages"
export DEBIAN_FRONTEND=noninteractive
apt-get update -y
apt-get install -y --no-install-recommends \
  ca-certificates curl wget git jq nmap dnsutils unzip build-essential libpcap-dev \
  python3 openssh-server coreutils util-linux

say "2/8 Service account and directories"
id "$ASM_USER" >/dev/null 2>&1 || useradd --create-home --shell /bin/bash "$ASM_USER"
install -d -o "$ASM_USER" -g "$ASM_USER" -m 0755 \
  "$ASM_HOME" "$ASM_HOME/bin" "$ASM_HOME/etc" "$ASM_HOME/wordlists" "$ASM_HOME/runs" "$ASM_HOME/logs" "$ASM_HOME/go"

say "3/8 Go toolchain ${GO_VERSION}"
ARCH="$(dpkg --print-architecture)"   # amd64 | arm64
if ! /usr/local/go/bin/go version 2>/dev/null | grep -q "go${GO_VERSION} "; then
  curl -fsSL "https://go.dev/dl/go${GO_VERSION}.linux-${ARCH}.tar.gz" -o /tmp/go.tgz
  rm -rf /usr/local/go
  tar -C /usr/local -xzf /tmp/go.tgz
  rm -f /tmp/go.tgz
fi
/usr/local/go/bin/go version

say "4/8 Open-source tools (subfinder, assetfinder, shuffledns, dnsx, httpx, nuclei)"
runuser -u "$ASM_USER" -- env \
  HOME="/home/$ASM_USER" GOPATH="$ASM_HOME/go" GOBIN="$ASM_HOME/bin" \
  PATH="/usr/local/go/bin:/usr/bin:/bin" CGO_ENABLED=1 \
  bash -euo pipefail -c '
    go install github.com/projectdiscovery/subfinder/v2/cmd/subfinder@latest
    go install github.com/tomnomnom/assetfinder@latest
    go install github.com/projectdiscovery/shuffledns/cmd/shuffledns@latest
    go install github.com/projectdiscovery/dnsx/cmd/dnsx@latest
    go install github.com/projectdiscovery/httpx/cmd/httpx@latest
    go install github.com/projectdiscovery/nuclei/v3/cmd/nuclei@latest
  ' || { warn "A go install failed. If the error mentions the Go version, re-run with a newer GO_VERSION=..."; exit 1; }

say "5/8 massdns (needed by shuffledns)"
if ! command -v massdns >/dev/null 2>&1; then
  rm -rf /tmp/massdns
  git clone --depth 1 https://github.com/blechschmidt/massdns.git /tmp/massdns
  make -C /tmp/massdns
  install -m 0755 /tmp/massdns/bin/massdns /usr/local/bin/massdns
  rm -rf /tmp/massdns
fi

say "6/8 Scripts, config, resolvers, wordlist"
install -m 0755 -o "$ASM_USER" -g "$ASM_USER" "$HERE"/scripts/asm-*.sh "$HERE"/scripts/asm_normalize.py "$ASM_HOME/bin/"
install -m 0644 -o "$ASM_USER" -g "$ASM_USER" "$HERE/resolvers.txt" "$ASM_HOME/etc/resolvers.txt"
[ -f "$ASM_HOME/etc/asm.conf" ] || install -m 0644 -o "$ASM_USER" -g "$ASM_USER" "$HERE/asm.conf.example" "$ASM_HOME/etc/asm.conf"
if [ ! -s "$ASM_HOME/wordlists/subdomains-top5000.txt" ]; then
  curl -fsSL "https://raw.githubusercontent.com/danielmiessler/SecLists/master/Discovery/DNS/subdomains-top1million-5000.txt" \
    -o "$ASM_HOME/wordlists/subdomains-top5000.txt" || warn "wordlist download failed (brute force stays unavailable)"
fi
chown -R "$ASM_USER:$ASM_USER" "$ASM_HOME"

say "7/8 Nuclei templates + daily refresh"
runuser -u "$ASM_USER" -- env HOME="/home/$ASM_USER" "$ASM_HOME/bin/nuclei" -update-templates -silent \
  || warn "template download failed — run '$ASM_HOME/bin/nuclei -update-templates' later as $ASM_USER"
cat > /etc/cron.daily/asm-update-templates <<EOF
#!/bin/sh
runuser -u $ASM_USER -- env HOME=/home/$ASM_USER $ASM_HOME/bin/nuclei -update-templates -silent >$ASM_HOME/logs/nuclei-update.log 2>&1
EOF
chmod 0755 /etc/cron.daily/asm-update-templates
# purge scratch dirs left by killed runs
cat > /etc/cron.daily/asm-clean-runs <<EOF
#!/bin/sh
find $ASM_HOME/runs -mindepth 1 -maxdepth 1 -mtime +1 -exec rm -rf {} +
EOF
chmod 0755 /etc/cron.daily/asm-clean-runs

say "8/8 SSH access for n8n"
install -d -m 0700 -o "$ASM_USER" -g "$ASM_USER" "/home/$ASM_USER/.ssh"
AK="/home/$ASM_USER/.ssh/authorized_keys"
touch "$AK"; chown "$ASM_USER:$ASM_USER" "$AK"; chmod 0600 "$AK"
if [ -n "$N8N_PUBKEY" ]; then
  if [ "$ASM_RESTRICT_KEY" = "1" ]; then
    LINE="command=\"$ASM_HOME/bin/asm-ssh-gate.sh\",restrict $N8N_PUBKEY"
  else
    LINE="$N8N_PUBKEY"
  fi
  grep -qF "$N8N_PUBKEY" "$AK" || echo "$LINE" >> "$AK"
  echo "Public key installed (forced-command gate: $([ "$ASM_RESTRICT_KEY" = 1 ] && echo ON || echo OFF))."
else
  warn "N8N_PUBKEY not set — add n8n's public key to $AK yourself (see README step 3)."
fi

say "Self-check"
runuser -u "$ASM_USER" -- env HOME="/home/$ASM_USER" "$ASM_HOME/bin/asm-selfcheck.sh" || warn "Self-check reported problems (see above)."

cat <<EOF

Done. Next steps:
  * Make sure sshd allows key auth and (ideally) only your n8n host: restrict via firewall / security group.
  * Egress: this host needs outbound DNS, HTTP(S) and the scan ports to the targets.
  * Tune $ASM_HOME/etc/asm.conf if needed (see asm.conf.example).
EOF
