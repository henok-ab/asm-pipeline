#!/bin/bash
# Forced-command gate for the n8n SSH key (authorized_keys: command="...asm-ssh-gate.sh",restrict ...).
# Only the exact command shapes emitted by the n8n workflows are allowed.
cmd="${SSH_ORIGINAL_COMMAND:-}"
re_discover='^/opt/asm/bin/asm-discover\.sh [a-z0-9.-]{4,253}$'
re_stdin="^echo '[A-Za-z0-9+/=]*' \| base64 -d \| /opt/asm/bin/asm-(fingerprint|vuln)\.sh --stdin\$"
re_check='^/opt/asm/bin/asm-selfcheck\.sh$'
if [[ "$cmd" =~ $re_discover ]] || [[ "$cmd" =~ $re_stdin ]] || [[ "$cmd" =~ $re_check ]]; then
  exec /bin/bash -c "$cmd"
fi
echo "asm-ssh-gate: command not allowed" >&2
exit 126
