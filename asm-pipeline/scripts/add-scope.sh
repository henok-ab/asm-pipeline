#!/usr/bin/env bash
# Authorise a domain for scanning (adds it to the MongoDB "scope" allow-list).
#   scripts/add-scope.sh example.com "Owner: Jane Doe, authorisation ref SEC-123"
#   scripts/add-scope.sh --list
#   scripts/add-scope.sh --remove example.com
# Subdomains of an authorised domain are in scope automatically. Nothing outside scope can be scanned.
set -euo pipefail
cd "$(dirname "$0")/.."
set -a; . ./.env; set +a
RE='^([a-z0-9]([a-z0-9-]{0,61}[a-z0-9])?\.)+[a-z]{2,63}$'
mongo() { docker compose exec -T "$@" mongo mongosh --quiet -u "$MONGO_APP_USER" -p "$MONGO_APP_PASSWORD" --authenticationDatabase asm asm --eval "$JS"; }

if [ "${1:-}" = "--list" ]; then
  JS='db.scope.find({}, {_id:0}).forEach(d => print(JSON.stringify(d)))'; mongo -e X=1; exit 0
fi
if [ "${1:-}" = "--remove" ]; then
  D="$(echo "${2:?domain}" | tr '[:upper:]' '[:lower:]')"; [[ "$D" =~ $RE ]] || { echo "invalid domain"; exit 1; }
  JS='printjson(db.scope.deleteOne({domain: process.env.DOMAIN}))'; mongo -e DOMAIN="$D"; exit 0
fi
D="$(echo "${1:?usage: add-scope.sh <domain> \"<authorisation note>\"}" | tr '[:upper:]' '[:lower:]')"
NOTE="${2:?Provide an authorisation note (who authorised this and where it is documented)}"
[[ "$D" =~ $RE ]] || { echo "invalid domain: $D"; exit 1; }
JS='printjson(db.scope.updateOne({domain: process.env.DOMAIN}, {$set: {domain: process.env.DOMAIN, active: true, note: process.env.NOTE, added_at: new Date()}}, {upsert: true}))'
mongo -e DOMAIN="$D" -e NOTE="$NOTE"
echo "Scope now includes: $D"
