# Handy mongosh queries

Open a shell:

    set -a; . ./.env; set +a
    docker compose exec mongo mongosh -u "$MONGO_APP_USER" -p "$MONGO_APP_PASSWORD" --authenticationDatabase asm asm

```js
// Inventory of live hosts for a domain
db.domains.find({root_domain:"example.com", status:"live"}, {host:1,"dns.a":1,"http.services.status_code":1,_id:0})

// Hosts with critical/high nuclei findings
db.domains.find({$or:[{"nuclei.counts.critical":{$gt:0}},{"nuclei.counts.high":{$gt:0}}]},{host:1,"nuclei.findings":1})

// Every open non-web port seen
db.domains.aggregate([{$unwind:"$port_scanning.ips"},{$unwind:"$port_scanning.ips.open_ports"},
  {$match:{"port_scanning.ips.open_ports.port":{$nin:[80,443]}}},
  {$project:{_id:0,host:1,ip:"$port_scanning.ips.ip",port:"$port_scanning.ips.open_ports.port",svc:"$port_scanning.ips.open_ports.service"}}])

// Certificates expiring within 30 days
db.domains.find({"tls.certificates":{$elemMatch:{days_to_expiry:{$gte:0,$lte:30}}}},{host:1,"tls.certificates.not_after":1})

// New assets since a date (trend analysis)
db.domains.find({root_domain:"example.com", first_seen:{$gte:ISODate("2025-01-01")}},{host:1,first_seen:1})

// Trend: verdict + counts per scan
db.scan_runs.find({root_domain:"example.com", status:"completed"},
  {_id:0,started_at:1,"summary.verdict":1,"summary.stats":1}).sort({started_at:1})

// Dangling CNAMEs (takeover candidates)
db.domains.find({"dns.dangling_cname":true},{host:1,"dns.cname":1})
```
