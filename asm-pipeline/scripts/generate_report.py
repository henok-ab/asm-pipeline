#!/usr/bin/env python3
"""Generate the validation report (Markdown) for a domain straight from MongoDB.

    python3 scripts/generate_report.py example.com > reports/example.com.md
    python3 scripts/generate_report.py --from-json dump.json example.com     # offline / testing

Reads .env for MONGO_APP_USER / MONGO_APP_PASSWORD and queries through `docker compose exec mongo mongosh`
(no pymongo needed).
"""
import argparse
import json
import os
import re
import subprocess
import sys
from datetime import datetime, timezone

ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
DOMAIN_RE = re.compile(r"^([a-z0-9]([a-z0-9-]{0,61}[a-z0-9])?\.)+[a-z]{2,63}$")
SEV = ["critical", "high", "medium", "low", "info", "unknown"]


def load_env():
    env = dict(os.environ)
    p = os.path.join(ROOT, ".env")
    if os.path.exists(p):
        for ln in open(p):
            ln = ln.strip()
            if ln and not ln.startswith("#") and "=" in ln:
                k, v = ln.split("=", 1)
                env.setdefault(k.strip(), v.strip().strip('"').strip("'"))
    return env


def fetch(domain):
    env = load_env()
    js = (
        "JSON.stringify({assets: db.domains.find({root_domain: %s}).toArray(),"
        " runs: db.scan_runs.find({root_domain: %s}).sort({started_at:-1}).limit(10).toArray()})"
    ) % (json.dumps(domain), json.dumps(domain))
    cmd = ["docker", "compose", "exec", "-T", "mongo", "mongosh", "--quiet",
           "-u", env.get("MONGO_APP_USER", "asm_app"), "-p", env.get("MONGO_APP_PASSWORD", ""),
           "--authenticationDatabase", "asm", "asm", "--eval", js]
    r = subprocess.run(cmd, cwd=ROOT, capture_output=True, text=True)
    if r.returncode:
        sys.exit("mongosh failed: " + r.stderr.strip())
    return json.loads(r.stdout.strip().splitlines()[-1])


def esc(s):
    return str(s if s is not None else "").replace("|", "\\|").replace("\n", " ")


def table(headers, rows):
    if not rows:
        return "_none_\n"
    out = ["| " + " | ".join(headers) + " |", "|" + "|".join("---" for _ in headers) + "|"]
    out += ["| " + " | ".join(esc(c) for c in r) + " |" for r in rows]
    return "\n".join(out) + "\n"


def build(domain, data):
    assets = sorted(data.get("assets", []), key=lambda a: a["host"])
    runs = data.get("runs", [])
    done = next((r for r in runs if r.get("status") == "completed"), None)
    summ = (done or {}).get("summary") or {}
    now = datetime.now(timezone.utc).strftime("%Y-%m-%d %H:%M UTC")
    L = [f"# ASM validation report: {domain}", "",
         f"_Generated {now} from MongoDB (`asm.domains`, `asm.scan_runs`)._", ""]

    L += ["## 1. Verdict", ""]
    if summ:
        L += [f"**{summ.get('verdict', 'n/a')}** (exposure level: {summ.get('exposure_level', 'n/a')})", ""]
        L += [f"- {r}" for r in summ.get("reasons", [])]
        L += ["", f"Scan `{done['scan_id']}` approved {done.get('approved_at')} / finished {done.get('finished_at')}.",
              f"Caveat: {summ.get('caveat', '')}", ""]
    else:
        L += ["_No completed scan found for this domain._", ""]

    live = [a for a in assets if a.get("status") == "live"]
    L += ["## 2. Discovered assets", "",
          f"{len(assets)} hostnames stored: {len(live)} live, "
          f"{sum(1 for a in assets if a.get('status') == 'resolved')} resolved without HTTP, "
          f"{sum(1 for a in assets if a.get('status') == 'unresolved')} unresolved.", ""]
    rows = []
    for a in assets:
        svcs = (a.get("http") or {}).get("services") or (a.get("discovery") or {}).get("live_probe") or []
        web = "; ".join(f"{s.get('status_code')} {s.get('url')}" for s in svcs[:3])
        tech = ", ".join(sorted({t for s in svcs for t in (s.get("tech") or [])})[:5])
        rows.append([a["host"], a.get("status"), ", ".join((a.get("dns") or {}).get("a", [])), web, tech,
                     str(a.get("first_seen", ""))[:10]])
    L += [table(["Host", "Status", "IPv4", "HTTP", "Tech", "First seen"], rows)]

    L += ["## 3. Exposed services (nmap)", ""]
    rows = []
    for a in assets:
        for ipr in (a.get("port_scanning") or {}).get("ips", []):
            for p in ipr.get("open_ports", []):
                rows.append([a["host"], f"{ipr['ip']}:{p['port']}/{p.get('protocol', 'tcp')}", p.get("service"),
                             " ".join(x for x in [p.get("product"), p.get("version")] if x)])
    seen, uniq = set(), []
    for r in rows:
        if (r[1], r[0]) not in seen:
            seen.add((r[1], r[0]))
            uniq.append(r)
    L += [table(["Host", "Endpoint", "Service", "Product/version"], uniq)]
    skipped = [(a["host"], i["ip"], i.get("skip_reason")) for a in assets
               for i in (a.get("port_scanning") or {}).get("ips", []) if i.get("skip_reason")]
    if skipped:
        L += ["IPs not port-scanned (by design):", "", table(["Host", "IP", "Reason"], skipped)]

    L += ["## 4. TLS observations", ""]
    rows = []
    for a in assets:
        for c in (a.get("tls") or {}).get("certificates", []):
            flags = [k for k in ("expired", "self_signed", "mismatched", "untrusted") if c.get(k)]
            rows.append([a["host"], c.get("port"), c.get("version"), c.get("issuer_cn"), c.get("not_after"),
                         c.get("days_to_expiry"), ", ".join(flags) or "ok"])
    L += [table(["Host", "Port", "TLS", "Issuer", "Not after", "Days left", "Flags"], rows)]

    L += ["## 5. Nuclei findings", ""]
    fr = []
    for a in assets:
        for f in (a.get("nuclei") or {}).get("findings", []):
            fr.append([f.get("severity"), a["host"], f.get("template_id"), f.get("name"), f.get("matched_at"),
                       ", ".join(f.get("cve") or [])])
    fr.sort(key=lambda r: SEV.index(r[0]) if r[0] in SEV else 99)
    L += [table(["Severity", "Host", "Template", "Name", "Matched at", "CVE"], fr)]
    ver = next(((a.get("nuclei") or {}).get("templates_version") for a in assets if (a.get("nuclei") or {}).get("templates_version")), None)
    L += [f"Nuclei templates version: {ver or 'n/a'}; severity filter: "
          f"{next(((a.get('nuclei') or {}).get('severity_filter') for a in assets if (a.get('nuclei') or {}).get('severity_filter')), 'n/a')}.", ""]

    L += ["## 6. Scan history (trend)", ""]
    rows = [[r.get("started_at", "")[:19], r.get("scan_id"), r.get("status"), r.get("stage"),
             (r.get("summary") or {}).get("verdict", ""),
             json.dumps(((r.get("summary") or {}).get("stats") or {}).get("nuclei")) if r.get("summary") else ""] for r in runs]
    L += [table(["Started", "Scan", "Status", "Stage", "Verdict", "Nuclei counts"], rows)]

    L += ["## 7. Authorisation & method", "",
          "- Target in the MongoDB `scope` allow-list; scan started only after an explicit `APPROVE <domain>` message.",
          "- Tools: subfinder, assetfinder, (shuffledns), dnsx, httpx, nmap (-sT -sV, targeted ports), nuclei (safe profile).",
          "- CDN edge and non-public IPs were not port-scanned. Absence of findings does not prove absence of risk.", ""]
    return "\n".join(L)


def main():
    ap = argparse.ArgumentParser()
    ap.add_argument("domain")
    ap.add_argument("--from-json")
    a = ap.parse_args()
    d = a.domain.lower().strip()
    if not DOMAIN_RE.match(d):
        sys.exit("invalid domain")
    data = json.load(open(a.from_json)) if a.from_json else fetch(d)
    print(build(d, data))


if __name__ == "__main__":
    main()
