#!/usr/bin/env python3
"""Normalisation helpers for the ASM scanner scripts (Python 3 stdlib only).

Sub-commands (all read/write files inside a per-run work directory):
  resolved  WORK                    -> WORK/resolved.txt (hosts with A/AAAA)
  discover  WORK --domain ...       -> prints discovery JSON on stdout
  fp-plan   WORK --skip-cdn 1|0     -> WORK/nmap_targets.txt + WORK/ip_meta.json
  fp-final  WORK ...                -> prints fingerprint JSON on stdout
  vuln      WORK ...                -> prints nuclei JSON on stdout

Every command that prints JSON prints exactly one line.
"""
import argparse
import datetime as dt
import ipaddress
import json
import os
import sys
import xml.etree.ElementTree as ET
from urllib.parse import urlparse

WEB_PORTS_NOT_INTERESTING = {80, 443}


# ------------------------------------------------------------------ helpers
def utcnow():
    return dt.datetime.now(dt.timezone.utc)


def iso(d):
    return d.strftime("%Y-%m-%dT%H:%M:%SZ")


def read_lines(path):
    try:
        with open(path, encoding="utf-8", errors="replace") as f:
            return [ln.strip() for ln in f if ln.strip()]
    except FileNotFoundError:
        return []


def read_jsonl(path):
    rows = []
    for ln in read_lines(path):
        if ln.startswith("{"):
            try:
                rows.append(json.loads(ln))
            except ValueError:
                continue
    return rows


def as_list(v):
    if v is None:
        return []
    if isinstance(v, (list, tuple)):
        return [x for x in v if x is not None]
    return [v]


def to_int(v):
    try:
        return int(str(v))
    except (TypeError, ValueError):
        return None


def host_of(row):
    h = (row.get("input") or row.get("host") or "").lower()
    h = h.split("://")[-1].split("/")[0]
    if h.count(":") == 1:  # host:port (ignore bare IPv6)
        h = h.split(":")[0]
    return h


def emit(obj):
    sys.stdout.write(json.dumps(obj, separators=(",", ":"), ensure_ascii=False) + "\n")


def uniq(seq):
    seen, out = set(), []
    for x in seq:
        if x not in seen:
            seen.add(x)
            out.append(x)
    return out


# ------------------------------------------------------------------ resolved
def cmd_resolved(a):
    hosts = set()
    for r in read_jsonl(f"{a.workdir}/dnsx.jsonl"):
        if (r.get("a") or r.get("aaaa")) and r.get("host"):
            hosts.add(r["host"].lower())
    with open(f"{a.workdir}/resolved.txt", "w") as f:
        f.write("".join(h + "\n" for h in sorted(hosts)))


# ------------------------------------------------------------------ discover
def cmd_discover(a):
    w = a.workdir
    subs = uniq(read_lines(f"{w}/all.txt"))
    dns = {}
    for r in read_jsonl(f"{w}/dnsx.jsonl"):
        h = (r.get("host") or "").lower()
        if not h:
            continue
        d = dns.setdefault(h, {"host": h, "a": [], "aaaa": [], "cname": [], "rcode": ""})
        for k in ("a", "aaaa", "cname"):
            for v in as_list(r.get(k)):
                if v not in d[k]:
                    d[k].append(v)
        d["rcode"] = r.get("status_code") or d["rcode"]

    live = {}
    for r in read_jsonl(f"{w}/httpx.jsonl"):
        h = host_of(r)
        if not h:
            continue
        svcs = live.setdefault(h, [])
        url = r.get("url")
        if url and all(s["url"] != url for s in svcs):
            svcs.append({
                "url": url,
                "scheme": r.get("scheme"),
                "port": to_int(r.get("port")),
                "status_code": r.get("status_code"),
                "title": r.get("title") or "",
                "webserver": r.get("webserver") or "",
            })

    tools = {
        "subfinder": len(read_lines(f"{w}/subfinder.txt")),
        "assetfinder": len(read_lines(f"{w}/assetfinder.txt")),
        "shuffledns": len(read_lines(f"{w}/shuffledns.txt")),
    }
    emit({
        "domain": a.domain,
        "started_at": a.started,
        "finished_at": a.finished,
        "bruteforce": a.bruteforce == "1",
        "tools": tools,
        "subdomains": subs,
        "dns": list(dns.values()),
        "live": [{"host": h, "services": s} for h, s in live.items() if s],
        "warnings": read_lines(f"{w}/warnings.txt"),
    })


# ------------------------------------------------------------------ fingerprint
def ipv4(s):
    try:
        ip = ipaddress.ip_address(str(s))
    except ValueError:
        return None
    return ip if ip.version == 4 else None


def cmd_fp_plan(a):
    w = a.workdir
    ip_hosts, ip_cdn = {}, {}
    for r in read_jsonl(f"{w}/httpx.jsonl"):
        h = host_of(r)
        cdn = bool(r.get("cdn"))
        for s in as_list(r.get("a")):
            ip = ipv4(s)
            if not ip:
                continue
            k = str(ip)
            ip_hosts.setdefault(k, set()).add(h)
            ip_cdn[k] = ip_cdn.get(k, False) or cdn
    meta, targets = {}, []
    for ip, hosts in sorted(ip_hosts.items()):
        reason = None
        if not ipaddress.ip_address(ip).is_global:
            reason = "non_public_ip"
        elif ip_cdn[ip] and a.skip_cdn == "1":
            reason = "cdn_edge"
        meta[ip] = {"hosts": sorted(hosts), "cdn": ip_cdn[ip], "skip_reason": reason}
        if reason is None:
            targets.append(ip)
    with open(f"{w}/nmap_targets.txt", "w") as f:
        f.write("".join(t + "\n" for t in targets))
    with open(f"{w}/ip_meta.json", "w") as f:
        json.dump(meta, f)


def parse_nmap(path):
    """Return {ip: [open port dicts]} for every host present in the XML."""
    res = {}
    try:
        root = ET.parse(path).getroot()
    except (ET.ParseError, FileNotFoundError, OSError):
        return res
    for h in root.findall("host"):
        addr = None
        for ad in h.findall("address"):
            if ad.get("addrtype") == "ipv4":
                addr = ad.get("addr")
        if not addr:
            continue
        ports = []
        for p in h.findall("./ports/port"):
            st = p.find("state")
            if st is None or st.get("state") != "open":
                continue
            sv = p.find("service")
            ports.append({
                "port": to_int(p.get("portid")),
                "protocol": p.get("protocol"),
                "service": sv.get("name") if sv is not None else None,
                "product": sv.get("product") if sv is not None else None,
                "version": sv.get("version") if sv is not None else None,
                "extrainfo": sv.get("extrainfo") if sv is not None else None,
                "tunnel": sv.get("tunnel") if sv is not None else None,
                "cpe": [c.text for c in sv.findall("cpe")] if sv is not None else [],
            })
        res[addr] = sorted(ports, key=lambda x: x["port"] or 0)
    return res


def parse_ts(s):
    if not s:
        return None
    try:
        d = dt.datetime.fromisoformat(str(s).replace("Z", "+00:00"))
    except ValueError:
        return None
    return d if d.tzinfo else d.replace(tzinfo=dt.timezone.utc)


def norm_tls(t, port):
    na = parse_ts(t.get("not_after"))
    expired = t.get("expired")
    days = None
    if na:
        days = int((na - utcnow()).total_seconds() // 86400)
        if expired is None:
            expired = days < 0
    fp = t.get("fingerprint_hash")
    return {
        "port": port,
        "version": t.get("tls_version") or t.get("version"),
        "cipher": t.get("cipher"),
        "subject_cn": t.get("subject_cn"),
        "subject_an": as_list(t.get("subject_an")),
        "issuer_cn": t.get("issuer_cn"),
        "issuer_org": as_list(t.get("issuer_org")),
        "not_before": t.get("not_before"),
        "not_after": t.get("not_after"),
        "days_to_expiry": days,
        "expired": bool(expired),
        "self_signed": bool(t.get("self_signed")),
        "mismatched": bool(t.get("mismatched")),
        "untrusted": bool(t.get("untrusted")),
        "wildcard": bool(t.get("wildcard_certificate")),
        "sha256": fp.get("sha256") if isinstance(fp, dict) else None,
    }


def cmd_fp_final(a):
    w = a.workdir
    try:
        with open(f"{w}/ip_meta.json") as f:
            meta = json.load(f)
    except (FileNotFoundError, ValueError):
        meta = {}
    targets = set(read_lines(f"{w}/nmap_targets.txt"))
    nmap = parse_nmap(f"{w}/nmap.xml")

    hosts = {}
    for r in read_jsonl(f"{w}/httpx.jsonl"):
        h = host_of(r)
        if not h:
            continue
        H = hosts.setdefault(h, {"host": h, "http_services": [], "tls_certificates": [], "ips": []})
        url = r.get("url")
        if url and all(s["url"] != url for s in H["http_services"]):
            H["http_services"].append({
                "url": url,
                "final_url": r.get("final_url"),
                "scheme": r.get("scheme"),
                "port": to_int(r.get("port")),
                "status_code": r.get("status_code"),
                "title": r.get("title") or "",
                "webserver": r.get("webserver") or "",
                "tech": as_list(r.get("tech")),
                "content_type": r.get("content_type"),
                "content_length": r.get("content_length"),
                "cdn": bool(r.get("cdn")),
                "cdn_name": r.get("cdn_name"),
            })
        tls = r.get("tls")
        if isinstance(tls, dict) and tls:
            cert = norm_tls(tls, to_int(r.get("port")))
            key = (cert["port"], cert["sha256"] or (cert["subject_cn"], cert["not_after"]))
            if all((c["port"], c["sha256"] or (c["subject_cn"], c["not_after"])) != key
                   for c in H["tls_certificates"]):
                H["tls_certificates"].append(cert)
        for s in as_list(r.get("a")):
            if ipv4(s) and str(ipv4(s)) not in H["ips"]:
                H["ips"].append(str(ipv4(s)))

    out_hosts = []
    for h, H in sorted(hosts.items()):
        ips = []
        for ip in sorted(H["ips"]):
            m = meta.get(ip, {})
            reason = m.get("skip_reason")
            scanned = False
            if reason is None and ip in targets:
                if ip in nmap:
                    scanned = True
                else:
                    reason = "no_nmap_result"
            ips.append({
                "ip": ip,
                "cdn": bool(m.get("cdn")),
                "scanned": scanned,
                "skip_reason": reason,
                "open_ports": nmap.get(ip, []) if scanned else [],
            })
        out_hosts.append({
            "host": h,
            "http_services": H["http_services"],
            "tls_certificates": H["tls_certificates"],
            "ips": ips,
        })

    skipped = {ip: m["skip_reason"] for ip, m in meta.items() if m.get("skip_reason")}
    emit({
        "started_at": a.started,
        "finished_at": a.finished,
        "hosts": out_hosts,
        "nmap": {
            "ports_profile": a.ports,
            "targets": sorted(targets),
            "scanned": sorted(nmap.keys()),
            "skipped": skipped,
        },
        "warnings": read_lines(f"{w}/warnings.txt"),
    })


# ------------------------------------------------------------------ nuclei
KNOWN_SEV = {"critical", "high", "medium", "low", "info", "unknown"}


def finding_host(matched, fallback):
    matched = matched or fallback or ""
    if not matched:
        return ""
    p = urlparse(matched if "://" in matched else "//" + matched)
    return (p.hostname or "").lower()


def cmd_vuln(a):
    w = a.workdir
    findings, seen = [], set()
    for r in read_jsonl(f"{w}/nuclei.jsonl"):
        info = r.get("info") or {}
        matched = r.get("matched-at") or r.get("host") or ""
        key = (r.get("template-id"), matched, r.get("matcher-name"))
        if key in seen:
            continue
        seen.add(key)
        sev = str(info.get("severity") or "unknown").lower()
        tags = info.get("tags")
        if isinstance(tags, str):
            tags = [t.strip() for t in tags.split(",") if t.strip()]
        cls = info.get("classification") or {}
        refs = info.get("reference")
        if isinstance(refs, str):
            refs = [refs]
        findings.append({
            "template_id": r.get("template-id"),
            "name": info.get("name"),
            "severity": sev if sev in KNOWN_SEV else "unknown",
            "type": r.get("type"),
            "host": finding_host(matched, r.get("host")),
            "matched_at": matched,
            "matcher_name": r.get("matcher-name"),
            "tags": as_list(tags),
            "description": (info.get("description") or "")[:400],
            "reference": as_list(refs)[:5],
            "cve": as_list(cls.get("cve-id")),
            "cvss_score": cls.get("cvss-score"),
            "extracted_results": as_list(r.get("extracted-results"))[:5],
            "timestamp": r.get("timestamp"),
        })
    emit({
        "started_at": a.started,
        "finished_at": a.finished,
        "scanned_urls": len(read_lines(f"{w}/targets.txt")),
        "templates_version": a.templates_version or None,
        "severity_filter": a.severity,
        "findings": findings,
        "warnings": read_lines(f"{w}/warnings.txt"),
    })


# ------------------------------------------------------------------ CLI
def main():
    ap = argparse.ArgumentParser()
    sub = ap.add_subparsers(dest="cmd", required=True)

    p = sub.add_parser("resolved"); p.add_argument("workdir"); p.set_defaults(fn=cmd_resolved)

    p = sub.add_parser("discover"); p.add_argument("workdir")
    p.add_argument("--domain", required=True); p.add_argument("--started", required=True)
    p.add_argument("--finished", required=True); p.add_argument("--bruteforce", default="0")
    p.set_defaults(fn=cmd_discover)

    p = sub.add_parser("fp-plan"); p.add_argument("workdir"); p.add_argument("--skip-cdn", default="1")
    p.set_defaults(fn=cmd_fp_plan)

    p = sub.add_parser("fp-final"); p.add_argument("workdir")
    p.add_argument("--started", required=True); p.add_argument("--finished", required=True)
    p.add_argument("--ports", default="")
    p.set_defaults(fn=cmd_fp_final)

    p = sub.add_parser("vuln"); p.add_argument("workdir")
    p.add_argument("--started", required=True); p.add_argument("--finished", required=True)
    p.add_argument("--severity", default=""); p.add_argument("--templates-version", default="")
    p.set_defaults(fn=cmd_vuln)

    args = ap.parse_args()
    args.fn(args)


if __name__ == "__main__":
    main()
