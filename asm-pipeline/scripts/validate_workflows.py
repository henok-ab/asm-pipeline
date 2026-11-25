#!/usr/bin/env python3
"""Static checks for workflows/*.json (run before importing into n8n).

* JSON parses; node names unique; every connection endpoint exists
* sub-workflow IDs referenced by tool nodes exist among the shipped workflows
* credential IDs used by nodes match scripts/make_credentials.py
* every Code node is syntactically valid JavaScript (needs `node` on PATH; skipped otherwise)
"""
import glob
import json
import os
import re
import shutil
import subprocess
import sys
import tempfile

ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
errors = []


def err(msg):
    errors.append(msg)
    print("  FAIL:", msg)


files = sorted(glob.glob(os.path.join(ROOT, "workflows", "*.json")))
wfs = {}
for f in files:
    try:
        wfs[os.path.basename(f)] = json.load(open(f))
    except ValueError as e:
        err(f"{f}: invalid JSON ({e})")

ids = {w["id"] for w in wfs.values()}
cred_src = open(os.path.join(ROOT, "scripts", "make_credentials.py")).read()
known_cred_ids = set(re.findall(r'"(asm[A-Za-z0-9]{13})"', cred_src))
node_bin = shutil.which("node")
n_code = 0

for fn, w in wfs.items():
    print(f"[{fn}] {w['name']}  ({len(w['nodes'])} nodes)")
    names = [n["name"] for n in w["nodes"]]
    if len(names) != len(set(names)):
        err(f"{fn}: duplicate node names")
    nameset = set(names)
    for src, kinds in w["connections"].items():
        if src not in nameset:
            err(f"{fn}: connection from unknown node '{src}'")
        for kind, outs in kinds.items():
            for lst in outs:
                for c in lst:
                    if c["node"] not in nameset:
                        err(f"{fn}: connection '{src}' -> unknown node '{c['node']}'")
    for n in w["nodes"]:
        for cname, c in (n.get("credentials") or {}).items():
            if c["id"] not in known_cred_ids:
                err(f"{fn}: node '{n['name']}' credential id {c['id']} not defined in make_credentials.py")
        if n["type"].endswith("toolWorkflow"):
            target = n["parameters"]["workflowId"]["value"]
            if target not in ids:
                err(f"{fn}: tool '{n['name']}' points to missing workflow id {target}")
        if n["type"] == "n8n-nodes-base.code":
            n_code += 1
            if node_bin:
                with tempfile.NamedTemporaryFile("w", suffix=".js", delete=False) as t:
                    t.write("(function(){\n" + n["parameters"]["jsCode"] + "\n})")
                r = subprocess.run([node_bin, "--check", t.name], capture_output=True, text=True)
                os.unlink(t.name)
                if r.returncode:
                    err(f"{fn}: Code node '{n['name']}' syntax error: {r.stderr.strip().splitlines()[0:3]}")

# every tool-called sub-workflow must have an Execute Workflow Trigger with a 'domain' input
for fn, w in wfs.items():
    if w["id"] == "asmOrchestrator1":
        continue
    trig = [n for n in w["nodes"] if n["type"] == "n8n-nodes-base.executeWorkflowTrigger"]
    if len(trig) != 1:
        err(f"{fn}: expected exactly one Execute Workflow Trigger")
    elif "domain" not in [v["name"] for v in trig[0]["parameters"]["workflowInputs"]["values"]]:
        err(f"{fn}: trigger lacks 'domain' input")

print(f"checked {len(wfs)} workflows, {n_code} Code nodes" + ("" if node_bin else " (node not found: JS syntax check skipped)"))
if errors:
    print(f"{len(errors)} problem(s)")
    sys.exit(1)
print("workflow static validation: OK")
