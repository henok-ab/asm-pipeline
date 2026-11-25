// Minimal n8n-like runner for the ASM sub-workflows (linear main chains only).
// Code nodes run as-is; Mongo is an in-memory fake; SSH runs the real scanner scripts (with stub tools).
const fs = require('fs');
const { spawnSync } = require('child_process');

const WF_DIR = process.argv[2];
const SCANNER_HOME = process.env.ASM_TEST_HOME || '/tmp/asmtest';
const db = { domains: [], scan_runs: [], scope: [], approvals: [] };

const clone = (x) => JSON.parse(JSON.stringify(x));
const load = (f) => JSON.parse(fs.readFileSync(`${WF_DIR}/${f}`, 'utf8'));

function evalParam(val, ctx) {
  if (typeof val !== 'string' || !val.startsWith('=')) return val;
  const body = val.slice(1);
  return body.replace(/\{\{([\s\S]*?)\}\}/g, (_, expr) => {
    const f = new Function('$json', '$', `return (${expr});`);
    return String(f(ctx.$json, ctx.$));
  });
}

function matches(doc, q) {
  return Object.entries(q).every(([k, v]) => {
    if (v && typeof v === 'object' && '$ne' in v) return doc[k] !== v.$ne;
    return doc[k] === v;
  });
}

function runNode(node, items, outputs, state) {
  const p = node.parameters;
  const $ = (name) => {
    const arr = outputs[name];
    if (!arr) throw new Error(`Node "${name}" has not run`);
    return { first: () => arr[0], all: () => arr, last: () => arr[arr.length - 1], item: arr[0] };
  };
  const ctx = { $json: items[0] ? items[0].json : {}, $ };
  switch (node.type) {
    case 'n8n-nodes-base.executeWorkflowTrigger': return items;
    case 'n8n-nodes-base.code': {
      const fn = new Function('$input', '$', 'Buffer', 'URL', p.jsCode);
      const res = fn({ first: () => items[0], all: () => items }, $, Buffer, URL);
      if (!Array.isArray(res)) throw new Error('Code node must return an array');
      return res;
    }
    case 'n8n-nodes-base.mongoDb': {
      const coll = db[p.collection];
      if (p.operation === 'find') {
        const q = JSON.parse(evalParam(p.query, ctx) || '{}');
        let res = coll.filter((d) => matches(d, q)).map(clone);
        if (p.options.sort) {
          const [[k, dir]] = Object.entries(JSON.parse(p.options.sort));
          res.sort((a, b) => (a[k] > b[k] ? 1 : a[k] < b[k] ? -1 : 0) * dir);
        }
        if (p.options.limit) res = res.slice(0, p.options.limit);
        if (p.options.projection) {
          const keep = new Set(Object.keys(JSON.parse(p.options.projection)).map((k) => k.split('.')[0]));
          res = res.map((d) => Object.fromEntries(Object.entries(d).filter(([k]) => keep.has(k) || k === '_id')));
        }
        if (!res.length && node.alwaysOutputData) return [{ json: {} }];
        return res.map((json) => ({ json }));
      }
      const fields = p.fields.split(',').map((s) => s.trim());
      const pick = (json) => Object.fromEntries(fields.map((f) => [f, json[f] === undefined ? null : clone(json[f])]));
      if (p.operation === 'insert') {
        items.forEach((i) => {
          const doc = pick(i.json);
          if (coll.some((d) => d.scan_id && d.scan_id === doc.scan_id)) throw new Error('E11000 duplicate key');
          coll.push(doc);
        });
        return items;
      }
      if (p.operation === 'update') {
        const key = p.updateKey;
        for (const i of items) {
          const upd = pick(i.json);
          let doc = coll.find((d) => d[key] === i.json[key]);
          if (!doc && p.options.upsert) { doc = { [key]: i.json[key] }; coll.push(doc); }
          if (doc) Object.assign(doc, upd);
        }
        return items.map(() => ({ json: { acknowledged: true } }));
      }
      throw new Error('unsupported mongo op ' + p.operation);
    }
    case 'n8n-nodes-base.ssh': {
      const cmd = evalParam(p.command, ctx).replace(/\/opt\/asm/g, SCANNER_HOME);
      const r = spawnSync('bash', ['-c', cmd], { env: { ...process.env, ASM_HOME: SCANNER_HOME }, encoding: 'utf8', maxBuffer: 64e6 });
      state.sshLog.push(cmd.length > 140 ? cmd.slice(0, 140) + '…' : cmd);
      return [{ json: { code: r.status, stdout: r.stdout, stderr: r.stderr } }];
    }
    case 'n8n-nodes-base.stickyNote': return items;
    default: throw new Error('harness: unsupported node type ' + node.type);
  }
}

function chainOrder(wf) {
  const targets = new Set(Object.values(wf.connections).flatMap((c) => (c.main || []).flat().map((x) => x.node)));
  let cur = wf.nodes.find((n) => !targets.has(n.name) && n.type !== 'n8n-nodes-base.stickyNote').name;
  const order = [];
  while (cur) {
    order.push(cur);
    const nxt = ((wf.connections[cur] || {}).main || [[]])[0][0];
    cur = nxt ? nxt.node : null;
  }
  return order;
}

function runWorkflow(file, input, state) {
  const wf = load(file);
  const byName = Object.fromEntries(wf.nodes.map((n) => [n.name, n]));
  const outputs = {};
  let items = [{ json: input }];
  for (const name of chainOrder(wf)) {
    items = runNode(byName[name], items, outputs, state);
    outputs[name] = items;
  }
  return items[0].json;
}

function tool(file, domain, state) {
  try { return { ok: true, out: runWorkflow(file, { domain }, state) }; }
  catch (e) { return { ok: false, err: e.message.split('\n')[0] }; }
}

// ---- orchestrator front door (interceptor + Record Approval) -------------------
function chat(message, state, sessionId = 'sess-1') {
  const wf = load('00_orchestrator.json');
  const byName = Object.fromEntries(wf.nodes.map((n) => [n.name, n]));
  const outputs = {};
  let items = [{ json: { chatInput: message, sessionId, action: 'sendMessage' } }];
  items = runNode(byName['Approval Interceptor'], items, outputs, state);
  outputs['Approval Interceptor'] = items;
  if (items[0].json.isApproval) runNode(byName['Record Approval'], items, outputs, state);
  return items[0].json;
}

module.exports = { db, tool, chat, runWorkflow };

if (require.main === module) {
  const assert = require('assert');
  const state = { sshLog: [] };
  const show = (t, r) => console.log(`\n### ${t}\n` + JSON.stringify(r, null, 1).slice(0, 1400));
  const C = 'example.com';

  db.scope.push({ domain: C, active: true });

  let r = tool('01_db_query.json', C, state);
  assert(r.ok && r.out.previously_scanned === false); console.log('1. DB query on unseen domain -> previously_scanned=false  OK');

  r = tool('02_discovery.json', C, state);
  assert(!r.ok && /no valid user approval/.test(r.err)); console.log('2. Discovery WITHOUT approval refused  OK ->', r.err);

  r = chat('hello there', state); assert(!r.isApproval && db.approvals.length === 0);
  r = chat('please APPROVE example.com now', state); assert(!r.isApproval && db.approvals.length === 0);
  r = chat('APPROVE evil;rm.com', state); assert(!r.isApproval && db.approvals.length === 0);
  console.log('3. Only the exact phrase counts; chatter / injection creates no approval  OK');

  r = chat('APPROVE other.org', state); assert(r.isApproval && db.approvals.length === 1);
  r = tool('02_discovery.json', 'other.org', state);
  assert(!r.ok && /not in the authorised scope/.test(r.err)); console.log('4. Approved but OUT-OF-SCOPE domain refused  OK ->', r.err.slice(0, 90));

  r = chat('APPROVE EXAMPLE.com', state); assert(r.isApproval && r.approvedDomain === C);
  console.log('5. Approval recorded for example.com (case-insensitive)');

  r = tool('03_fingerprint.json', C, state);
  assert(!r.ok && /no approved, running scan/.test(r.err)); console.log('6. Fingerprint before discovery refused  OK ->', r.err.slice(0, 80));

  r = tool('02_discovery.json', C, state);
  assert(r.ok, r.err); show('discovery result', r.out);
  const afterFirst = db.domains.map((d) => ({ host: d.host, first_seen: d.first_seen }));
  assert(db.approvals.find((a) => a.domain === C).status === 'consumed'); console.log('7. Approval consumed  OK');
  assert(db.scan_runs.length === 1 && db.scan_runs[0].stage === 'discovery_done');

  r = tool('02_discovery.json', C, state);
  assert(!r.ok && /no valid user approval/.test(r.err)); console.log('8. Re-running discovery with consumed approval refused (single use)  OK');

  r = tool('04_vulnerability.json', C, state);
  assert(!r.ok && /stage "discovery_done"/.test(r.err)); console.log('9. Vuln before fingerprint refused  OK ->', r.err.slice(0, 90));

  r = tool('03_fingerprint.json', C, state);
  assert(r.ok, r.err); show('fingerprint result', r.out);

  r = tool('04_vulnerability.json', C, state);
  assert(r.ok, r.err); show('final result', r.out);
  assert(r.out.verdict === 'EXPOSED');
  assert(db.scan_runs[0].status === 'completed');

  // idempotency: a second approved scan must not duplicate hosts or reset first_seen
  const n1 = db.domains.length;
  chat('APPROVE example.com', state);
  await_sleep(1100);
  r = tool('02_discovery.json', C, state); assert(r.ok, r.err);
  assert(db.domains.length === n1, 'host count changed'); 
  assert(r.out.new_assets === 0 && r.out.already_known === n1);
  for (const b of afterFirst) assert(db.domains.find((d) => d.host === b.host).first_seen === b.first_seen, 'first_seen reset');
  assert(db.scan_runs.length === 2);
  console.log(`10. Second scan idempotent: ${n1} hosts before/after, first_seen preserved, new_assets=0  OK`);

  const hostDoc = db.domains.find((d) => d.host === 'api.example.com');
  console.log('\n### Stored document (api.example.com), sections:', Object.keys(hostDoc).join(', '));
  assert(['dns', 'http', 'tls', 'port_scanning', 'nuclei'].every((k) => k in hostDoc));
  assert(!('_is_new' in hostDoc) && !('_unassigned' in hostDoc));
  assert(!db.domains.some((d) => d.host === '__none__'));
  console.log('11. dns/http/tls/port_scanning/nuclei present; no helper fields or sentinels leaked  OK');

  r = tool('01_db_query.json', C, state);
  assert(r.ok && r.out.previously_scanned && r.out.last_scan_time); show('db query after scans', { ...r.out, stored_summary: { verdict: r.out.stored_summary.verdict, stats: r.out.stored_summary.stats } });
  console.log('\nSSH commands issued:\n  ' + state.sshLog.join('\n  '));
  if (process.env.ASM_DUMP) fs.writeFileSync(process.env.ASM_DUMP, JSON.stringify({ assets: db.domains, runs: [...db.scan_runs].sort((a, b) => (a.started_at < b.started_at ? 1 : -1)) }, null, 1));
  console.log('\nALL HARNESS CHECKS PASSED');
}

function await_sleep(ms) { Atomics.wait(new Int32Array(new SharedArrayBuffer(4)), 0, 0, ms); }
