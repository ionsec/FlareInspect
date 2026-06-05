/**
 * @fileoverview Build a typed resource graph from a FlareInspect assessment.
 * @description
 * The graph is the single source of truth shared by:
 *   - the Posture map UI (web/public/postureMap.js),
 *   - the SIEM exporters (Phase 2 — to attach attack-path context to findings),
 *   - the MCP server (Phase 4 — `flareinspect_get_attack_paths`).
 *
 * Input shape: the `assessment` object produced by AssessmentService, with the
 * richer `configuration` capture that the foundation phase added. Output shape:
 *   { nodes: Node[], edges: Edge[], stats: {...} }
 *
 * Node types:  internet, identity, account, zone, dns_record, origin,
 *              certificate, access_app, access_policy, idp, tunnel, worker,
 *              binding (kv|d1|queue), r2_bucket, load_balancer
 * Edge types:  contains, resolves_to, exposes, protected_by, routes_to,
 *              authenticates_with, binds, serves
 *
 * The function is pure: same input → same output, no side effects, no I/O.
 * @module core/graph/resourceGraph
 */

'use strict';

const { worstOf } = require('./severity');

/* ── Public API ─────────────────────────────────────────────────────────── */

/**
 * Build a resource graph from an assessment.
 * @param {object} assessment
 * @returns {{nodes: Array, edges: Array, stats: object}}
 */
function buildResourceGraph(assessment) {
  const a = assessment || {};
  const zones = Array.isArray(a.zones) ? a.zones : [];
  const findings = Array.isArray(a.findings) ? a.findings : [];
  const account = a.account || { id: 'account', name: 'Account' };
  const config = a.configuration || {};

  const nodes = [];
  const edges = [];
  const findingsByNodeId = new Map();   // nodeId -> [finding, ...]
  const nodeIndex = new Map();          // id -> node

  const addNode = (n) => {
    if (!n || !n.id) return null;
    if (nodeIndex.has(n.id)) return nodeIndex.get(n.id);
    nodeIndex.set(n.id, n);
    nodes.push(n);
    return n;
  };

  const addEdge = (from, to, type, props = {}) => {
    if (!from || !to || !type) return;
    edges.push({ id: `${from}->${to}#${type}`, from, to, type, props });
  };

  const attachFinding = (nodeId, ...finds) => {
    if (!nodeId) return;
    for (const f of finds) {
      if (!f) continue;
      if (!findingsByNodeId.has(nodeId)) findingsByNodeId.set(nodeId, []);
      findingsByNodeId.get(nodeId).push(f);
    }
  };

  /* ── Internet + Account root ──────────────────────────────────────── */
  const internetId = 'internet';
  addNode({ id: internetId, type: 'internet', label: 'Internet', props: {} });

  const accountId = `account:${account.id || 'unknown'}`;
  addNode({
    id: accountId,
    type: 'account',
    label: account.name || 'Account',
    props: { accountId: account.id, type: account.type }
  });
  addEdge(internetId, accountId, 'contains');
  attachFinding(accountId, ...findingsForResource(findings, 'account', account.id));

  /* ── Per-zone graph ───────────────────────────────────────────────── */
  for (const zone of zones) {
    const zoneId = `zone:${zone.id}`;
    const zoneNode = addNode({
      id: zoneId,
      type: 'zone',
      label: zone.name,
      props: {
        zoneId: zone.id,
        plan: zone.plan || 'Free',
        status: zone.status || null
      }
    });
    addEdge(accountId, zoneId, 'contains');
    attachFinding(zoneId, ...findingsForResource(findings, 'zone', zone.id));
    attachFinding(zoneId, ...findingsForZoneName(findings, zone.name));

    buildZoneContents(zone, config, addNode, addEdge, attachFinding, findings);
  }

  /* ── Account-scoped resources (R2, KV/D1/Queues, tunnels, etc.) ──── */
  buildAccountContents(account, config, addNode, addEdge, attachFinding, findings);

  /* ── Compute node severity from attached findings ─────────────────── */
  for (const n of nodes) {
    const fs = findingsByNodeId.get(n.id) || [];
    n.findingIds = fs.map(f => f.id).filter(Boolean);
    n.findingCount = fs.length;
    n.failedCount = fs.filter(f => f.status === 'failed' || f.status === 'warning').length;
    n.severity = worstOf(fs);
  }

  return {
    nodes,
    edges,
    stats: {
      nodeCount: nodes.length,
      edgeCount: edges.length,
      byNodeType: countBy(nodes, 'type'),
      byEdgeType: countBy(edges, 'type')
    }
  };
}

/* ── Per-zone content builder ──────────────────────────────────────────── */

function buildZoneContents(zone, config, addNode, addEdge, attachFinding, findings) {
  const zoneId = `zone:${zone.id}`;
  const zoneConfig = (config.zones && config.zones[zone.name]) || {};
  const dnsConfig = zoneConfig.dns || (config.dns && config.dns[zone.name]) || {};
  const sslConfig = zoneConfig.ssl || (config.ssl && config.ssl[zone.name]) || {};
  const mtlsConfig = (config.mtls && config.mtls[zone.id]) || {};
  const chConfig = zoneConfig.customHostnames || (config.customHostnames && config.customHostnames[zone.name]) || {};
  const originCerts = (config.originCertificates && config.originCertificates[zone.name]) || [];
  const zarazConfig = zoneConfig.zaraz || (config.zaraz && config.zaraz[zone.id]) || null;
  const workersRoutes = ((config.workers && config.workers.routes) || {})[zone.name] || [];

  /* DNS records ─ derive exposed origins (un-proxied A/AAAA/CNAME) */
  const records = Array.isArray(dnsConfig.records) ? dnsConfig.records : [];
  for (const r of records) {
    const nodeId = `dns:${zone.id}:${r.id || r.name + ':' + r.type}`;
    const node = addNode({
      id: nodeId,
      type: 'dns_record',
      label: `${r.name} · ${r.type}`,
      props: {
        name: r.name,
        recordType: r.type,
        content: r.content,
        proxied: r.proxied === true,
        ttl: r.ttl || null
      }
    });
    if (!node) continue;
    addEdge(zoneId, nodeId, 'contains');
    attachFinding(nodeId, ...findingsForDnsRecord(findings, zone.id, r.id, r.name, r.type));

    if (isOriginRecord(r)) {
      const originId = `origin:${r.content}`;
      addNode({ id: originId, type: 'origin', label: r.content, props: { ip: r.content } });
      addEdge(nodeId, originId, r.proxied ? 'protected_by' : 'resolves_to');
    }
  }

  /* Origin / universal SSL (summary node) */
  if (sslConfig && (sslConfig.universal || sslConfig.full || sslConfig.mode)) {
    const certId = `cert:${zone.id}:universal`;
    addNode({
      id: certId,
      type: 'certificate',
      label: `Universal SSL (${sslConfig.mode || 'unknown'})`,
      props: { kind: 'universal', mode: sslConfig.mode || null, edgeCerts: sslConfig.edgeCerts || null }
    });
    addEdge(zoneId, certId, 'contains');
  }

  /* mTLS certs */
  if (Array.isArray(mtlsConfig.certificates) && mtlsConfig.certificates.length > 0) {
    for (const c of mtlsConfig.certificates) {
      const certId = `cert:${zone.id}:mtls:${c.id || c.name}`;
      addNode({ id: certId, type: 'certificate', label: c.name || c.id || 'mTLS cert', props: c });
      addEdge(zoneId, certId, 'contains');
    }
  }

  /* Origin certificates */
  for (const c of originCerts) {
    const certId = `cert:${zone.id}:origin:${c.id}`;
    addNode({ id: certId, type: 'certificate', label: c.hostnames || c.id || 'Origin cert', props: c });
    addEdge(zoneId, certId, 'contains');
  }

  /* Custom hostnames */
  if (Array.isArray(chConfig.hostnames)) {
    for (const h of chConfig.hostnames) {
      const chId = `dns:${zone.id}:ch:${h.id || h.hostname}`;
      addNode({ id: chId, type: 'dns_record', label: h.hostname, props: h });
      addEdge(zoneId, chId, 'contains');
    }
  }

  /* Workers routes (zone-scoped) */
  for (const route of workersRoutes) {
    const workerId = `worker:${route.script || 'unknown'}`;
    addNode({
      id: workerId,
      type: 'worker',
      label: route.script || 'Worker',
      props: { script: route.script, pattern: route.pattern }
    });
    addEdge(zoneId, workerId, 'routes_to');
  }

  /* Zaraz */
  if (zarazConfig && typeof zarazConfig === 'object' && !zarazConfig.error) {
    const zId = `zaraz:${zone.id}`;
    addNode({ id: zId, type: 'worker', label: 'Zaraz', props: { kind: 'zaraz' } });
    addEdge(zoneId, zId, 'contains');
    attachFinding(zId, ...findingsForResource(findings, 'zone', zone.id, 'zaraz'));
  }
}

/* ── Account-scoped content builder ────────────────────────────────────── */

function buildAccountContents(account, config, addNode, addEdge, attachFinding, findings) {
  const accountId = `account:${account.id || 'unknown'}`;

  /* R2 buckets */
  const r2 = (config.r2 && config.r2[account.id]) || {};
  for (const b of r2.buckets || []) {
    const id = `r2:${b.name}`;
    addNode({ id, type: 'r2_bucket', label: b.name, props: b });
    addEdge(accountId, id, 'contains');
    attachFinding(id, ...findingsForResource(findings, 'r2', b.name, 'r2'));
  }

  /* KV / D1 / Queues (storage inventory) */
  const storage = config.storage || {};
  for (const kind of ['kv', 'd1', 'queues']) {
    for (const item of storage[kind] || []) {
      const id = `binding:${kind}:${item.id || item.name}`;
      addNode({ id, type: 'binding', label: item.name || item.id, props: { ...item, kind } });
      addEdge(accountId, id, 'contains');
    }
  }

  /* Tunnels */
  for (const t of config.tunnels || []) {
    const id = `tunnel:${t.id || t.name}`;
    addNode({ id, type: 'tunnel', label: t.name || t.id, props: t });
    addEdge(accountId, id, 'contains');
  }

  /* Access applications (if captured) */
  for (const app of (config.access && config.access.applications) || []) {
    const id = `access_app:${app.id}`;
    addNode({ id, type: 'access_app', label: app.name || app.id, props: app });
    addEdge(accountId, id, 'contains');
    if (Array.isArray(app.policies)) {
      for (const p of app.policies) {
        const pid = `access_policy:${p.id}`;
        addNode({ id: pid, type: 'access_policy', label: p.name || p.id, props: p });
        addEdge(id, pid, 'protected_by');
      }
    }
  }

  /* Load balancers (account-scoped) */
  for (const lb of config.loadBalancers || []) {
    const id = `lb:${lb.id}`;
    addNode({ id, type: 'load_balancer', label: lb.name || lb.id, props: lb });
    addEdge(accountId, id, 'contains');
    for (const o of lb.defaultPools || []) {
      const oid = `origin:${o}`;
      addNode({ id: oid, type: 'origin', label: o, props: { poolOrigin: o } });
      addEdge(id, oid, 'routes_to');
    }
  }
}

/* ── Helpers ────────────────────────────────────────────────────────────── */

function findingsForResource(findings, resourceType, resourceId, category) {
  return (findings || []).filter(f => {
    if (category && f.category !== category) return false;
    const r = f.resource || {};
    return r.type === resourceType && r.id === resourceId;
  });
}

function findingsForZoneName(findings, zoneName) {
  return (findings || []).filter(f => {
    const r = f.resource || {};
    return r.type === 'zone' && (r.name === zoneName || r.zoneName === zoneName);
  });
}

function findingsForDnsRecord(findings, zoneId, recordId, name, type) {
  return (findings || []).filter(f => {
    const r = f.resource || {};
    return r.type === 'dns_record' && (
      r.zoneId === zoneId ||
      (r.id && recordId && r.id === recordId) ||
      (r.name === name && r.recordType === type)
    );
  });
}

function isOriginRecord(r) {
  if (!r) return false;
  if (r.proxied) return false;            // proxied: Cloudflare in front, not an "exposed origin"
  return r.type === 'A' || r.type === 'AAAA' || r.type === 'CNAME';
}

function countBy(arr, key) {
  const out = {};
  for (const item of arr) {
    const v = item[key];
    out[v] = (out[v] || 0) + 1;
  }
  return out;
}

module.exports = {
  buildResourceGraph,
  // exported for tests
  _internal: { isOriginRecord, countBy },
};
