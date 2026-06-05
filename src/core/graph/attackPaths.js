/**
 * @fileoverview Detect attack paths through the resource graph.
 * @description
 * Rule-based chain detection. Each rule reads the graph and emits 0+ paths
 * with a stable shape:
 *   {
 *     id, title, severity, hopCount,
 *     entryNodeId, targetNodeId,
 *     nodes: [id, ...],  edges: [{from, to, type}],
 *     explanation, relatedCheckIds, remediableCheckIds
 *   }
 *
 * Path severity is the worst of the relevant finding severities on the path.
 * Rules are intentionally *deterministic and ordered* — same input → same
 * path IDs (so the UI can deep-link a path).
 *
 * Adding a new rule:
 *   1. Append a new `detect*` function below.
 *   2. Add it to the `RULES` array with a `kind` string.
 *   3. Add a fixture + assertion in tests/attackPaths.test.js.
 * @module core/graph/attackPaths
 */

'use strict';

const { worstOf, worst } = require('./severity');

/* ── Public API ─────────────────────────────────────────────────────────── */

/**
 * Run all attack-path rules against a resource graph + assessment.
 * @param {{nodes: Array, edges: Array}} graph
 * @param {object} assessment   the original assessment (for findings lookup)
 * @returns {Array} paths (sorted: severity asc → hopCount asc → title asc)
 */
function findAttackPaths(graph, assessment) {
  let g;
  try {
    g = normaliseGraph(graph);
  } catch (err) {
    return [{
      id: 'rule_error:normalise',
      title: 'Graph normalisation failed',
      kind: 'error',
      severity: 'low',
      hopCount: 0,
      entryNodeId: null,
      targetNodeId: null,
      nodes: [],
      edges: [],
      explanation: err.message,
      relatedCheckIds: [],
      remediableCheckIds: []
    }];
  }
  const findings = (assessment && assessment.findings) || [];
  const findingsByNode = indexFindingsByNode(findings, g);

  const all = [];
  for (const rule of RULES) {
    try {
      const emitted = rule.detect(g, findingsByNode);
      for (const path of emitted) {
        // backfill severity from attached findings, just in case the rule guessed
        const pathFindings = collectPathFindings(path, findingsByNode);
        path.severity = worstOf(pathFindings) || path.severity || 'low';
        path.hopCount = path.nodes.length;
        all.push(path);
      }
    } catch (err) {
      // never let a single rule crash the rest
      all.push({
        id: `rule_error:${rule.kind}`,
        title: `Rule error in ${rule.kind}`,
        severity: 'low',
        kind: 'error',
        explanation: err.message,
        nodes: [],
        edges: [],
        relatedCheckIds: [],
        remediableCheckIds: []
      });
    }
  }

  return all.sort(cmpPath);
}

/* ── Rule: exposed origin (un-proxied A/AAAA/CNAME) ────────────────────── */

function detectExposedOrigin(g, fb) {
  const out = [];
  for (const n of g.nodes.values()) {
    if (n.type !== 'dns_record') continue;
    if (n.props?.proxied) continue;
    const t = n.props?.recordType;
    if (t !== 'A' && t !== 'AAAA' && t !== 'CNAME') continue;

    const originEdge = g.outEdges.get(n.id)?.find(e => e.to.startsWith('origin:'));
    if (!originEdge) continue;

    const findings = fb.get(n.id) || [];
    if (!findings.some(f => f.status === 'failed' || f.status === 'warning')) continue;

    out.push({
      id: `exposed_origin:${n.id}`,
      title: `Exposed origin: ${n.props.name} (${t})`,
      kind: 'exposed-origin',
      entryNodeId: 'internet',
      targetNodeId: originEdge.to,
      nodes: ['internet', n.id, originEdge.to],
      edges: [
        { from: 'internet', to: n.id, type: 'contains' },
        { from: n.id, to: originEdge.to, type: 'resolves_to' }
      ],
      explanation: `DNS record ${n.props.name} is unproxied, exposing the origin directly to the Internet and bypassing Cloudflare WAF / DDoS protection.`,
      relatedCheckIds: ['CFL-INSIGHT-005', 'CFL-DNS-001'],
      remediableCheckIds: ['CFL-DNS-001']
    });
  }
  return out;
}

/* ── Rule: weak transport (flexible SSL / low min-TLS) ─────────────────── */

function detectWeakTransport(g, fb) {
  const out = [];
  for (const n of g.nodes.values()) {
    if (n.type !== 'zone') continue;
    const findings = fb.get(n.id) || [];
    const hasFlexible = findings.some(f => /SSL.*flexible/i.test(JSON.stringify(f.evidence || {})) && (f.status === 'failed' || f.status === 'warning'));
    const hasMinTls   = findings.some(f => /min.*tls.*1\.[01]/i.test(JSON.stringify(f.evidence || {})) && (f.status === 'failed' || f.status === 'warning'));
    if (!hasFlexible && !hasMinTls) continue;

    out.push({
      id: `weak_transport:${n.id}`,
      title: `Weak transport on ${n.label}`,
      kind: 'weak-transport',
      entryNodeId: 'internet',
      targetNodeId: n.id,
      nodes: ['internet', n.id],
      edges: [{ from: 'internet', to: n.id, type: 'contains' }],
      explanation: `Zone ${n.label} uses weak transport (flexible SSL or min-TLS < 1.2), allowing on-path attackers to intercept traffic.`,
      relatedCheckIds: ['CFL-SSL-001', 'CFL-SSL-002'],
      remediableCheckIds: ['CFL-SSL-001', 'CFL-SSL-002']
    });
  }
  return out;
}

/* ── Rule: open Access app (no policy) ─────────────────────────────────── */

function detectOpenAccessApp(g, fb) {
  const out = [];
  for (const n of g.nodes.values()) {
    if (n.type !== 'access_app') continue;
    const policies = (g.outEdges.get(n.id) || []).filter(e => e.type === 'protected_by');
    if (policies.length > 0) continue;
    const findings = fb.get(n.id) || [];
    if (!findings.some(f => f.status === 'failed' || f.status === 'warning')) continue;

    out.push({
      id: `open_access_app:${n.id}`,
      title: `Open Access app: ${n.label}`,
      kind: 'open-access-app',
      entryNodeId: 'internet',
      targetNodeId: n.id,
      nodes: ['internet', n.id],
      edges: [{ from: 'internet', to: n.id, type: 'contains' }],
      explanation: `Access app "${n.label}" has no policies attached and is reachable from the Internet.`,
      relatedCheckIds: ['CFL-ZT-007', 'CFL-ZT-008'],
      remediableCheckIds: ['CFL-ZT-007']
    });
  }
  return out;
}

/* ── Rule: tunnel with no Access policy (only as advisory — no check yet) ─ */

function detectTunnelWithoutAccess(g, fb) {
  const out = [];
  for (const t of g.nodes.values()) {
    if (t.type !== 'tunnel') continue;
    // Path is: internet → tunnel → origin (heuristic — no check today)
    out.push({
      id: `tunnel_no_access:${t.id}`,
      title: `Tunnel without Access: ${t.label}`,
      kind: 'tunnel-without-access',
      entryNodeId: 'internet',
      targetNodeId: t.id,
      nodes: ['internet', t.id],
      edges: [{ from: 'internet', to: t.id, type: 'contains' }],
      explanation: `Tunnel "${t.label}" connects an origin to the Cloudflare edge. Consider wrapping its routes in an Access application to enforce identity.`,
      relatedCheckIds: ['CFL-ZT-009'],
      remediableCheckIds: []
    });
  }
  return out;
}

/* ── Rule: plaintext worker secret ─────────────────────────────────────── */

function detectPlaintextSecret(g, fb) {
  const out = [];
  for (const n of g.nodes.values()) {
    if (n.type !== 'binding') continue;
    const findings = fb.get(n.id) || [];
    if (!findings.some(f => f.status === 'failed' || f.status === 'warning')) continue;
    out.push({
      id: `plaintext_secret:${n.id}`,
      title: `Plaintext secret binding: ${n.label}`,
      kind: 'worker-plaintext-secret',
      entryNodeId: 'internet',
      targetNodeId: n.id,
      nodes: ['internet', n.id],
      edges: [{ from: 'internet', to: n.id, type: 'contains' }],
      explanation: `Worker binding "${n.label}" stores a secret in plain text. Anyone with read access to the Worker can extract it.`,
      relatedCheckIds: ['CFL-WORK-002'],
      remediableCheckIds: ['CFL-WORK-002']
    });
  }
  return out;
}

/* ── Rule table ─────────────────────────────────────────────────────────── */

const RULES = [
  { kind: 'exposed-origin',         detect: detectExposedOrigin },
  { kind: 'weak-transport',         detect: detectWeakTransport },
  { kind: 'open-access-app',        detect: detectOpenAccessApp },
  { kind: 'tunnel-without-access',  detect: detectTunnelWithoutAccess },
  { kind: 'worker-plaintext-secret',detect: detectPlaintextSecret },
];

/* ── Helpers ────────────────────────────────────────────────────────────── */

function normaliseGraph(graph) {
  if (!graph || !Array.isArray(graph.nodes) || !Array.isArray(graph.edges)) {
    throw new TypeError('graph must be an object with nodes[] and edges[]');
  }
  const nodes = new Map();
  const outEdges = new Map();
  const inEdges = new Map();
  for (const n of graph.nodes) nodes.set(n.id, n);
  for (const e of graph.edges) {
    if (!outEdges.has(e.from)) outEdges.set(e.from, []);
    if (!inEdges.has(e.to)) inEdges.set(e.to, []);
    outEdges.get(e.from).push(e);
    inEdges.get(e.to).push(e);
  }
  return { nodes, outEdges, inEdges };
}

function indexFindingsByNode(findings, g) {
  const idx = new Map();
  for (const f of findings) {
    const ids = nodesForFinding(f, g);
    for (const id of ids) {
      if (!idx.has(id)) idx.set(id, []);
      idx.get(id).push(f);
    }
  }
  return idx;
}

function nodesForFinding(f, g) {
  const out = [];
  const r = f.resource || {};
  // direct match
  if (r.id) {
    const direct = [
      `account:${r.id}`, `zone:${r.id}`, `dns:${r.zoneId || ''}:${r.id}`,
      `r2:${r.id}`, `binding:${r.kind || ''}:${r.id}`,
      `tunnel:${r.id}`, `lb:${r.id}`, `access_app:${r.id}`
    ];
    for (const id of direct) if (g.nodes.has(id)) out.push(id);
  }
  // fallback: by zoneName / resourceName
  if (r.zoneName) {
    for (const n of g.nodes.values()) {
      if (n.type === 'zone' && (n.id === `zone:${r.id}` || n.label === r.zoneName || n.props?.zoneId === r.id)) {
        out.push(n.id);
      }
    }
  }
  return Array.from(new Set(out));
}

function collectPathFindings(path, fb) {
  const out = [];
  for (const id of path.nodes || []) {
    const fs = fb.get(id) || [];
    for (const f of fs) out.push(f);
  }
  return out;
}

function cmpPath(a, b) {
  const order = ['critical', 'high', 'medium', 'low', 'informational', 'pass'];
  const ai = order.indexOf(a.severity);
  const bi = order.indexOf(b.severity);
  if (ai !== bi) return ai - bi;
  if (a.hopCount !== b.hopCount) return a.hopCount - b.hopCount;
  return String(a.title).localeCompare(String(b.title));
}

module.exports = {
  findAttackPaths,
  RULES: RULES.map(r => r.kind),
  // exported for tests
  _internal: { nodesForFinding, collectPathFindings, cmpPath, normaliseGraph },
};
