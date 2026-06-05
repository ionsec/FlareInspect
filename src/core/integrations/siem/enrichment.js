/**
 * @fileoverview Join findings to graph nodes + attack paths.
 * @description Phase 2a — every finding shipped to a SIEM should be enriched with
 * (a) the graph node it attaches to, and (b) every attack path it participates in.
 * This module is the *only* place that does that join — the ECS and Splunk shippers
 * both consume its output, so the enrichment is consistent across vendors.
 *
 *   buildEnrichmentIndex(assessment) →
 *     {
 *       graph:        object,
 *       paths:        path[],
 *       nodeByFindingId:  Map<findingId, nodeId>,
 *       pathsByFindingId: Map<findingId, path[]>,
 *       findingsByNodeId: Map<nodeId, finding[]>,
 *     }
 *
 *   enrichFinding(finding, index) →
 *     { ...finding, flareinspect: { nodeId, attackPathIds, attackPaths: [...] } }
 * @module core/integrations/siem/enrichment
 */

'use strict';

const { buildResourceGraph } = require('../../graph/resourceGraph');
const { findAttackPaths }    = require('../../graph/attackPaths');

/**
 * Find the graph node that a finding attaches to.
 *
 * The graph keys are not a simple (type,id) tuple — dns_record nodes are
 * keyed `dns:<zoneId>:<recordId>`, zone nodes are keyed `zone:<id>`, etc.
 * We re-derive the key using the same shape the graph uses.
 *
 * @param {object} graph
 * @param {object} finding
 * @returns {string|null}
 */
function findNodeIdForFinding(graph, finding) {
  if (!finding || !finding.resource) return null;
  const r = finding.resource;
  const byId = new Map();
  for (const n of graph.nodes) byId.set(n.id, n);

  // dns_record: id is `dns:<zoneId>:<recordId>`
  if (r.type === 'dns_record') {
    const zid = r.zoneId;
    const rid = r.id;
    if (zid && rid) {
      const cand = byId.get(`dns:${zid}:${rid}`);
      if (cand) return cand.id;
    }
  }
  // zone: id is `zone:<zoneId>`
  if (r.type === 'zone' && r.id) {
    const cand = byId.get(`zone:${r.id}`);
    if (cand) return cand.id;
  }
  // account: id is `account:<id>`
  if (r.type === 'account' && r.id) {
    const cand = byId.get(`account:${r.id}`);
    if (cand) return cand.id;
  }
  // access_app / access_policy / idp / tunnel / worker / binding / r2_bucket / load_balancer /
  // certificate / origin — try the direct id form first, then fall back to a
  // label/props match.
  const direct = r.id ? byId.get(r.id) : null;
  if (direct && direct.type === r.type) return direct.id;

  // Last-ditch: any node whose props have a `resourceId` matching r.id and type matches
  for (const n of graph.nodes) {
    if (n.type !== r.type) continue;
    if (n.props && n.props.resourceId && n.props.resourceId === r.id) return n.id;
  }
  return null;
}

/**
 * Build an enrichment index from an assessment.
 * Cheap-ish: O(F + N + E + P) where F=findings, N=nodes, E=edges, P=paths.
 * @param {object} assessment
 * @returns {{
 *   graph: object,
 *   paths: Array,
 *   nodeByFindingId: Map<string, string>,
 *   pathsByFindingId: Map<string, Array>,
 *   findingsByNodeId: Map<string, Array>
 * }}
 */
function buildEnrichmentIndex(assessment) {
  const graph = buildResourceGraph(assessment || {});
  const paths = findAttackPaths(graph, assessment || {});

  // Build per-node finding lists
  const findingsByNodeId = new Map();
  const nodeByFindingId  = new Map();
  for (const f of (assessment && assessment.findings) || []) {
    const nodeId = findNodeIdForFinding(graph, f);
    if (!nodeId) continue;
    if (!findingsByNodeId.has(nodeId)) findingsByNodeId.set(nodeId, []);
    findingsByNodeId.get(nodeId).push(f);
    if (f.id) nodeByFindingId.set(f.id, nodeId);
  }

  // Build per-finding attack-path lists
  const pathsByFindingId = new Map();
  for (const p of paths) {
    const relatedCheckIds = new Set(p.relatedCheckIds || []);
    const seen = new Set();
    for (const nid of (p.nodes || [])) {
      const fs = findingsByNodeId.get(nid) || [];
      for (const f of fs) {
        if (!f.id) continue;
        if (relatedCheckIds.size && !relatedCheckIds.has(f.checkId)) continue;
        if (seen.has(f.id)) continue;
        seen.add(f.id);
        if (!pathsByFindingId.has(f.id)) pathsByFindingId.set(f.id, []);
        pathsByFindingId.get(f.id).push(p);
      }
    }
  }

  return { graph, paths, nodeByFindingId, pathsByFindingId, findingsByNodeId };
}

/**
 * Enrich a finding with node + attack-path context.
 * Always returns a *new* object — does not mutate the input.
 * @param {object} finding
 * @param {object} index
 * @returns {object}
 */
function enrichFinding(finding, index) {
  if (!finding) return finding;
  const nodeId = index.nodeByFindingId.get(finding.id) || null;
  const paths  = index.pathsByFindingId.get(finding.id) || [];
  return Object.assign({}, finding, {
    flareinspect: {
      nodeId,
      attackPathIds: paths.map(p => p.id),
      attackPaths:   paths.map(p => ({
        id: p.id, title: p.title, severity: p.severity, hopCount: p.hopCount
      }))
    }
  });
}

/**
 * Enrich every finding in an assessment. Pure — does not mutate.
 * @param {object} assessment
 * @param {object} [index]   pre-built enrichment index (skips rebuild)
 * @returns {{ index: object, findings: Array }}
 */
function enrichAssessment(assessment, index) {
  const idx = index || buildEnrichmentIndex(assessment);
  const findings = ((assessment && assessment.findings) || []).map(f => enrichFinding(f, idx));
  return { index: idx, findings };
}

module.exports = {
  buildEnrichmentIndex,
  enrichFinding,
  enrichAssessment,
  // exported for tests
  _internal: { findNodeIdForFinding }
};
