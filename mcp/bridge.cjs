/**
 * @fileoverview CJS façade for the MCP server's engine seams.
 * @description The MCP server is ESM (.mjs) so it can be invoked via
 * `node mcp/server.mjs` / `flareinspect-mcp` without a build step.
 * Jest's CJS runner can't import .mjs dynamically, so this façade
 * exposes the *same* tool functions via require() for tests.
 *
 * This is the ONLY place that ties MCP tool semantics to engine
 * implementation. Production callers go through mcp/server.mjs;
 * tests go through this façade. No logic is duplicated.
 * @module mcp/bridge
 */

'use strict';

const path = require('path');
const resourceGraphMod  = require(path.join(__dirname, '..', 'src/core/graph/resourceGraph.js'));
const attackPathsMod    = require(path.join(__dirname, '..', 'src/core/graph/attackPaths.js'));
const { buildResourceGraph } = resourceGraphMod;
const { findAttackPaths }    = attackPathsMod;

/* ── Tool: get_attack_paths ───────────────────────────────────────────── */

async function toolGetAttackPaths({ assessment }) {
  const graph = buildResourceGraph(assessment);
  const paths = findAttackPaths(graph, assessment);
  return {
    graph: { nodeCount: graph.nodes.length, edgeCount: graph.edges.length, stats: graph.stats },
    paths
  };
}

/* ── Tool: list_findings ──────────────────────────────────────────────── */

async function toolListFindings({ assessment, severity, status, limit = 100 }) {
  const findings = (assessment && assessment.findings) || [];
  let out = findings;
  if (severity) out = out.filter(f => String(f.severity).toLowerCase() === String(severity).toLowerCase());
  if (status)   out = out.filter(f => String(f.status).toLowerCase() === String(status).toLowerCase());
  return { count: out.length, findings: out.slice(0, limit) };
}

module.exports = {
  toolGetAttackPaths,
  toolListFindings,
};
