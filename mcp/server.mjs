#!/usr/bin/env node
/**
 * @fileoverview FlareInspect MCP server.
 * @description Exposes the assessment + remediation + graph engines as MCP tools.
 * The server uses stdio transport for local agents (Claude Code, Cowork,
 * Hermes, OpenClaw, anything MCP-aware) and calls the *existing* engine
 * seams — zero logic duplication.
 *
 * Tools (all read-only by default):
 *   - flareinspect_assess
 *   - flareinspect_list_findings
 *   - flareinspect_get_attack_paths
 *   - flareinspect_plan_remediation
 *   - flareinspect_apply_remediation  (gated by FLAREINSPECT_ALLOW_REMEDIATION
 *                                      + an edit-scope token check)
 *   - flareinspect_rollback
 *
 * Run:
 *   npx -y flareinspect-mcp
 *   node mcp/server.mjs
 *
 * Edit-scope policy (per the plan's self-review delta):
 *   The apply tool refuses to run unless BOTH conditions hold:
 *     1. FLAREINSPECT_ALLOW_REMEDIATION === 'true' (or '1')
 *     2. The supplied token satisfies verifyEditScope(token) — see
 *        src/core/auth/editScope.js for the policy.
 *   The token is passed by the agent in the tool arguments; the agent
 *   must obtain it from the user's secret store. A flat string is also
 *   accepted as `permission:edit` for compatibility.
 *
 * The SDK is loaded lazily so callers without it installed (optionalDep)
 * get a clean error message rather than a stack trace.
 * @module mcp/server
 */

import { createRequire } from 'node:module';
import { pathToFileURL } from 'node:url';
import { dirname, resolve } from 'node:path';
import { fileURLToPath } from 'node:url';

const require = createRequire(import.meta.url);
const here = dirname(fileURLToPath(import.meta.url));
const repoRoot = resolve(here, '..');

// ── Tool implementations (no MCP dependency) ──────────────────────────────
// These are exposed as plain async functions and re-used by the MCP tool
// handlers AND by the test suite (so we can unit-test the engine seams
// without spinning up an MCP transport).

const assessmentServiceMod = require(resolve(repoRoot, 'src/core/services/assessmentService.js'));
const remediationEngineMod = require(resolve(repoRoot, 'src/core/remediation/remediationEngine.js'));
const backupManagerMod     = require(resolve(repoRoot, 'src/core/remediation/backupManager.js'));
const resourceGraphMod     = require(resolve(repoRoot, 'src/core/graph/resourceGraph.js'));
const attackPathsMod       = require(resolve(repoRoot, 'src/core/graph/attackPaths.js'));
const editScopeMod         = require(resolve(repoRoot, 'src/core/auth/editScope.js'));
const assessmentStore      = require(resolve(repoRoot, 'src/core/services/assessmentStore.js'));

const AssessmentService = assessmentServiceMod;
const remediationEngine = remediationEngineMod;
const backupManager     = backupManagerMod;
const buildResourceGraph = resourceGraphMod.buildResourceGraph;
const findAttackPaths   = attackPathsMod.findAttackPaths;
const verifyEditScope   = editScopeMod.verifyEditScope;
const isRemediationEnabled = editScopeMod.isRemediationEnabled;

/* ── Tool: assess ─────────────────────────────────────────────────────── */

export async function toolAssess({ token, zones, concurrency, note, compliance }) {
  // The token is supplied by the caller per request — the server stores nothing.
  if (!token) throw new Error('token is required — pass your Cloudflare API token in the tool call.');
  const svc = new AssessmentService({ useSpinner: false });
  const opts = {};
  if (Array.isArray(zones) && zones.length) opts.zones = zones;
  if (concurrency) opts.concurrency = concurrency;
  if (note) opts.note = note;
  const assessment = await svc.runAssessment({ apiToken: token }, opts);
  if (compliance) {
    const complianceEngine = new (require(resolve(repoRoot, 'src/core/services/complianceEngine.js')))();
    assessment.complianceReport = complianceEngine.getComplianceReport(assessment.findings || []);
  }
  // Persist so the results/reports can be read back by id WITHOUT a token.
  let stored = false;
  try { assessmentStore.persist(assessment); stored = true; } catch (_) { /* non-fatal */ }
  return {
    assessmentId: assessment.assessmentId,
    score: assessment.score && assessment.score.overallScore != null ? assessment.score.overallScore : null,
    grade: (assessment.score && assessment.score.grade) || assessment.grade || null,
    summary: assessment.summary || null,
    findingsCount: (assessment.findings || []).length,
    zones: (assessment.zones || []).map(z => ({ id: z.id, name: z.name })),
    stored,
    hint: 'Use flareinspect_get_assessment / flareinspect_list_findings / flareinspect_get_report with this assessmentId — no token needed to read results.'
  };
}

/* ── Tool: list_findings ──────────────────────────────────────────────── */

export async function toolListFindings({ assessment, assessmentId, severity, status, limit = 100 }) {
  const a = resolveAssessment(assessment, assessmentId);
  const findings = (a && a.findings) || [];
  let out = findings;
  if (severity) out = out.filter(f => String(f.severity).toLowerCase() === String(severity).toLowerCase());
  if (status)   out = out.filter(f => String(f.status).toLowerCase() === String(status).toLowerCase());
  return { assessmentId: a.assessmentId, count: out.length, returned: Math.min(out.length, limit), findings: out.slice(0, limit) };
}

/* ── Tool: get_attack_paths ───────────────────────────────────────────── */

export async function toolGetAttackPaths({ assessment, assessmentId }) {
  const a = resolveAssessment(assessment, assessmentId);
  const graph = buildResourceGraph(a);
  const paths = findAttackPaths(graph, a);
  return {
    assessmentId: a.assessmentId,
    graph: { nodeCount: graph.nodes.length, edgeCount: graph.edges.length, stats: graph.stats },
    paths
  };
}

/* ── Read helpers (no token — stored results only) ────────────────────── */

// Accept an inline assessment object OR load a stored one by id (or latest).
function resolveAssessment(assessment, assessmentId) {
  if (assessment && typeof assessment === 'object') return assessment;
  return assessmentStore.loadById(assessmentId);
}

/* ── Tool: list_assessments ───────────────────────────────────────────── */

export async function toolListAssessments() {
  return { assessments: assessmentStore.list() };
}

/* ── Tool: get_assessment (compact summary by id) ─────────────────────── */

export async function toolGetAssessment({ assessmentId }) {
  const a = assessmentStore.loadById(assessmentId);
  return {
    assessmentId: a.assessmentId,
    account: a.account || null,
    score: a.score || null,
    grade: (a.score && a.score.grade) || a.grade || null,
    summary: a.summary || null,
    zones: (a.zones || []).map(z => ({ id: z.id, name: z.name, plan: z.plan })),
    completedAt: a.completedAt || a.startedAt || null
  };
}

/* ── Tool: get_report (rendered report by id) ─────────────────────────── */

export async function toolGetReport({ assessmentId, format = 'markdown' }) {
  const a = assessmentStore.loadById(assessmentId);
  const fmt = String(format).toLowerCase();
  if (fmt === 'json') return { assessmentId: a.assessmentId, format: 'json', report: a };
  const exporters = {
    html: 'src/exporters/html.js',
    markdown: 'src/exporters/markdown.js',
    md: 'src/exporters/markdown.js',
    sarif: 'src/exporters/sarif.js',
    csv: 'src/exporters/csv.js',
    asff: 'src/exporters/asff.js'
  };
  const modPath = exporters[fmt];
  if (!modPath) throw new Error(`Unknown report format "${format}". Use json|markdown|html|sarif|csv|asff.`);
  const Exporter = require(resolve(repoRoot, modPath));
  const data = await new Exporter().export(a);
  const report = typeof data === 'string' ? data : JSON.stringify(data, null, 2);
  return { assessmentId: a.assessmentId, format: fmt, report };
}

/* ── Tool: plan_remediation ───────────────────────────────────────────── */

export async function toolPlanRemediation({ assessment, checks, zones, excludeZones, concurrency, token }) {
  token = token || process.env.CLOUDFLARE_TOKEN;
  if (!token) throw new Error('token is required to plan remediation (argument or CLOUDFLARE_TOKEN env)');
  const client = new (require(resolve(repoRoot, 'src/core/services/cloudflareClient.js')))(token);
  const opts = { client, checks, zones, excludeZones, concurrency };
  const plan = await remediationEngine.buildPlan(assessment, opts);
  return { plan };
}

/* ── Tool: apply_remediation (gated) ──────────────────────────────────── */

export async function toolApplyRemediation({ assessment, token, checkIds, force, concurrency, backupDir }) {
  if (!isRemediationEnabled()) {
    throw new Error(
      'Remediation is disabled. Set FLAREINSPECT_ALLOW_REMEDIATION=true to enable it.'
    );
  }
  if (!verifyEditScope(token)) {
    throw new Error(
      'Refusing to apply: token does not have edit scope. Re-issue with permission:edit or aud:tag:edit.'
    );
  }
  if (!Array.isArray(checkIds) || checkIds.length === 0) {
    throw new Error('checkIds is required and must be non-empty');
  }
  const client = new (require(resolve(repoRoot, 'src/core/services/cloudflareClient.js')))(token);
  const dir = backupDir || backupManager.defaultBackupDir();
  const plan = await remediationEngine.buildPlan(assessment, { client, checks: checkIds, concurrency });
  const result = await remediationEngine.apply(plan.items, { client, backupDir: dir, assessment, concurrency });
  return { applied: result.applied, results: result.results, backupFile: result.filePath || null };
}

/* ── Tool: rollback ───────────────────────────────────────────────────── */

export async function toolRollback({ bundleFile, token, concurrency }) {
  if (!isRemediationEnabled()) {
    throw new Error('Remediation is disabled. Set FLAREINSPECT_ALLOW_REMEDIATION=true to enable it.');
  }
  if (!verifyEditScope(token)) {
    throw new Error('Refusing to rollback: token does not have edit scope.');
  }
  if (!bundleFile) throw new Error('bundleFile is required');
  const client = new (require(resolve(repoRoot, 'src/core/services/cloudflareClient.js')))(token);
  const result = await remediationEngine.rollback(bundleFile, { client, concurrency });
  return { result };
}

/* ── MCP transport wiring (lazy) ──────────────────────────────────────── */

async function startServer() {
  let sdk;
  try {
    sdk = await import('@modelcontextprotocol/sdk/server/mcp.js');
  } catch (err) {
    process.stderr.write(
      'FATAL: @modelcontextprotocol/sdk is not installed.\n' +
      '       Install it with:  npm install --save-optional @modelcontextprotocol/sdk\n'
    );
    process.exit(1);
  }
  const { McpServer } = sdk;
  const stdio = await import('@modelcontextprotocol/sdk/server/stdio.js');
  const { StdioServerTransport } = stdio;
  const { z } = await import('zod');

  const server = new McpServer(
    { name: 'flareinspect', version: '2.0.0' },
    {
      capabilities: { tools: {} },
      instructions: 'FlareInspect: read-only by default. apply_remediation/rollback require FLAREINSPECT_ALLOW_REMEDIATION + an edit-scope token.'
    }
  );

  // assess
  server.tool(
    'flareinspect_assess',
    'Run a Cloudflare security assessment.',
    {
      token: z.string().min(1),
      zones: z.array(z.string()).optional(),
      concurrency: z.number().int().min(1).max(20).optional(),
      note: z.string().max(2000).optional(),
      compliance: z.string().optional()
    },
    async (args) => {
      try {
        const out = await toolAssess(args);
        return { content: [{ type: 'text', text: JSON.stringify(out, null, 2) }] };
      } catch (e) { return { isError: true, content: [{ type: 'text', text: e.message }] }; }
    }
  );

  // list_findings
  server.tool(
    'flareinspect_list_findings',
    'List findings from a stored assessment (by assessmentId, no token needed) or an inline assessment object.',
    {
      assessmentId: z.string().optional(),
      assessment: z.union([z.string(), z.any()]).optional(),
      severity: z.string().optional(),
      status: z.string().optional(),
      limit: z.number().int().min(1).max(1000).optional()
    },
    async (args) => {
      try {
        const a = typeof args.assessment === 'string' ? JSON.parse(args.assessment) : args.assessment;
        const out = await toolListFindings({ assessment: a, assessmentId: args.assessmentId, severity: args.severity, status: args.status, limit: args.limit });
        return { content: [{ type: 'text', text: JSON.stringify(out, null, 2) }] };
      } catch (e) { return { isError: true, content: [{ type: 'text', text: e.message }] }; }
    }
  );

  // get_attack_paths
  server.tool(
    'flareinspect_get_attack_paths',
    'Compute the resource graph + ranked attack paths for a stored assessment (by assessmentId, no token) or an inline assessment object.',
    {
      assessmentId: z.string().optional(),
      assessment: z.union([z.string(), z.any()]).optional()
    },
    async (args) => {
      try {
        const a = typeof args.assessment === 'string' ? JSON.parse(args.assessment) : args.assessment;
        const out = await toolGetAttackPaths({ assessment: a, assessmentId: args.assessmentId });
        return { content: [{ type: 'text', text: JSON.stringify(out, null, 2) }] };
      } catch (e) { return { isError: true, content: [{ type: 'text', text: e.message }] }; }
    }
  );

  // list_assessments (no token — stored results)
  server.tool(
    'flareinspect_list_assessments',
    'List saved assessments (id, account, score, grade, findings, date). No token required.',
    {},
    async () => {
      try {
        const out = await toolListAssessments();
        return { content: [{ type: 'text', text: JSON.stringify(out, null, 2) }] };
      } catch (e) { return { isError: true, content: [{ type: 'text', text: e.message }] }; }
    }
  );

  // get_assessment (no token — compact summary by id)
  server.tool(
    'flareinspect_get_assessment',
    'Read back a stored assessment summary (score, grade, severity counts, zones) by assessmentId. Omit id for the latest. No token required.',
    {
      assessmentId: z.string().optional()
    },
    async (args) => {
      try {
        const out = await toolGetAssessment({ assessmentId: args.assessmentId });
        return { content: [{ type: 'text', text: JSON.stringify(out, null, 2) }] };
      } catch (e) { return { isError: true, content: [{ type: 'text', text: e.message }] }; }
    }
  );

  // get_report (no token — rendered report by id)
  server.tool(
    'flareinspect_get_report',
    'Render a stored assessment as a report. format: json|markdown|html|sarif|csv|asff. Omit id for the latest. No token required.',
    {
      assessmentId: z.string().optional(),
      format: z.enum(['json', 'markdown', 'md', 'html', 'sarif', 'csv', 'asff']).optional()
    },
    async (args) => {
      try {
        const out = await toolGetReport({ assessmentId: args.assessmentId, format: args.format });
        return { content: [{ type: 'text', text: typeof out.report === 'string' ? out.report : JSON.stringify(out.report, null, 2) }] };
      } catch (e) { return { isError: true, content: [{ type: 'text', text: e.message }] }; }
    }
  );

  // plan_remediation
  server.tool(
    'flareinspect_plan_remediation',
    'Build a remediation plan (dry-run). No mutations; no edit scope required.',
    {
      assessment: z.union([z.string(), z.any()]),
      token: z.string().min(1),
      checks: z.array(z.string()).optional(),
      zones: z.array(z.string()).optional(),
      excludeZones: z.array(z.string()).optional(),
      concurrency: z.number().int().min(1).max(20).optional()
    },
    async (args) => {
      try {
        const a = typeof args.assessment === 'string' ? JSON.parse(args.assessment) : args.assessment;
        const out = await toolPlanRemediation({ assessment: a, token: args.token, checks: args.checks, zones: args.zones, excludeZones: args.excludeZones, concurrency: args.concurrency });
        return { content: [{ type: 'text', text: JSON.stringify(out, null, 2) }] };
      } catch (e) { return { isError: true, content: [{ type: 'text', text: e.message }] }; }
    }
  );

  // apply_remediation
  server.tool(
    'flareinspect_apply_remediation',
    'Apply a remediation plan. Gated by FLAREINSPECT_ALLOW_REMEDIATION + an edit-scope token.',
    {
      assessment: z.union([z.string(), z.any()]),
      token: z.string().min(1),
      checkIds: z.array(z.string()).min(1),
      force: z.boolean().optional(),
      concurrency: z.number().int().min(1).max(20).optional(),
      backupDir: z.string().optional()
    },
    async (args) => {
      try {
        const a = typeof args.assessment === 'string' ? JSON.parse(args.assessment) : args.assessment;
        const out = await toolApplyRemediation({ assessment: a, token: args.token, checkIds: args.checkIds, force: args.force, concurrency: args.concurrency, backupDir: args.backupDir });
        return { content: [{ type: 'text', text: JSON.stringify(out, null, 2) }] };
      } catch (e) { return { isError: true, content: [{ type: 'text', text: e.message }] }; }
    }
  );

  // rollback
  server.tool(
    'flareinspect_rollback',
    'Roll back a previously applied remediation bundle. Gated by FLAREINSPECT_ALLOW_REMEDIATION + edit-scope token.',
    {
      bundleFile: z.string().min(1),
      token: z.string().min(1),
      concurrency: z.number().int().min(1).max(20).optional()
    },
    async (args) => {
      try {
        const out = await toolRollback(args);
        return { content: [{ type: 'text', text: JSON.stringify(out, null, 2) }] };
      } catch (e) { return { isError: true, content: [{ type: 'text', text: e.message }] }; }
    }
  );

  const transport = new StdioServerTransport();
  await server.connect(transport);
}

// ── Entrypoint ──────────────────────────────────────────────────────────
const isMain = (() => {
  try {
    const thisFile = fileURLToPath(import.meta.url);
    const argv1 = process.argv[1] && pathToFileURL(process.argv[1]).href;
    return argv1 === pathToFileURL(thisFile).href;
  } catch (_) { return false; }
})();

if (isMain) {
  startServer().catch((err) => {
    process.stderr.write(`FATAL: ${err.stack || err.message}\n`);
    process.exit(1);
  });
}
