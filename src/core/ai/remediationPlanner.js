/**
 * @fileoverview Remediation Planner
 * @description Wraps an LLM provider to order and annotate a deterministic
 *   remediation plan. CRITICAL SAFETY PROPERTY: the planner can only ever reorder /
 *   annotate items that already exist in the engine's plan. Any checkId the model
 *   returns that is not in the provided item set is dropped — the model cannot widen
 *   the action set. If the provider is disabled or errors, this degrades cleanly to
 *   rules-only ordering.
 * @module core/ai/remediationPlanner
 */

const logger = require('../utils/logger');
const { getProvider } = require('./llmProvider');

function rulesOnlyOrder(items) {
  const sevRank = { critical: 0, high: 1, medium: 2, low: 3, informational: 4 };
  const riskRank = { low: 0, medium: 1, high: 2 };
  return [...items].sort((a, b) =>
    (sevRank[a.severity] ?? 9) - (sevRank[b.severity] ?? 9) ||
    (riskRank[a.risk] ?? 9) - (riskRank[b.risk] ?? 9)
  );
}

/**
 * @param {{provider?: string, model?: string, apiKey?: string}} [opts]
 */
function createPlanner(opts = {}) {
  const provider = getProvider(opts);

  return {
    providerName: provider.name,
    enabled: provider.enabled,

    /**
     * Annotate + reorder items. Returns the same item objects (possibly reordered)
     * with `aiRationale`, `aiRiskNote`, `aiRecommend` attached where the model spoke.
     */
    async annotate(items, manualItems = []) {
      if (!provider.enabled || items.length === 0) {
        return { items: rulesOnlyOrder(items), aiUsed: false, provider: provider.name, notes: null };
      }

      let plan = null;
      try {
        plan = await provider.generatePlan(items, manualItems);
      } catch (err) {
        logger.warn('AI planner request failed; using rules-only ordering', { error: err.message });
        return { items: rulesOnlyOrder(items), aiUsed: false, provider: provider.name, notes: `error: ${err.message}` };
      }

      if (!plan || !Array.isArray(plan.orderedCheckIds)) {
        return { items: rulesOnlyOrder(items), aiUsed: false, provider: provider.name, notes: 'no structured plan returned' };
      }

      const byCheckId = new Map(items.map(i => [i.checkId, i]));

      // Attach annotations — only for checkIds we actually have (drop the rest).
      let droppedAnnotations = 0;
      for (const ann of plan.annotations || []) {
        const item = byCheckId.get(ann.checkId);
        if (!item) { droppedAnnotations++; continue; }
        item.aiRationale = ann.rationale || null;
        item.aiRiskNote = ann.riskNote || null;
        item.aiRecommend = ann.recommend === 'manual' ? 'manual' : 'auto';
      }

      // Reorder per the model, dropping unknown checkIds; append any items the model
      // omitted (so nothing silently disappears) in rules-only order.
      const ordered = [];
      const seen = new Set();
      let droppedOrder = 0;
      for (const checkId of plan.orderedCheckIds) {
        const item = byCheckId.get(checkId);
        if (!item) { droppedOrder++; continue; }
        if (seen.has(checkId)) continue;
        seen.add(checkId);
        ordered.push(item);
      }
      for (const item of rulesOnlyOrder(items)) {
        if (!seen.has(item.checkId)) ordered.push(item);
      }

      if (droppedOrder || droppedAnnotations) {
        logger.warn('AI planner returned unknown checkIds — dropped (catalog is authoritative)', {
          droppedOrder, droppedAnnotations
        });
      }

      return {
        items: ordered,
        aiUsed: true,
        provider: provider.name,
        notes: droppedOrder || droppedAnnotations ? `dropped ${droppedOrder + droppedAnnotations} unknown reference(s)` : null
      };
    }
  };
}

module.exports = { createPlanner, rulesOnlyOrder };
