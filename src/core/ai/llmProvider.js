/**
 * @fileoverview LLM Provider (provider-configurable)
 * @description A thin, optional abstraction over an LLM used ONLY to order and
 *   annotate a pre-computed, deterministic remediation plan. Providers are loaded
 *   lazily so their SDKs remain optional dependencies; if a provider/SDK/key is
 *   unavailable the provider reports `enabled: false` and the engine falls back to
 *   rules-only ordering. The LLM is never on the critical safety path.
 * @module core/ai/llmProvider
 */

const logger = require('../utils/logger');

const PLAN_TOOL = {
  name: 'submit_remediation_plan',
  description: 'Return an ordered, annotated remediation plan. You may only reference the checkIds provided to you; never invent new ones.',
  input_schema: {
    type: 'object',
    properties: {
      orderedCheckIds: {
        type: 'array',
        items: { type: 'string' },
        description: 'The provided checkIds in the recommended application order (safest / highest-value first).'
      },
      annotations: {
        type: 'array',
        items: {
          type: 'object',
          properties: {
            checkId: { type: 'string' },
            rationale: { type: 'string', description: 'One sentence: why this change matters.' },
            riskNote: { type: 'string', description: 'One sentence: operational risk / blast radius.' },
            recommend: { type: 'string', enum: ['auto', 'manual'], description: 'Whether to auto-apply or review manually.' }
          },
          required: ['checkId', 'recommend']
        }
      }
    },
    required: ['orderedCheckIds', 'annotations']
  }
};

const SYSTEM_PROMPT =
  'You are a Cloudflare security remediation planner. You are given a list of proposed, ' +
  'already-validated configuration changes (each identified by a checkId, with its severity, ' +
  'operational risk, target setting, and current vs proposed value). Your ONLY job is to (1) order ' +
  'them safest-and-highest-value-first and (2) annotate each with a short rationale, a risk note, ' +
  'and whether it should be auto-applied or reviewed manually. You MUST NOT invent checkIds, ' +
  'endpoints, or values — only use the checkIds provided. High operational-risk changes should be ' +
  'recommended "manual".';

function buildUserPayload(items, manualItems) {
  return JSON.stringify({
    proposedChanges: items.map(i => ({
      checkId: i.checkId,
      title: i.title,
      severity: i.severity,
      operationalRisk: i.risk,
      setting: i.setting,
      resource: i.resourceName,
      current: i.valueBefore,
      proposed: i.valueProposed
    })),
    manualOnlyFindings: manualItems.map(m => ({ checkId: m.checkId, severity: m.severity, title: m.checkTitle }))
  }, null, 2);
}

/** Lazy, soft require — returns null if the module isn't installed. */
function softRequire(name) {
  try {
    return require(name);
  } catch {
    return null;
  }
}

function createAnthropicProvider({ model, apiKey }) {
  const key = apiKey || process.env.ANTHROPIC_API_KEY;
  const Anthropic = softRequire('@anthropic-ai/sdk');
  const enabled = !!(key && Anthropic);
  return {
    name: 'anthropic',
    enabled,
    async generatePlan(items, manualItems) {
      if (!enabled) return null;
      const client = new Anthropic({ apiKey: key });
      const resp = await client.messages.create({
        model: model || 'claude-opus-4-8',
        max_tokens: 2048,
        system: SYSTEM_PROMPT,
        tools: [PLAN_TOOL],
        tool_choice: { type: 'tool', name: PLAN_TOOL.name },
        messages: [{ role: 'user', content: buildUserPayload(items, manualItems) }]
      });
      const toolUse = (resp.content || []).find(c => c.type === 'tool_use' && c.name === PLAN_TOOL.name);
      return toolUse ? toolUse.input : null;
    }
  };
}

function createOpenAIProvider({ model, apiKey }) {
  const key = apiKey || process.env.OPENAI_API_KEY;
  const OpenAI = softRequire('openai');
  const enabled = !!(key && OpenAI);
  return {
    name: 'openai',
    enabled,
    async generatePlan(items, manualItems) {
      if (!enabled) return null;
      const client = new OpenAI({ apiKey: key });
      const resp = await client.chat.completions.create({
        model: model || 'gpt-4o',
        messages: [
          { role: 'system', content: SYSTEM_PROMPT },
          { role: 'user', content: buildUserPayload(items, manualItems) }
        ],
        tools: [{ type: 'function', function: { name: PLAN_TOOL.name, description: PLAN_TOOL.description, parameters: PLAN_TOOL.input_schema } }],
        tool_choice: { type: 'function', function: { name: PLAN_TOOL.name } }
      });
      const call = resp.choices?.[0]?.message?.tool_calls?.[0];
      if (!call) return null;
      try {
        return JSON.parse(call.function.arguments);
      } catch {
        return null;
      }
    }
  };
}

/**
 * Local model via Ollama (or any OpenAI-compatible local server). No API key and no
 * SDK required — talks to the OpenAI-compatible /v1/chat/completions endpoint with
 * plain fetch, so it runs fully offline. If the local server is down, generatePlan
 * throws and the planner degrades to rules-only ordering.
 */
function createOllamaProvider({ model, baseUrl }) {
  const raw = (baseUrl || process.env.OLLAMA_HOST || 'http://localhost:11434').replace(/\/+$/, '');
  const apiBase = raw.endsWith('/v1') ? raw : `${raw}/v1`;
  return {
    name: 'ollama',
    enabled: true, // assume a local server; failures fall back to rules-only
    async generatePlan(items, manualItems) {
      const resp = await fetch(`${apiBase}/chat/completions`, {
        method: 'POST',
        headers: { 'Content-Type': 'application/json' },
        body: JSON.stringify({
          model: model || 'llama3.1',
          stream: false,
          messages: [
            { role: 'system', content: SYSTEM_PROMPT },
            { role: 'user', content: buildUserPayload(items, manualItems) }
          ],
          tools: [{ type: 'function', function: { name: PLAN_TOOL.name, description: PLAN_TOOL.description, parameters: PLAN_TOOL.input_schema } }],
          tool_choice: { type: 'function', function: { name: PLAN_TOOL.name } }
        })
      });
      if (!resp.ok) throw new Error(`Ollama request failed (${resp.status})`);
      const data = await resp.json();
      const call = data.choices?.[0]?.message?.tool_calls?.[0];
      if (!call) return null;
      try {
        return typeof call.function.arguments === 'string'
          ? JSON.parse(call.function.arguments)
          : call.function.arguments;
      } catch {
        return null;
      }
    }
  };
}

/** Disabled provider — always triggers rules-only ordering. */
function createNoneProvider() {
  return { name: 'none', enabled: false, async generatePlan() { return null; } };
}

/**
 * Resolve an LLM provider from config. Never throws — returns a disabled provider if
 * the requested provider is unavailable.
 *
 * @param {{provider?: string, model?: string, apiKey?: string, baseUrl?: string}} [opts]
 */
function getProvider(opts = {}) {
  const provider = (opts.provider || 'none').toLowerCase();
  try {
    switch (provider) {
      case 'anthropic': return createAnthropicProvider(opts);
      case 'openai': return createOpenAIProvider(opts);
      case 'ollama': return createOllamaProvider(opts);
      case 'local': return createOllamaProvider(opts);
      case 'none': return createNoneProvider();
      default:
        logger.warn(`Unknown AI provider "${provider}" — disabling AI planning`);
        return createNoneProvider();
    }
  } catch (err) {
    logger.warn(`Failed to initialize AI provider "${provider}" — disabling AI planning`, { error: err.message });
    return createNoneProvider();
  }
}

module.exports = { getProvider, PLAN_TOOL, SYSTEM_PROMPT };
