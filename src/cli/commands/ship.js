/**
 * @fileoverview `flareinspect ship` command.
 * @description Phase 2b — push an assessment to a SIEM (Elasticsearch or Splunk).
 * Targets: elastic|splunk (or "all"). Supports live ship and dry-run.
 *
 *   flareinspect ship -i assessment.json --target elastic \
 *     --es-url https://es.example.com --es-api-key $ES_KEY
 *
 *   flareinspect ship -i assessment.json --target splunk \
 *     --hec-url https://splunk.example.com:8088 --hec-token $HEC
 *
 *   flareinspect ship -i assessment.json --target all --out-dir ./out
 *
 * Env fallbacks: FLAREINSPECT_ES_URL/_ES_APIKEY, FLAREINSPECT_SPLUNK_HEC_URL/_HEC_TOKEN.
 * @module cli/commands/ship
 */

'use strict';

const fs = require('fs').promises;
const chalk = require('chalk');
const ora = require('ora');
const { shipFindings: shipElastic, buildIndexTemplate } = require('../../core/integrations/siem/elastic');
const { shipFindings: shipSplunk } = require('../../core/integrations/siem/splunk');
const EcsExporter = require('../../exporters/ecs');
const SplunkHecExporter = require('../../exporters/splunkHec');
const logger = require('../../core/utils/logger');

function pickEsTargets(opts) {
  return {
    esUrl:    opts.esUrl    || process.env.FLAREINSPECT_ES_URL    || null,
    apiKey:   opts.esApiKey || process.env.FLAREINSPECT_ES_APIKEY || null,
    username: opts.esUsername || process.env.FLAREINSPECT_ES_USERNAME || null,
    password: opts.esPassword || process.env.FLAREINSPECT_ES_PASSWORD || null,
    indexName: opts.indexName || 'flareinspect-findings'
  };
}

function pickSplunkTargets(opts) {
  return {
    hecUrl:   opts.hecUrl   || process.env.FLAREINSPECT_SPLUNK_HEC_URL   || null,
    hecToken: opts.hecToken || process.env.FLAREINSPECT_SPLUNK_HEC_TOKEN || null,
    index:    opts.splunkIndex || 'main'
  };
}

async function shipToElastic(assessment, opts) {
  const t = pickEsTargets(opts);
  if (!t.esUrl) {
    throw new Error('Elastic target requires --es-url (or FLAREINSPECT_ES_URL)');
  }
  if (!t.apiKey && !(t.username && t.password)) {
    throw new Error('Elastic target requires --es-api-key OR --es-username + --es-password');
  }
  return shipElastic({
    esUrl: t.esUrl, apiKey: t.apiKey, username: t.username, password: t.password,
    assessment, indexName: t.indexName, dryRun: !!opts.dryRun
  });
}

async function shipToSplunk(assessment, opts) {
  const t = pickSplunkTargets(opts);
  if (!t.hecUrl)   throw new Error('Splunk target requires --hec-url (or FLAREINSPECT_SPLUNK_HEC_URL)');
  if (!t.hecToken) throw new Error('Splunk target requires --hec-token (or FLAREINSPECT_SPLUNK_HEC_TOKEN)');
  return shipSplunk({ hecUrl: t.hecUrl, hecToken: t.hecToken, assessment, dryRun: !!opts.dryRun });
}

async function exportToFiles(assessment, opts) {
  const dir = opts.outDir || `./out-${Date.now()}`;
  const ex = new EcsExporter({ indexName: opts.indexName || 'flareinspect-findings' });
  const sp = new SplunkHecExporter();
  const ecsR = await ex.exportToFile(assessment, dir);
  const hecR = await sp.exportToFile(assessment, dir);
  return { dir, files: { ecs: ecsR.file, hec: hecR.file }, counts: { ecs: ecsR.count, hec: hecR.count } };
}

async function execute(options) {
  const spinner = ora('Loading assessment data…').start();
  try {
    const raw = await fs.readFile(options.input, 'utf8');
    const assessment = JSON.parse(raw);
    spinner.succeed('Assessment data loaded');

    const target = (options.target || 'all').toLowerCase();
    const wantElastic = target === 'all' || target === 'elastic';
    const wantSplunk  = target === 'all' || target === 'splunk';

    const result = { elastic: null, splunk: null, files: null };

    if (options.outDir) {
      spinner.start('Writing SIEM NDJSON files…');
      result.files = await exportToFiles(assessment, options);
      spinner.succeed(`Files written to ${result.files.dir}`);
      for (const [k, v] of Object.entries(result.files.files)) {
        console.log(chalk.green(`  ✓ ${k}: ${v} (${result.files.counts[k]} docs)`));
      }
    }

    if (wantElastic && !options.outDir) {
      spinner.start('Shipping to Elasticsearch…');
      result.elastic = await shipToElastic(assessment, options);
      spinner.stop();
      printElastic(result.elastic, options);
    }
    if (wantSplunk && !options.outDir) {
      spinner.start('Shipping to Splunk HEC…');
      result.splunk = await shipToSplunk(assessment, options);
      spinner.stop();
      printSplunk(result.splunk, options);
    }

    if (options.dryRun) {
      console.log(chalk.cyan('\n--- Dry-run summary ---'));
      console.log(JSON.stringify({
        elastic: result.elastic && { ok: result.elastic.ok, count: result.elastic.count, body: result.elastic.body },
        splunk:  result.splunk  && { ok: result.splunk.ok,  count: result.splunk.count,  events: result.splunk.events }
      }, null, 2));
    }

    const ok = (!result.elastic || result.elastic.ok) && (!result.splunk || result.splunk.ok);
    if (!ok) {
      console.log(chalk.red('One or more targets failed; see errors above.'));
      process.exit(1);
    }
  } catch (err) {
    spinner.fail('Ship failed');
    console.error(chalk.red('Error:'), err.message);
    logger.error('Ship failed', { error: err.message, stack: err.stack });
    process.exit(1);
  }
}

function printElastic(r, opts) {
  if (!r) return;
  if (r.dryRun) { console.log(chalk.cyan(`  ↷ Elastic dry-run: ${r.count} docs (no POST)`)); return; }
  if (r.ok)     { console.log(chalk.green(`  ✓ Elastic shipped: ${r.count} docs (HTTP ${r.status}, ${r.itemsCount} items)`)); return; }
  console.log(chalk.red(`  ✗ Elastic failed: status=${r.status} error=${r.error || 'unknown'}`));
}

function printSplunk(r, opts) {
  if (!r) return;
  if (r.dryRun) { console.log(chalk.cyan(`  ↷ Splunk dry-run: ${r.count} events (no POST)`)); return; }
  if (r.ok)     { console.log(chalk.green(`  ✓ Splunk shipped: ${r.sent}/${r.count} events`)); return; }
  console.log(chalk.red(`  ✗ Splunk failed: sent=${r.sent} failed=${r.failed} (${r.errors.length} errors)`));
}

module.exports = { execute, shipToElastic, shipToSplunk, exportToFiles, pickEsTargets, pickSplunkTargets };
