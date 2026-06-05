/**
 * @fileoverview ECS file exporter (for pull / air-gapped SIEM ingestion).
 * @description Phase 2a — produces an Elasticsearch `_bulk`-compatible NDJSON
 * file on disk. The same `buildBulkBody` used by the live shipper drives this,
 * so what's on disk is exactly what the live POST would have sent.
 *
 * The companion Kibana saved-objects NDJSON (Kibana index template +
 * dashboard + search + visualisation) is shipped in Phase 2b.
 * @module exporters/ecs
 */

'use strict';

const fs = require('fs').promises;
const path = require('path');
const { buildBulkBody, buildIndexTemplate } = require('../core/integrations/siem/elastic');

class EcsExporter {
  /**
   * @param {{ indexName?: string }} [opts]
   */
  constructor(opts = {}) {
    this.indexName = opts.indexName || 'flareinspect-findings';
  }

  /**
   * Write a `_bulk`-compatible NDJSON file to `outDir`.
   * @param {object} assessment
   * @param {string} outDir
   * @returns {Promise<{ file: string, count: number, indexTemplate: object }>}
   */
  async exportToFile(assessment, outDir) {
    await fs.mkdir(outDir, { recursive: true });
    const bulk = buildBulkBody(assessment, this.indexName);
    const file = path.join(outDir, `${this.indexName}-${Date.now()}.ndjson`);
    await fs.writeFile(file, bulk.body, 'utf8');
    const tplFile = path.join(outDir, `${this.indexName}-template.json`);
    await fs.writeFile(tplFile, JSON.stringify(buildIndexTemplate(), null, 2), 'utf8');
    return { file, count: bulk.count, indexTemplate: buildIndexTemplate(), tplFile };
  }

  /**
   * Expose the bulk body without writing to disk.
   * @param {object} assessment
   * @returns {string}
   */
  buildBody(assessment) {
    return buildBulkBody(assessment, this.indexName).body;
  }
}

module.exports = EcsExporter;
