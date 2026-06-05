/**
 * @fileoverview Splunk HEC file exporter (for pull / air-gapped ingestion).
 * @description Phase 2a — produces a NDJSON file where each line is one HEC
 * envelope, ready for replay with `curl -d @hec.ndjson .../services/collector/event`
 * or with `splunk cmd splunkd print-modinput-results` style replay.
 *
 * The companion Splunk TA / dashboards ship in Phase 2b.
 * @module exporters/splunkHec
 */

'use strict';

const fs = require('fs').promises;
const path = require('path');
const { buildHecPayload, SOURCETYPE } = require('../core/integrations/siem/splunk');

class SplunkHecExporter {
  /**
   * @param {{ sourcetype?: string }} [opts]
   */
  constructor(opts = {}) {
    this.sourcetype = opts.sourcetype || SOURCETYPE;
  }

  /**
   * Write a NDJSON HEC file to `outDir` (one envelope per line).
   * @param {object} assessment
   * @param {string} outDir
   * @returns {Promise<{ file: string, count: number }>}
   */
  async exportToFile(assessment, outDir) {
    await fs.mkdir(outDir, { recursive: true });
    const built = buildHecPayload(assessment);
    const file = path.join(outDir, `flareinspect-hec-${Date.now()}.ndjson`);
    const body = built.events.map(e => JSON.stringify(e)).join('\n') + (built.events.length ? '\n' : '');
    await fs.writeFile(file, body, 'utf8');
    return { file, count: built.count };
  }

  /**
   * Expose the HEC envelopes without writing to disk.
   * @param {object} assessment
   * @returns {Array}
   */
  buildEvents(assessment) {
    return buildHecPayload(assessment).events;
  }
}

module.exports = SplunkHecExporter;
