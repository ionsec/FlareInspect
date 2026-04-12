/**
 * @fileoverview Configuration Manager for FlareInspect
 * @description Loads .flareinspect.yml config files for team-shared settings
 * @module core/config
 */

const fs = require('fs');
const path = require('path');
const logger = require('../core/utils/logger');

const CONFIG_FILENAMES = ['.flareinspect.yml', '.flareinspect.yaml', 'flareinspect.config.json'];
const MAX_CONFIG_SIZE_BYTES = 1024 * 64;

class ConfigManager {
  constructor() {
    this.config = this.loadConfig();
  }

  loadConfig() {
    // Search from cwd upward
    let currentDir = process.cwd();
    const root = path.parse(currentDir).root;

    while (currentDir !== root) {
      for (const filename of CONFIG_FILENAMES) {
        const filePath = path.join(currentDir, filename);
        if (fs.existsSync(filePath)) {
          try {
            const stats = fs.statSync(filePath);
            if (!stats.isFile() || stats.size > MAX_CONFIG_SIZE_BYTES) {
              logger.warn('Skipping unsafe config candidate', { path: filePath });
              continue;
            }
            const content = fs.readFileSync(filePath, 'utf8');
            const parsed = filename.endsWith('.json')
              ? JSON.parse(content)
              : this.parseYaml(content);
            logger.info('Loaded config from', { path: filePath });
            return { ...parsed, _configPath: filePath };
          } catch (error) {
            logger.warn('Failed to parse config', { path: filePath, error: error.message });
          }
        }
      }
      currentDir = path.dirname(currentDir);
    }

    return this.getDefaults();
  }

  parseYaml(content) {
    // Simple YAML parser for flat key-value pairs (no nested objects needed for config)
    const config = {};
    const lines = content.split('\n');
    let currentSection = null;

    for (const line of lines) {
      const trimmed = line.trim();
      if (!trimmed || trimmed.startsWith('#')) continue;

      // Section header
      const sectionMatch = trimmed.match(/^(\w+):$/);
      if (sectionMatch) {
        currentSection = sectionMatch[1];
        if (!config[currentSection]) config[currentSection] = {};
        continue;
      }

      // Key-value pair
      const kvMatch = trimmed.match(/^(\w+):\s*(.+)$/);
      if (kvMatch) {
        const key = kvMatch[1];
        let value = kvMatch[2].trim();
        
        // Remove quotes
        if ((value.startsWith('"') && value.endsWith('"')) || (value.startsWith("'") && value.endsWith("'"))) {
          value = value.slice(1, -1);
        }

        // Parse booleans and numbers
        if (value === 'true') value = true;
        else if (value === 'false') value = false;
        else if (/^\d+$/.test(value)) value = parseInt(value, 10);

        if (currentSection) {
          config[currentSection][key] = value;
        } else {
          config[key] = value;
        }
      }

      // List items
      const listMatch = trimmed.match(/^- (.+)$/);
      if (listMatch && currentSection) {
        if (!Array.isArray(config[currentSection])) {
          config[currentSection] = [];
        }
        config[currentSection].push(listMatch[1].trim());
      }
    }

    return config;
  }

  getDefaults() {
    return {
      token: process.env.CLOUDFLARE_TOKEN || null,
      output: { format: 'json', directory: './output' },
      assessment: {
        concurrency: 3,
        checks: null,
        zones: null,
        excludeZones: null
      },
      compliance: { framework: null },
      scoring: { sensitivity: 'medium' },
      ci: {
        threshold: null,
        failOn: null
      }
    };
  }

  get(key, defaultValue) {
    const keys = key.split('.');
    let value = this.config;
    for (const k of keys) {
      if (value && typeof value === 'object' && k in value) {
        value = value[k];
      } else {
        return defaultValue;
      }
    }
    return value !== undefined ? value : defaultValue;
  }

  mergeWithCLIOptions(cliOptions) {
    return {
      token: cliOptions.token || this.get('token') || process.env.CLOUDFLARE_TOKEN,
      output: cliOptions.output || this.get('output.directory'),
      format: cliOptions.format || this.get('output.format', 'json'),
      concurrency: cliOptions.concurrency || this.get('assessment.concurrency', 3),
      checks: cliOptions.checks ? cliOptions.checks.split(',') : this.get('assessment.checks'),
      zones: cliOptions.zones ? cliOptions.zones.split(',') : this.get('assessment.zones'),
      excludeZones: cliOptions.excludeZones ? cliOptions.excludeZones.split(',') : this.get('assessment.excludeZones'),
      compliance: cliOptions.compliance || this.get('compliance.framework'),
      sensitivity: cliOptions.sensitivity || this.get('scoring.sensitivity', 'medium'),
      threshold: cliOptions.threshold || this.get('ci.threshold'),
      failOn: cliOptions.failOn || this.get('ci.failOn'),
      ci: cliOptions.ci || false
    };
  }
}

module.exports = ConfigManager;
