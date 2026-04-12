/**
 * @fileoverview Plugin Interface for FlareInspect
 * @description Base class and loader for community security check plugins
 * @module plugins/interface
 */

const path = require('path');
const fs = require('fs');
const logger = require('../core/utils/logger');

class FlareInspectPlugin {
  constructor(manifest) {
    this.name = manifest.name || 'unnamed-plugin';
    this.version = manifest.version || '1.0.0';
    this.description = manifest.description || '';
    this.author = manifest.author || '';
    this.checks = manifest.checks || [];
    this.hooks = manifest.hooks || {};
  }

  /**
   * Called before assessment starts
   * @param {Object} assessment - Assessment object being prepared
   */
  async preAssess(assessment) {
    if (this.hooks.preAssess) {
      return this.hooks.preAssess(assessment);
    }
  }

  /**
   * Called after assessment completes
   * @param {Object} assessment - Completed assessment
   */
  async postAssess(assessment) {
    if (this.hooks.postAssess) {
      return this.hooks.postAssess(assessment);
    }
  }

  /**
   * Called when a finding is created - can modify or enrich
   * @param {Object} finding - The finding being created
   */
  async onFinding(finding) {
    if (this.hooks.onFinding) {
      return this.hooks.onFinding(finding);
    }
    return finding;
  }

  /**
   * Get additional checks defined by this plugin
   */
  getChecks() {
    return this.checks;
  }
}

class PluginLoader {
  constructor() {
    this.plugins = [];
    this.pluginDir = path.join(__dirname);
  }

  /**
   * Load all plugins from the plugins directory
   */
  loadAll() {
    if (!fs.existsSync(this.pluginDir)) {
      logger.debug('No plugins directory found');
      return this;
    }

    const entries = fs.readdirSync(this.pluginDir, { withFileTypes: true });
    
    for (const entry of entries) {
      if (entry.isDirectory()) {
        const manifestPath = path.join(this.pluginDir, entry.name, 'flareinspect-plugin.json');
        if (fs.existsSync(manifestPath)) {
          try {
            const manifest = JSON.parse(fs.readFileSync(manifestPath, 'utf8'));
            const indexPath = path.join(this.pluginDir, entry.name, manifest.main || 'index.js');
            
            if (fs.existsSync(indexPath)) {
              const PluginClass = require(indexPath);
              const plugin = typeof PluginClass === 'function' 
                ? new PluginClass(manifest) 
                : new FlareInspectPlugin(manifest);
              
              this.plugins.push(plugin);
              logger.info(`Loaded plugin: ${plugin.name} v${plugin.version}`);
            }
          } catch (error) {
            logger.warn(`Failed to load plugin ${entry.name}:`, error.message);
          }
        }
      }
    }

    return this;
  }

  /**
   * Execute a hook on all plugins
   */
  async executeHook(hookName, data) {
    let result = data;
    for (const plugin of this.plugins) {
      try {
        if (plugin[hookName]) {
          const hookResult = await plugin[hookName](result);
          if (hookResult !== undefined) {
            result = hookResult;
          }
        }
      } catch (error) {
        logger.warn(`Plugin ${plugin.name} hook ${hookName} failed:`, error.message);
      }
    }
    return result;
  }

  /**
   * Get all additional checks from plugins
   */
  getAllPluginChecks() {
    return this.plugins.flatMap(p => p.getChecks());
  }

  /**
   * Get loaded plugin names
   */
  getLoadedPlugins() {
    return this.plugins.map(p => ({ name: p.name, version: p.version, description: p.description }));
  }
}

module.exports = { FlareInspectPlugin, PluginLoader };
