/**
 * @fileoverview Tests for Plugin system
 */

const { FlareInspectPlugin, PluginLoader } = require('../src/plugins/interface');

describe('FlareInspectPlugin', () => {
  test('creates plugin from manifest', () => {
    const plugin = new FlareInspectPlugin({
      name: 'test-plugin',
      version: '1.0.0',
      description: 'Test plugin',
      checks: [{ id: 'PLUGIN-001', title: 'Custom Check' }]
    });
    expect(plugin.name).toBe('test-plugin');
    expect(plugin.checks.length).toBe(1);
  });

  test('default hooks are no-ops', async () => {
    const plugin = new FlareInspectPlugin({ name: 'test' });
    const assessment = { test: true };
    await expect(plugin.preAssess(assessment)).resolves.toBeUndefined();
  });

  test('onFinding returns finding unchanged', async () => {
    const plugin = new FlareInspectPlugin({ name: 'test' });
    const finding = { id: 'f-001', checkId: 'TEST' };
    const result = await plugin.onFinding(finding);
    expect(result).toEqual(finding);
  });

  test('getChecks returns plugin checks', () => {
    const checks = [{ id: 'PLUGIN-001' }, { id: 'PLUGIN-002' }];
    const plugin = new FlareInspectPlugin({ name: 'test', checks });
    expect(plugin.getChecks()).toEqual(checks);
  });
});

describe('PluginLoader', () => {
  test('loads without plugins directory', () => {
    const loader = new PluginLoader();
    loader.pluginDir = '/nonexistent/path';
    loader.loadAll();
    expect(loader.plugins.length).toBe(0);
  });

  test('executeHook passes data through with no plugins', async () => {
    const loader = new PluginLoader();
    const data = { test: true };
    const result = await loader.executeHook('preAssess', data);
    expect(result).toEqual(data);
  });

  test('getAllPluginChecks returns empty array when no plugins', () => {
    const loader = new PluginLoader();
    expect(loader.getAllPluginChecks()).toEqual([]);
  });

  test('getLoadedPlugins returns empty array', () => {
    const loader = new PluginLoader();
    expect(loader.getLoadedPlugins()).toEqual([]);
  });
});
