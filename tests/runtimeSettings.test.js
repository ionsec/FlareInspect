/**
 * @fileoverview Unit tests for the runtime settings overlay.
 */

'use strict';

const fs = require('fs');
const os = require('os');
const path = require('path');
const rs = require('../src/core/config/runtimeSettings');

let counter = 0;
function tmpFile() {
  counter += 1;
  return path.join(os.tmpdir(), `flareinspect-settings-${process.pid}-${counter}.json`);
}
function cleanup(file) { try { fs.unlinkSync(file); } catch (_) { /* ignore */ } }

describe('runtimeSettings.resolve precedence', () => {
  test('saved value wins over env', () => {
    const file = tmpFile();
    rs.saveSettings({ slackWebhook: 'https://hooks.slack.com/saved/value1234' }, { file });
    const out = rs.resolve('slackWebhook', { FLAREINSPECT_SLACK_WEBHOOK: 'https://env/value' }, { file });
    expect(out).toBe('https://hooks.slack.com/saved/value1234');
    cleanup(file);
  });

  test('falls back to env when not saved', () => {
    const file = tmpFile();
    const out = rs.resolve('esUrl', { FLAREINSPECT_ES_URL: 'https://es.env:9200' }, { file });
    expect(out).toBe('https://es.env:9200');
    cleanup(file);
  });

  test('returns null when neither saved nor in env', () => {
    const file = tmpFile();
    expect(rs.resolve('hecToken', {}, { file })).toBeNull();
    cleanup(file);
  });

  test('empty string clears a key and re-enables the env fallback', () => {
    const file = tmpFile();
    rs.saveSettings({ esUrl: 'https://es.saved:9200' }, { file });
    expect(rs.resolve('esUrl', {}, { file })).toBe('https://es.saved:9200');
    rs.saveSettings({ esUrl: '' }, { file });
    expect(rs.resolve('esUrl', { FLAREINSPECT_ES_URL: 'https://es.env:9200' }, { file })).toBe('https://es.env:9200');
    cleanup(file);
  });
});

describe('runtimeSettings.saveSettings validation', () => {
  test('ignores unknown keys', () => {
    const file = tmpFile();
    const merged = rs.saveSettings({ bogusKey: 'x', aiModel: 'gpt-4o' }, { file });
    expect(merged.bogusKey).toBeUndefined();
    expect(merged.aiModel).toBe('gpt-4o');
    cleanup(file);
  });

  test('rejects invalid enum values', () => {
    const file = tmpFile();
    expect(() => rs.saveSettings({ aiProvider: 'definitely-not-valid' }, { file })).toThrow(/Invalid value/);
    cleanup(file);
  });

  test('rejects non-object payloads', () => {
    const file = tmpFile();
    expect(() => rs.saveSettings('nope', { file })).toThrow(/must be an object/);
    cleanup(file);
  });
});

describe('runtimeSettings.maskedView', () => {
  test('never exposes secret values, only a hint', () => {
    const file = tmpFile();
    rs.saveSettings({ anthropicApiKey: 'sk-ant-supersecret-ABCD' }, { file });
    const view = rs.maskedView({}, { file });
    expect(view.anthropicApiKey.secret).toBe(true);
    expect(view.anthropicApiKey).not.toHaveProperty('value');
    expect(view.anthropicApiKey.configured).toBe(true);
    expect(view.anthropicApiKey.source).toBe('settings');
    expect(view.anthropicApiKey.hint).toMatch(/ABCD$/);
    cleanup(file);
  });

  test('exposes non-secret values for pre-fill', () => {
    const file = tmpFile();
    rs.saveSettings({ aiProvider: 'anthropic', aiModel: 'claude-opus-4-8' }, { file });
    const view = rs.maskedView({}, { file });
    expect(view.aiProvider.value).toBe('anthropic');
    expect(view.aiModel.value).toBe('claude-opus-4-8');
    expect(view.aiProvider.secret).toBe(false);
    cleanup(file);
  });

  test('reports source as env when only the environment is set', () => {
    const file = tmpFile();
    const view = rs.maskedView({ FLAREINSPECT_ES_URL: 'https://es.env:9200' }, { file });
    expect(view.esUrl.source).toBe('env');
    expect(view.esUrl.value).toBe('https://es.env:9200');
    expect(view.hecToken.source).toBe('none');
    expect(view.hecToken.configured).toBe(false);
    cleanup(file);
  });
});
