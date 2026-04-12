/**
 * @fileoverview Tests for ConfigManager
 */

const ConfigManager = require('../src/core/config');

describe('ConfigManager', () => {
  test('loads default config when no file exists', () => {
    const config = new ConfigManager();
    expect(config.get('assessment.concurrency')).toBe(3);
  });

  test('gets nested values with dot notation', () => {
    const config = new ConfigManager();
    expect(config.get('scoring.sensitivity', 'medium')).toBe('medium');
  });

  test('returns default for missing keys', () => {
    const config = new ConfigManager();
    expect(config.get('nonexistent.key', 'fallback')).toBe('fallback');
  });

  test('merges CLI options with config defaults', () => {
    const config = new ConfigManager();
    const merged = config.mergeWithCLIOptions({
      token: 'test-token-123456',
      concurrency: '5',
      zones: 'example.com,test.com',
      format: 'html'
    });
    expect(merged.token).toBe('test-token-123456');
    expect(merged.zones).toEqual(['example.com', 'test.com']);
  });
});
