/**
 * @fileoverview Unit tests for the shared on-disk assessment store.
 */

'use strict';

const fs = require('fs');
const os = require('os');
const path = require('path');
const store = require('../src/core/services/assessmentStore');

let dir;
beforeEach(() => { dir = fs.mkdtempSync(path.join(os.tmpdir(), 'fi-store-')); });
afterEach(() => { try { fs.rmSync(dir, { recursive: true, force: true }); } catch (_) { /* ignore */ } });

const sample = (id, score = 50) => ({
  assessmentId: id,
  account: { name: 'Acme' },
  zones: [{ id: 'z1', name: 'x.test', plan: 'Free' }],
  findings: [{ id: 'f1', checkId: 'CFL-SSL-002', severity: 'high', status: 'FAIL' }],
  score: { overallScore: score, grade: 'F' },
  completedAt: '2026-06-06T00:00:00Z'
});

describe('assessmentStore', () => {
  const ID = '11111111-1111-4111-8111-111111111111';

  test('persist writes <id>.json and latest.json; loadById reads it back (no token)', () => {
    store.persist(sample(ID), { dir });
    expect(fs.existsSync(path.join(dir, `${ID}.json`))).toBe(true);
    expect(fs.existsSync(path.join(dir, 'latest.json'))).toBe(true);
    const a = store.loadById(ID, { dir });
    expect(a.assessmentId).toBe(ID);
    expect(a.score.overallScore).toBe(50);
  });

  test('loadById with no id returns the latest', () => {
    store.persist(sample(ID, 77), { dir });
    expect(store.loadById(undefined, { dir }).score.overallScore).toBe(77);
  });

  test('loadById rejects an invalid id', () => {
    expect(() => store.loadById('not-a-uuid', { dir })).toThrow(/Invalid assessmentId/);
  });

  test('loadById throws a clear error when the assessment is missing', () => {
    expect(() => store.loadById(ID, { dir })).toThrow(/not found/);
  });

  test('list returns compact metadata, newest first', () => {
    store.persist({ ...sample('22222222-2222-4222-8222-222222222222', 10), completedAt: '2026-06-01T00:00:00Z' }, { dir });
    store.persist({ ...sample(ID, 90), completedAt: '2026-06-06T00:00:00Z' }, { dir });
    const list = store.list({ dir });
    expect(list).toHaveLength(2);
    expect(list[0].assessmentId).toBe(ID); // newest first
    expect(list[0]).toMatchObject({ accountName: 'Acme', score: 90, grade: 'F', findings: 1 });
  });
});
