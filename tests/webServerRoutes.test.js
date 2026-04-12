/**
 * @fileoverview Static route contract checks for the web server
 */

const fs = require('fs');
const path = require('path');

describe('web server routes', () => {
  const serverSource = fs.readFileSync(path.join(__dirname, '..', 'web', 'server.js'), 'utf8');

  test('supports ASFF download endpoint', () => {
    expect(serverSource).toContain("app.get('/api/download/asff'");
  });

  test('returns compliance data via framework route', () => {
    expect(serverSource).toContain("app.get('/api/compliance/:framework'");
  });

  test('uses timingSafeEqual for API key comparison', () => {
    expect(serverSource).toContain('crypto.timingSafeEqual');
  });

  test('does not accept api keys from query parameters', () => {
    expect(serverSource).not.toContain('req.query?.apiKey');
  });

  test('validates assessment ids against a strict pattern', () => {
    expect(serverSource).toContain('ASSESSMENT_ID_PATTERN');
    expect(serverSource).toContain('baselineId and currentId must be valid assessment IDs.');
  });

  test('bounds concurrency input for assessment requests', () => {
    expect(serverSource).toContain('MAX_CONCURRENCY');
    expect(serverSource).toContain('Concurrency must be an integer between 1 and');
  });

  test('uses generic unexpected errors for internal failures', () => {
    expect(serverSource).toContain('sendUnexpectedError');
    expect(serverSource).toContain("'Unexpected error.'");
  });
});
