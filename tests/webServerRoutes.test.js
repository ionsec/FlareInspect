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
});
