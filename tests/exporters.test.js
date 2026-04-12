/**
 * @fileoverview Tests for exporters
 */

const SARIFExporter = require('../src/exporters/sarif');
const MarkdownExporter = require('../src/exporters/markdown');
const CSVExporter = require('../src/exporters/csv');
const ASFFExporter = require('../src/exporters/asff');
const HTMLExporter = require('../src/exporters/html');

const mockAssessment = {
  assessmentId: 'test-001',
  status: 'completed',
  startedAt: new Date().toISOString(),
  completedAt: new Date().toISOString(),
  executionTime: 5000,
  account: { id: 'acc-001', name: 'Test Account', type: 'standard' },
  zones: [{ id: 'zone-001', name: 'example.com', plan: 'Pro' }],
  score: { overallScore: 75, grade: 'C' },
  summary: {
    totalChecks: 20,
    passedChecks: 15,
    failedChecks: 5,
    criticalFindings: 1,
    highFindings: 2,
    mediumFindings: 2,
    lowFindings: 0,
    informationalFindings: 0,
    byService: { ssl: 2, dns: 3 }
  },
  findings: [
    { id: 'f-001', checkId: 'CFL-SSL-001', checkTitle: 'SSL Mode', service: 'ssl', severity: 'high', status: 'FAIL', description: 'SSL not strict', remediation: 'Set to Full Strict', resourceId: 'zone-001', resourceType: 'zone', timestamp: new Date(), compliance: ['SOC2', 'PCI-DSS'], evidence: { summary: 'Zone is using flexible SSL.', observed: 'flexible', expected: 'strict', affectedEntities: [{ name: 'example.com', type: 'zone' }], counts: { impactedZones: 1 }, reviewGuidance: 'Move to strict mode.' }, metadata: { resourceName: 'example.com' } },
    { id: 'f-002', checkId: 'CFL-DNS-001', checkTitle: 'DNSSEC', service: 'dns', severity: 'high', status: 'PASS', description: 'DNSSEC enabled', remediation: 'N/A', resourceId: 'zone-001', resourceType: 'zone', timestamp: new Date(), compliance: [], evidence: { summary: 'DNSSEC enabled.', observed: 'active', expected: 'active', counts: { records: 12 } }, metadata: { resourceName: 'example.com' } },
    { id: 'f-003', checkId: 'CFL-WAF-001', checkTitle: 'WAF Level', service: 'waf', severity: 'critical', status: 'FAIL', description: 'WAF off', remediation: 'Enable WAF', resourceId: 'zone-001', resourceType: 'zone', timestamp: new Date(), compliance: ['PCI-DSS'], evidence: { summary: 'WAF is disabled.', observed: 'off', expected: 'medium or high', affectedEntities: [{ name: 'example.com', type: 'zone' }, { name: 'admin@example.com', email: 'admin@example.com', roles: ['Administrator'] }], counts: { firewallRules: 0 }, reviewGuidance: 'Enable managed WAF.' }, metadata: { resourceName: 'example.com' } }
  ],
  report: {
    securityFindings: {
      criticalFindings: [],
      highRiskFindings: [],
      detailedFindings: [
        { id: 'f-001', checkId: 'CFL-SSL-001', checkTitle: 'SSL Mode', service: 'ssl', severity: 'high', status: 'FAIL', description: 'SSL not strict', remediation: 'Set to Full Strict', resourceId: 'zone-001', metadata: { resourceName: 'example.com' }, analysis: 'Observed state is flexible.', evidence: { summary: 'Zone is using flexible SSL.', observed: 'flexible', expected: 'strict', affectedEntities: [{ name: 'example.com', type: 'zone' }], counts: { impactedZones: 1 }, source: { endpoint: 'zones.settings.ssl.get' }, reviewGuidance: 'Move to strict mode.' } },
        { id: 'f-003', checkId: 'CFL-WAF-001', checkTitle: 'WAF Level', service: 'waf', severity: 'critical', status: 'FAIL', description: 'WAF off', remediation: 'Enable WAF', resourceId: 'zone-001', metadata: { resourceName: 'example.com' }, analysis: 'WAF is disabled.', evidence: { summary: 'WAF is disabled.', observed: 'off', expected: 'medium or high', affectedEntities: [{ name: 'example.com', type: 'zone' }, { name: 'admin@example.com', email: 'admin@example.com', roles: ['Administrator'] }], counts: { firewallRules: 0 }, source: { endpoint: 'zones.settings.security_level.get' }, reviewGuidance: 'Enable managed WAF.' } }
      ]
    },
    analysis: {
      identityAccess: {
        summary: 'Identity controls need review.',
        quickWins: [{ title: 'Review admins', action: 'Reduce admin count', reviewGuidance: 'Confirm each admin still needs access.' }],
        topAffectedEntities: [{ name: 'admin@example.com', email: 'admin@example.com', roles: ['Administrator'] }]
      }
    },
    recommendations: {
      immediate: [{ title: 'Enable WAF', action: 'Turn on WAF', timeline: 'Immediate', effort: 'low' }],
      shortTerm: [],
      longTerm: []
    }
  }
};

describe('SARIFExporter', () => {
  test('exports valid SARIF structure', async () => {
    const exporter = new SARIFExporter();
    const result = await exporter.export(mockAssessment);
    expect(result.$schema).toContain('sarif');
    expect(result.version).toBe('2.1.0');
    expect(result.runs.length).toBe(1);
    expect(result.runs[0].tool.driver.name).toBe('FlareInspect');
    expect(result.runs[0].results.length).toBeGreaterThan(0);
  });

  test('maps severity to SARIF levels', async () => {
    const exporter = new SARIFExporter();
    const result = await exporter.export(mockAssessment);
    const levels = result.runs[0].results.map(r => r.level);
    expect(levels).toContain('error');
  });
});

describe('MarkdownExporter', () => {
  test('exports markdown with executive summary', async () => {
    const exporter = new MarkdownExporter();
    const result = await exporter.export(mockAssessment);
    expect(result).toContain('# FlareInspect Security Assessment Report');
    expect(result).toContain('Executive Summary');
    expect(result).toContain('75/100');
  });

  test('includes findings by severity', async () => {
    const exporter = new MarkdownExporter();
    const result = await exporter.export(mockAssessment);
    expect(result).toContain('Critical Findings');
    expect(result).toContain('High Findings');
  });

  test('escapes markdown table and html-sensitive content', async () => {
    const exporter = new MarkdownExporter();
    const assessment = {
      ...mockAssessment,
      findings: [{
        ...mockAssessment.findings[0],
        checkTitle: 'Bad | Title',
        description: '<script>alert(1)</script>\nsecond line',
        remediation: 'fix | now'
      }]
    };
    const result = await exporter.export(assessment);
    expect(result).toContain('Bad \\| Title');
    expect(result).toContain('&lt;script&gt;alert(1)&lt;/script&gt; second line');
    expect(result).toContain('fix \\| now');
  });

  test('includes evidence-rich details and analysis', async () => {
    const exporter = new MarkdownExporter();
    const result = await exporter.export(mockAssessment);
    expect(result).toContain('Evidence Summary');
    expect(result).toContain('Affected Entities');
    expect(result).toContain('Full Data Analysis');
    expect(result).toContain('admin@example.com');
  });
});

describe('CSVExporter', () => {
  test('exports CSV with headers', async () => {
    const exporter = new CSVExporter();
    const result = await exporter.export(mockAssessment);
    const lines = result.split('\n');
    expect(lines[0]).toContain('CheckID');
    expect(lines.length).toBeGreaterThan(1);
  });

  test('escapes commas in fields', async () => {
    const exporter = new CSVExporter();
    const assessment = {
      ...mockAssessment,
      findings: [{ ...mockAssessment.findings[0], description: 'Has, commas, in, it' }]
    };
    const result = await exporter.export(assessment);
    expect(result).toContain('"Has, commas, in, it"');
  });

  test('includes flattened evidence columns', async () => {
    const exporter = new CSVExporter();
    const result = await exporter.export(mockAssessment);
    const [header, firstRow] = result.split('\n');
    expect(header).toContain('EvidenceSummary');
    expect(header).toContain('AffectedEntities');
    expect(firstRow).toContain('Zone is using flexible SSL.');
  });
});

describe('ASFFExporter', () => {
  test('exports ASFF-compliant findings', async () => {
    const exporter = new ASFFExporter();
    const result = await exporter.export(mockAssessment);
    expect(Array.isArray(result)).toBe(true);
    expect(result.length).toBeGreaterThan(0);
    expect(result[0].SchemaVersion).toBe('2018-10-08');
    expect(result[0].Types).toContain('Software and Configuration Checks/Cloudflare');
  });
});

describe('HTMLExporter', () => {
  test('json helper escapes characters unsafe in HTML script contexts', () => {
    const exporter = new HTMLExporter();
    const helper = exporter.constructor ? require('handlebars').helpers.json : null;
    const result = helper({ payload: '</script><img src=x onerror=alert(1)>' });
    expect(result).toContain('\\u003c/script\\u003e');
    expect(result).not.toContain('</script>');
  });

  test('exports chart data without external cdn dependency', async () => {
    const exporter = new HTMLExporter();
    const result = await exporter.export(mockAssessment);
    expect(result).not.toContain('cdn.jsdelivr.net');
    expect(result).toContain('const categoryLabels =');
    expect(result).toContain('drawBarChart');
  });

  test('renders detailed evidence review sections', async () => {
    const exporter = new HTMLExporter();
    const result = await exporter.export(mockAssessment);
    expect(result).toContain('Detailed Findings Review');
    expect(result).toContain('Affected Entities');
    expect(result).toContain('admin@example.com');
    expect(result).toContain('Identity and Access Analysis');
  });
});
