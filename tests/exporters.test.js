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
    { id: 'f-001', checkId: 'CFL-SSL-001', checkTitle: 'SSL Mode', service: 'ssl', severity: 'high', status: 'FAIL', description: 'SSL not strict', remediation: 'Set to Full Strict', resourceId: 'zone-001', resourceType: 'zone', timestamp: new Date(), compliance: ['SOC2', 'PCI-DSS'] },
    { id: 'f-002', checkId: 'CFL-DNS-001', checkTitle: 'DNSSEC', service: 'dns', severity: 'high', status: 'PASS', description: 'DNSSEC enabled', remediation: 'N/A', resourceId: 'zone-001', resourceType: 'zone', timestamp: new Date(), compliance: [] },
    { id: 'f-003', checkId: 'CFL-WAF-001', checkTitle: 'WAF Level', service: 'waf', severity: 'critical', status: 'FAIL', description: 'WAF off', remediation: 'Enable WAF', resourceId: 'zone-001', resourceType: 'zone', timestamp: new Date(), compliance: ['PCI-DSS'] }
  ],
  report: {
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
});
