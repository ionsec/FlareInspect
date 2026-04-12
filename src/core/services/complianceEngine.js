/**
 * @fileoverview Compliance Mapping Engine for FlareInspect
 * @description Maps security check IDs to compliance framework controls
 * @module core/services/complianceEngine
 */

const logger = require('../utils/logger');

class ComplianceEngine {
  constructor() {
    this.mappings = this.initializeMappings();
  }

  initializeMappings() {
    return {
      'CFL-ACC-001': { cis: ['1.1'], soc2: ['CC6.1'], pci: ['8.3'], nist: ['PR.AC-7'] },
      'CFL-ACC-002': { cis: ['1.2'], soc2: ['CC6.1'], pci: ['8.6'], nist: ['PR.AC-1'] },
      'CFL-ACC-003': { cis: ['1.3'], soc2: ['CC6.1', 'CC6.2'], pci: ['8.1'], nist: ['PR.AC-4'] },
      'CFL-ACC-004': { cis: ['1.4'], soc2: ['CC7.2'], pci: ['10.1'], nist: ['DE.CM-1'] },
      'CFL-ACC-005': { cis: ['1.5'], soc2: ['CC6.1'], pci: ['8.3'], nist: ['PR.AC-7'] },
      'CFL-DNS-001': { cis: ['2.1'], soc2: ['CC6.1'], pci: ['4.1'], nist: ['PR.DS-5'] },
      'CFL-DNS-002': { cis: ['2.2'], soc2: ['CC6.6'], pci: ['4.1'], nist: ['PR.DS-5'] },
      'CFL-DNS-003': { cis: ['2.3'], soc2: ['CC6.6'], nist: ['PR.DS-5'] },
      'CFL-DNS-004': { cis: ['2.4'], soc2: ['CC6.1'], pci: ['4.1'], nist: ['PR.DS-5'] },
      'CFL-DNS-005': { cis: ['2.5'], soc2: ['CC6.6'], pci: ['4.1'], nist: ['PR.DS-5'] },
      'CFL-SSL-001': { cis: ['3.1'], soc2: ['CC6.1', 'CC6.7'], pci: ['4.1', '4.2'], nist: ['PR.DS-1', 'PR.DS-2'] },
      'CFL-SSL-002': { cis: ['3.2'], soc2: ['CC6.7'], pci: ['4.1', '8.2'], nist: ['PR.DS-2'] },
      'CFL-SSL-003': { cis: ['3.3'], soc2: ['CC6.7'], pci: ['4.1'], nist: ['PR.DS-2'] },
      'CFL-SSL-004': { cis: ['3.4'], soc2: ['CC6.7'], pci: ['4.1', '6.1'], nist: ['PR.DS-2'] },
      'CFL-SSL-005': { cis: ['3.5'], soc2: ['CC6.7'], pci: ['4.1'], nist: ['PR.DS-2'] },
      'CFL-WAF-001': { cis: ['4.1'], soc2: ['CC6.1'], pci: ['6.5', '6.6'], nist: ['PR.IP-1'] },
      'CFL-WAF-002': { cis: ['4.2'], soc2: ['CC6.1', 'CC6.6'], pci: ['6.5'], nist: ['PR.IP-1'] },
      'CFL-WAF-003': { cis: ['4.3'], soc2: ['CC6.6'], pci: ['6.5'], nist: ['PR.IP-1'] },
      'CFL-WAF-004': { cis: ['4.4'], soc2: ['CC6.1'], pci: ['6.5'], nist: ['PR.IP-1'] },
      'CFL-WAF-005': { cis: ['4.5'], soc2: ['CC6.1'], pci: ['6.5', '6.6'], nist: ['PR.IP-1'] },
      'CFL-ZT-001': { cis: ['5.1'], soc2: ['CC6.1', 'CC6.2'], pci: ['8.3'], nist: ['PR.AC-1', 'PR.AC-7'] },
      'CFL-ZT-002': { cis: ['5.2'], soc2: ['CC6.1', 'CC6.3'], pci: ['8.3'], nist: ['PR.AC-4'] },
      'CFL-ZT-003': { cis: ['5.3'], soc2: ['CC6.1'], nist: ['PR.AC-3'] },
      'CFL-ZT-004': { cis: ['5.4'], soc2: ['CC6.6'], pci: ['1.3'], nist: ['PR.AC-5'] },
      'CFL-ZT-005': { cis: ['5.5'], soc2: ['CC6.1', 'CC6.7'], pci: ['3.4'], nist: ['PR.DS-5'] },
      'CFL-ZT-006': { cis: ['5.6'], soc2: ['CC6.1'], pci: ['8.6'], nist: ['PR.AC-1'] },
      'CFL-PERF-001': { cis: ['6.1'], nist: ['PR.IP-1'] },
      'CFL-PERF-002': { cis: ['6.2'], nist: ['PR.IP-1'] },
      'CFL-PERF-003': { cis: ['6.3'], nist: ['PR.IP-1'] },
      'CFL-PERF-004': { cis: ['6.4'], nist: ['PR.IP-1'] },
      'CFL-PERF-005': { cis: ['6.5'], nist: ['PR.IP-1'] },
      'CFL-WORK-001': { cis: ['7.1'], soc2: ['CC8.1'], nist: ['PR.IP-1'] },
      'CFL-WORK-002': { cis: ['7.2'], soc2: ['CC6.6'], nist: ['PR.IP-1'] },
      'CFL-BOT-001': { cis: ['4.4'], soc2: ['CC6.1'], pci: ['6.5'], nist: ['PR.IP-1'] },
      'CFL-API-001': { cis: ['8.1'], soc2: ['CC6.1'], pci: ['6.5'], nist: ['PR.IP-1'] },
      'CFL-API-002': { cis: ['8.2'], soc2: ['CC6.1'], pci: ['6.5'], nist: ['PR.IP-1'] },
      'CFL-LB-001': { cis: ['9.1'], soc2: ['CC6.6'], nist: ['PR.DS-4'] },
      'CFL-LB-002': { cis: ['9.2'], soc2: ['CC6.6'], nist: ['PR.DS-4'] },
      'CFL-PAGE-001': { cis: ['7.3'], soc2: ['CC6.1'], nist: ['PR.DS-5'] },
      'CFL-PAGE-002': { cis: ['7.4'], soc2: ['CC6.1'], nist: ['PR.IP-1'] },
      'CFL-EMAIL-001': { cis: ['10.1'], soc2: ['CC6.1'], nist: ['PR.DS-5'] },
      'CFL-EMAIL-002': { cis: ['10.2'], soc2: ['CC6.1'], nist: ['PR.DS-5'] },
      'CFL-EMAIL-003': { cis: ['10.3'], soc2: ['CC6.1'], nist: ['PR.DS-5'] },
      'CFL-SEC-001': { cis: ['11.1'], soc2: ['CC7.1'], nist: ['ID.RA-1'] },
      'CFL-SEC-002': { cis: ['11.2'], soc2: ['CC7.1'], nist: ['ID.RA-1'] },
      'CFL-TURN-001': { cis: ['4.6'], soc2: ['CC6.1'], pci: ['6.5'], nist: ['PR.IP-1'] },
      'CFL-LOG-001': { cis: ['12.1'], soc2: ['CC7.2'], pci: ['10.1', '10.5'], nist: ['DE.CM-1', 'DE.AE-3'] },
      'CFL-MTLS-001': { cis: ['3.6'], soc2: ['CC6.7'], pci: ['4.1', '8.2'], nist: ['PR.DS-2'] },
      'CFL-MTLS-002': { cis: ['3.7'], soc2: ['CC6.7'], pci: ['4.1'], nist: ['PR.DS-2'] },
      'CFL-ASM-001': { cis: ['11.3'], soc2: ['CC7.1', 'CC7.2'], nist: ['ID.RA-1', 'DE.CM-8'] },
      'CFL-ASM-002': { cis: ['11.4'], soc2: ['CC7.1'], nist: ['ID.RA-1'] },
      'CFL-INSIGHT-001': { cis: ['11.5'], soc2: ['CC7.1'], pci: ['6.5'], nist: ['DE.CM-8'] },
      'CFL-INSIGHT-002': { cis: ['11.6'], soc2: ['CC7.1'], nist: ['DE.CM-8'] },
      'CFL-INSIGHT-003': { cis: ['11.7'], soc2: ['CC7.2'], nist: ['DE.CM-1'] },
      'CFL-INSIGHT-004': { soc2: ['CC6.1', 'CC6.7'], pci: ['8.6'], nist: ['PR.DS-5'] },
      'CFL-INSIGHT-005': { cis: ['2.6'], soc2: ['CC6.6'], nist: ['PR.DS-5'] },
      // New checks
      'CFL-DLP-001': { cis: ['5.7'], soc2: ['CC6.1', 'CC6.7'], pci: ['3.4', '4.2'], nist: ['PR.DS-5'] },
      'CFL-PAGESHIELD-001': { cis: ['4.7'], soc2: ['CC6.1'], pci: ['6.5'], nist: ['PR.IP-1'] },
      'CFL-TUNNEL-001': { cis: ['5.8'], soc2: ['CC6.6'], pci: ['1.3'], nist: ['PR.AC-5'] },
      'CFL-GW-001': { cis: ['5.9'], soc2: ['CC6.6'], pci: ['1.3'], nist: ['PR.AC-5'] },
      'CFL-SPECTRUM-001': { cis: ['9.3'], soc2: ['CC6.1'], nist: ['PR.DS-2'] },
      'CFL-AIGW-001': { soc2: ['CC6.7'], nist: ['PR.DS-5'] },
      'CFL-CDA-001': { cis: ['4.8'], soc2: ['CC6.1'], pci: ['6.5'], nist: ['PR.IP-1'] },
      'CFL-SNIPPET-001': { soc2: ['CC6.1', 'CC8.1'], nist: ['PR.IP-1'] },
      'CFL-CH-001': { cis: ['3.8'], pci: ['4.1'], nist: ['PR.DS-2'] },
      'CFL-ORIGCERT-001': { cis: ['3.9'], soc2: ['CC6.7'], pci: ['4.1', '4.2'], nist: ['PR.DS-2'] },
      'CFL-CFRULE-001': { soc2: ['CC6.1'], nist: ['PR.IP-1'] },
      'CFL-TXRULE-001': { cis: ['4.9'], soc2: ['CC6.1'], pci: ['6.5'], nist: ['PR.IP-1'] },
      'CFL-DEVICE-001': { cis: ['5.10'], soc2: ['CC6.1', 'CC6.3'], pci: ['8.3'], nist: ['PR.AC-3'] }
    };
  }

  mapFindingsToFramework(findings, framework) {
    const frameworkKey = this.getFrameworkKey(framework);
    if (!frameworkKey) {
      throw new Error(`Unknown compliance framework: ${framework}`);
    }

    const controls = {};
    const mappedFindings = [];

    findings.forEach(finding => {
      const mapping = this.mappings[finding.checkId];
      if (!mapping || !mapping[frameworkKey]) return;

      mapping[frameworkKey].forEach(controlId => {
        if (!controls[controlId]) {
          controls[controlId] = { id: controlId, findings: [], passRate: 0 };
        }
        controls[controlId].findings.push(finding);
      });

      mappedFindings.push({
        checkId: finding.checkId,
        controls: mapping[frameworkKey],
        status: finding.status,
        severity: finding.severity
      });
    });

    // Calculate pass rates per control
    Object.values(controls).forEach(control => {
      const total = control.findings.length;
      const passed = control.findings.filter(f => f.status === 'PASS').length;
      control.passRate = total > 0 ? Math.round((passed / total) * 100) : 0;
      control.status = control.passRate >= 80 ? 'pass' : control.passRate >= 50 ? 'partial' : 'fail';
    });

    const allControls = Object.values(controls);
    const totalControls = allControls.length;
    const passedControls = allControls.filter(c => c.status === 'pass').length;

    return {
      framework,
      controls: allControls.sort((a, b) => a.id.localeCompare(b.id)),
      overallScore: totalControls > 0 ? Math.round((passedControls / totalControls) * 100) : 0,
      totalControls,
      passedControls,
      partialControls: allControls.filter(c => c.status === 'partial').length,
      failedControls: allControls.filter(c => c.status === 'fail').length,
      mappedFindings
    };
  }

  getComplianceReport(findings) {
    const frameworks = ['cis', 'soc2', 'pci', 'nist'];
    const report = {};

    frameworks.forEach(fw => {
      try {
        report[fw] = this.mapFindingsToFramework(findings, fw);
      } catch (error) {
        logger.debug(`Compliance mapping failed for ${fw}:`, error.message);
      }
    });

    return report;
  }

  getCheckCompliance(checkId) {
    const mapping = this.mappings[checkId];
    if (!mapping) return { cis: [], soc2: [], pci: [], nist: [] };

    return {
      cis: mapping.cis || [],
      soc2: mapping.soc2 || [],
      pci: mapping.pci || [],
      nist: mapping.nist || []
    };
  }

  getFrameworkChecks(framework) {
    const frameworkKey = this.getFrameworkKey(framework);
    if (!frameworkKey) return [];

    return Object.entries(this.mappings)
      .filter(([_, mapping]) => mapping[frameworkKey] && mapping[frameworkKey].length > 0)
      .map(([checkId, mapping]) => ({
        checkId,
        controls: mapping[frameworkKey]
      }));
  }

  getFrameworkKey(framework) {
    const keyMap = {
      'cis': 'cis',
      'cis-benchmark': 'cis',
      'soc2': 'soc2',
      'soc-2': 'soc2',
      'pci': 'pci',
      'pci-dss': 'pci',
      'nist': 'nist',
      'nist-csf': 'nist'
    };
    return keyMap[framework.toLowerCase()] || null;
  }
}

module.exports = ComplianceEngine;
