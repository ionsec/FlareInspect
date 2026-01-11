/**
 * @fileoverview Cloudflare Security Assessment Service for FlareInspect
 * @description Core assessment logic for Cloudflare security configurations
 * @module core/services/assessmentService
 */

const CloudflareClient = require('./cloudflareClient');
const SecurityBaseline = require('./securityBaseline');
const ReportService = require('./reportService');
const logger = require('../utils/logger');
const { v4: uuidv4 } = require('uuid');
const ora = require('ora');
const chalk = require('chalk');

class AssessmentService {
  constructor(options = {}) {
    this.securityBaseline = new SecurityBaseline();
    this.reportService = new ReportService();
    this.spinner = null;
    this.useSpinner = options.useSpinner !== false;
  }

  startSpinner(text) {
    if (!this.useSpinner) {
      return null;
    }
    return ora({ text, spinner: 'dots' }).start();
  }

  /**
   * Run comprehensive Cloudflare security assessment
   */
  async runAssessment(credentials, options = {}) {
    const assessmentId = options.assessmentId || uuidv4();
    const startTime = Date.now();
    
    logger.assessment('Starting Cloudflare security assessment', {
      assessmentId,
      timestamp: new Date().toISOString()
    });

    this.spinner = this.startSpinner('Initializing Cloudflare API connection...');
    
    try {
      // Initialize Cloudflare client
      const client = new CloudflareClient(credentials.apiToken);
      
      // Test connection
      if (this.spinner) {
        this.spinner.text = 'Testing Cloudflare API connection...';
      }
      const connectionTest = await client.testConnection();
      
      if (!connectionTest.success) {
        throw new Error(`Failed to connect to Cloudflare API: ${connectionTest.error}`);
      }

      if (this.spinner) {
        this.spinner.succeed('Connected to Cloudflare API successfully');
      }
      
      logger.assessment('Cloudflare API connection successful', {
        assessmentId,
        account: connectionTest.account?.name,
        zonesCount: connectionTest.zonesCount
      });

      // Get account and zones
      const account = connectionTest.account;
      const zones = await client.getZones();
      
      console.log(chalk.cyan(`\nFound ${zones.length} zones to assess:`));
      zones.forEach(zone => {
        console.log(chalk.gray(`  • ${zone.name} (${zone.plan?.name || 'Free'} plan)`));
      });
      console.log();

      // Initialize assessment results
      const assessment = {
        assessmentId,
        provider: 'cloudflare',
        startedAt: new Date(startTime),
        status: 'running',
        metadata: {
          note: options.note || null,
          totalApiCalls: 0
        },
        account: {
          id: account.id,
          name: account.name,
          type: account.type
        },
        zones: zones.map(zone => ({
          id: zone.id,
          name: zone.name,
          status: zone.status,
          plan: zone.plan?.name || 'Free'
        })),
        findings: [],
        summary: {
          total: 0,
          passed: 0,
          failed: 0,
          warnings: 0,
          bySeverity: {
            critical: 0,
            high: 0,
            medium: 0,
            low: 0,
            informational: 0
          }
        },
        configuration: {
          account: {},
          zones: {},
          zeroTrust: {},
          dns: {},
          waf: {},
          ssl: {},
          apiGateway: {},
          securityTxt: {},
          logpush: {},
          mtls: {},
          attackSurface: {},
          turnstile: {},
          dnsFirewall: {}
        }
      };

      // Run account-level assessments
      this.spinner = this.startSpinner('Assessing account-level configurations...');
      await this.assessAccount(client, account, assessment);
      if (this.spinner) {
        this.spinner.succeed('Account assessment completed');
      }

      // Run zone-level assessments for each zone
      const zoneCount = zones.length;
      for (let i = 0; i < zoneCount; i++) {
        const zone = zones[i];
        this.spinner = this.startSpinner(`Assessing zone ${i + 1}/${zoneCount}: ${zone.name}...`);
        await this.assessZone(client, zone, assessment);
        if (this.spinner) {
          this.spinner.succeed(`Zone ${zone.name} assessed`);
        }
      }

      // Calculate final summary
      logger.info('Calculating assessment summary');
      this.calculateSummary(assessment);

      // Calculate security score
      const score = this.securityBaseline.calculateScore(assessment.findings);
      assessment.score = score;

      // Generate comprehensive report
      logger.info('Generating comprehensive assessment report');
      assessment.report = this.reportService.generateReport(assessment);

      // Mark assessment as completed
      assessment.status = 'completed';
      assessment.completedAt = new Date();
      assessment.executionTime = Date.now() - startTime;
      assessment.metadata.totalApiCalls = client.requestCount;

      logger.assessment('Cloudflare security assessment completed', {
        assessmentId,
        duration: assessment.executionTime,
        totalFindings: assessment.findings.length,
        failedChecks: assessment.summary.failed
      });

      return assessment;

    } catch (error) {
      if (this.spinner) {
        this.spinner.fail('Assessment failed');
      }
      
      logger.error('Assessment failed', {
        assessmentId,
        error: error.message,
        stack: error.stack
      });

      return {
        assessmentId,
        provider: 'cloudflare',
        status: 'failed',
        error: error.message,
        startedAt: new Date(startTime),
        completedAt: new Date(),
        executionTime: Date.now() - startTime,
        metadata: {
          note: options.note || null
        }
      };
    }
  }

  /**
   * Assess account-level configurations
   */
  async assessAccount(client, account, assessment) {
    logger.assessment('Assessing account-level configurations', {
      assessmentId: assessment.assessmentId,
      accountId: account.id
    });

    try {
      // Get account members and audit logs
      const [
        members,
        auditLogs,
        zeroTrustSettings,
        workers,
        pages,
        securityInsights,
        turnstileWidgets,
        dnsFirewallRules,
        logpushJobs,
        accessCertificates,
        mtlsCertificates,
        attackSurface
      ] = await Promise.all([
        client.getAccountMembers(account.id),
        client.getAuditLogs(account.id, { 
          since: new Date(Date.now() - 30 * 24 * 60 * 60 * 1000).toISOString()
        }),
        client.getZeroTrustSettings(account.id),
        client.getWorkers ? client.getWorkers(account.id).catch(() => ({ workers: [] })) : { workers: [] },
        client.getPages ? client.getPages(account.id).catch(() => ({ projects: [] })) : { projects: [] },
        client.getSecurityInsights({ accountId: account.id }).catch(e => {
          logger.debug('Failed to get account security insights:', e.message);
          return { insights: [], error: e.message };
        }),
        client.getTurnstileWidgets ? client.getTurnstileWidgets(account.id) : [],
        client.getDNSFirewall ? client.getDNSFirewall(account.id) : [],
        client.getLogpushJobs ? client.getLogpushJobs({ accountId: account.id }) : [],
        client.getAccessCertificates ? client.getAccessCertificates({ accountId: account.id }) : [],
        client.getMtlsCertificates ? client.getMtlsCertificates({ accountId: account.id }) : [],
        client.getAttackSurfaceIssues ? client.getAttackSurfaceIssues(account.id) : { issues: [], count: 0 }
      ]);

      // Store configuration data
      assessment.configuration.account = {
        id: account.id,
        name: account.name,
        members: members.length,
        auditLogsAvailable: auditLogs.length > 0,
        zeroTrustEnabled: !zeroTrustSettings.error,
        workersCount: workers?.workers?.length || 0,
        pagesProjectsCount: pages?.projects?.length || 0,
        securityInsights: securityInsights.summary || { total: 0 },
        turnstileWidgetsCount: turnstileWidgets?.length || 0,
        dnsFirewallRulesCount: dnsFirewallRules?.length || 0,
        logpushJobsCount: logpushJobs?.length || 0,
        accessCertificatesCount: accessCertificates?.length || 0,
        mtlsCertificatesCount: mtlsCertificates?.length || 0,
        attackSurfaceIssuesCount: attackSurface?.count || 0
      };
      assessment.configuration.zeroTrust = zeroTrustSettings;
      assessment.configuration.securityInsights = {
        account: securityInsights
      };
      assessment.configuration.turnstile = {
        account: {
          widgets: turnstileWidgets || []
        }
      };
      assessment.configuration.dnsFirewall = {
        account: {
          rules: dnsFirewallRules || []
        }
      };
      assessment.configuration.logpush = {
        account: {
          jobs: logpushJobs || []
        }
      };
      assessment.configuration.mtls = {
        account: {
          accessCertificates: accessCertificates || [],
          mtlsCertificates: mtlsCertificates || []
        }
      };
      assessment.configuration.attackSurface = {
        account: attackSurface || { issues: [], count: 0 }
      };

      // Run account security checks
      await this.checkAccountSecurity(account, members, auditLogs, assessment);
      
      // Check Zero Trust
      if (!zeroTrustSettings.error) {
        // Zero Trust is enabled - assess it
        await this.assessZeroTrust(zeroTrustSettings, assessment);
      } else {
        // Add finding for missing Zero Trust
        assessment.findings.push({
          id: uuidv4(),
          checkId: 'cf-account-001',
          checkTitle: 'Zero Trust Not Enabled',
          service: 'account',
          severity: 'medium',
          status: 'FAIL',
          description: 'Cloudflare Zero Trust is not enabled for this account, missing advanced security capabilities.',
          remediation: 'Consider enabling Cloudflare Zero Trust to protect applications and networks with identity-based security.',
          resourceId: account.id,
          resourceType: 'account',
          timestamp: new Date(),
          metadata: {
            accountName: account.name,
            recommendation: 'Enable Zero Trust for enhanced security posture'
          }
        });
      }

      // Assess Workers if available
      if (workers?.workers && workers.workers.length > 0) {
        await this.assessWorkers(workers.workers, assessment);
      }

      // Assess Pages if available
      if (pages?.projects && pages.projects.length > 0) {
        await this.assessPages(pages.projects, assessment);
      }

      // Assess Security Insights
      if (securityInsights && !securityInsights.error) {
        await this.assessSecurityInsights(securityInsights, 'account', account.id, assessment);
      }

      await this.assessTurnstile(account, turnstileWidgets || [], assessment);
      await this.assessDNSFirewall(account, dnsFirewallRules || [], assessment);
      await this.assessLogpush(account, logpushJobs || [], 'account', assessment);
      await this.assessMtls({ ...account, type: 'account' }, {
        accessCertificates: accessCertificates || [],
        mtlsCertificates: mtlsCertificates || []
      }, assessment);
      await this.assessAttackSurface(account, attackSurface || { issues: [], count: 0 }, assessment);

    } catch (error) {
      logger.error('Account assessment failed', {
        assessmentId: assessment.assessmentId,
        error: error.message
      });
    }
  }

  /**
   * Assess zone-level configurations
   */
  async assessZone(client, zone, assessment) {
    logger.assessment('Assessing zone configurations', {
      assessmentId: assessment.assessmentId,
      zoneName: zone.name,
      zoneId: zone.id
    });

    try {
      // Get zone configuration data
      const [
        zoneDetails, 
        dnsRecords, 
        dnssecSettings, 
        sslSettings, 
        wafSettings, 
        analytics,
        allZoneSettings,
        firewallRules,
        accessRules,
        pageRules,
        rateLimitingRules,
        performanceSettings,
        botManagement,
        apiShield,
        loadBalancers,
        emailRoutingRules,
        securityInsights,
        apiGateway,
        securityTxt,
        logpushJobs,
        accessCertificates,
        rulesets
      ] = await Promise.all([
        client.getZone(zone.id),
        client.getDNSRecords(zone.id),
        client.getDNSSECSettings(zone.id),
        client.getSSLSettings(zone.id),
        client.getWAFSettings(zone.id),
        client.getSecurityAnalytics(zone.id),
        client.getAllZoneSettings(zone.id),
        client.getFirewallRules(zone.id),
        client.getAccessRules(zone.id),
        client.getPageRules(zone.id),
        client.getRateLimitingRules(zone.id),
        client.getPerformanceSettings(zone.id),
        client.getBotManagement(zone.id),
        client.getAPIShield(zone.id),
        client.getLoadBalancers(zone.id, assessment.account.id),
        client.getEmailRoutingRules(zone.id),
        client.getSecurityInsights({ zoneId: zone.id }).catch(e => {
          logger.debug('Failed to get zone security insights:', e.message);
          return { insights: [], error: e.message };
        }),
        client.getApiGateway ? client.getApiGateway(zone.id) : null,
        client.getSecurityTxt ? client.getSecurityTxt(zone.id) : null,
        client.getLogpushJobs ? client.getLogpushJobs({ zoneId: zone.id }) : [],
        client.getAccessCertificates ? client.getAccessCertificates({ zoneId: zone.id }) : [],
        client.getRulesets ? client.getRulesets(zone.id) : []
      ]);

      // Store configuration data
      assessment.configuration.zones[zone.name] = {
        details: zoneDetails,
        dnsRecords: dnsRecords.length,
        dnssecEnabled: dnssecSettings?.status === 'active' || dnssecSettings?.status === 'pending',
        dnssecStatus: dnssecSettings?.status || 'unknown',
        sslMode: sslSettings?.settings?.value,
        certificatesCount: sslSettings?.certificates?.length || 0,
        customCertificatesCount: sslSettings?.customCertificates?.length || 0,
        firewallRules: firewallRules.length,
        accessRules: accessRules.length,
        pageRules: pageRules.length,
        rateLimitingRules: rateLimitingRules.length,
        settings: allZoneSettings,
        securityLevel: allZoneSettings?.security_level?.value || 'unknown',
        alwaysUseHttps: allZoneSettings?.always_use_https?.value || false,
        minTlsVersion: allZoneSettings?.min_tls_version?.value || '1.0',
        hsts: allZoneSettings?.security_header?.value?.strict_transport_security || {},
        performanceSettings: performanceSettings || {},
        botManagementEnabled: botManagement?.enabled || false,
        apiShieldEnabled: apiShield?.enabled || false,
        apiGatewayEnabled: apiGateway?.enabled || false,
        loadBalancersCount: loadBalancers?.load_balancers?.length || 0,
        emailRoutingRulesCount: emailRoutingRules?.length || 0,
        securityInsights: securityInsights.summary || { total: 0 },
        securityTxtEnabled: securityTxt?.enabled || false,
        logpushJobsCount: logpushJobs?.length || 0,
        accessCertificatesCount: accessCertificates?.length || 0,
        rulesetsCount: rulesets?.length || 0
      };
      
      // Store zone security insights separately
      if (!assessment.configuration.securityInsights.zones) {
        assessment.configuration.securityInsights.zones = {};
      }
      assessment.configuration.securityInsights.zones[zone.name] = securityInsights;

      assessment.configuration.apiGateway[zone.name] = apiGateway || {};
      assessment.configuration.securityTxt[zone.name] = securityTxt || {};
      assessment.configuration.logpush[zone.name] = { jobs: logpushJobs || [] };
      assessment.configuration.mtls[zone.name] = { accessCertificates: accessCertificates || [] };
      assessment.configuration.waf[zone.name] = {
        rulesets: rulesets || []
      };

      // Run security assessments
      await this.assessDNSSecurity(zone, dnsRecords, dnssecSettings, assessment);
      await this.assessSSLSecurity(zone, sslSettings, assessment, allZoneSettings);
      await this.assessWAFSecurity(zone, {
        ...wafSettings,
        firewallRules,
        accessRules,
        rateLimitingRules,
        securityLevel: allZoneSettings?.security_level,
        rulesets: rulesets || []
      }, assessment);
      
      // Run new assessments
      await this.assessPerformance(zone, performanceSettings, allZoneSettings, assessment);
      if (botManagement) {
        await this.assessBotManagement(zone, botManagement, assessment);
      }
      if (apiShield?.source === 'legacy') {
        await this.assessAPIShield(zone, apiShield, assessment);
      }
      if (apiGateway) {
        await this.assessAPIGateway(zone, apiGateway, assessment);
      }
      if (loadBalancers) {
        await this.assessLoadBalancing(zone, loadBalancers, assessment);
      }
      if (emailRoutingRules && emailRoutingRules.length > 0) {
        await this.assessEmailRouting(zone, emailRoutingRules, dnsRecords, assessment);
      }
      await this.assessSecurityTxt(zone, securityTxt, assessment);
      await this.assessLogpush(zone, logpushJobs || [], 'zone', assessment);
      await this.assessMtls({ ...zone, type: 'zone' }, { accessCertificates: accessCertificates || [] }, assessment);
      
      // Assess Security Insights
      if (securityInsights && !securityInsights.error) {
        await this.assessSecurityInsights(securityInsights, 'zone', zone.id, assessment);
      }

      // Run general zone security checks
      await this.checkZoneSecurity(zone, zoneDetails, analytics, assessment, allZoneSettings);

    } catch (error) {
      logger.error('Zone assessment failed', {
        assessmentId: assessment.assessmentId,
        zoneName: zone.name,
        error: error.message
      });
    }
  }

  /**
   * Check account-level security configurations
   */
  async checkAccountSecurity(account, members, auditLogs, assessment) {
    const findings = [];
    const accountChecks = this.securityBaseline.getChecksByCategory('account');

    // Check 1: MFA Enforcement
    const mfaCheck = accountChecks.find(c => c.id === 'CFL-ACC-001');
    
    const membersWithoutMfa = members.filter(member => {
      const user = member.user || {};
      const hasMFA = user.two_factor_authentication_enabled || 
                     user.two_factor_auth_enabled || 
                     user.mfa_enabled || 
                     user.two_factor_enabled ||
                     user.twoFactorEnabled ||
                     member.two_factor_authentication_enabled || 
                     member.two_factor_auth_enabled || 
                     member.mfa_enabled || 
                     member.two_factor_enabled ||
                     member.twoFactorEnabled;
      return !hasMFA;
    });
    
    if (membersWithoutMfa.length > 0) {
      findings.push(this.securityBaseline.createFinding(
        mfaCheck,
        'FAIL',
        `${membersWithoutMfa.length} members without MFA`,
        'All members with MFA enabled',
        { id: account.id, type: 'account', name: account.name }
      ));
    } else {
      findings.push(this.securityBaseline.createFinding(
        mfaCheck,
        'PASS',
        'All members have MFA enabled',
        'All members with MFA enabled',
        { id: account.id, type: 'account', name: account.name }
      ));
    }

    // Check 2: Admin Access Control
    const adminCheck = accountChecks.find(c => c.id === 'CFL-ACC-003');
    const adminUsers = members.filter(member => 
      member.roles?.some(role => role.name?.toLowerCase().includes('admin'))
    );
    
    if (adminUsers.length > 3) {
      findings.push(this.securityBaseline.createFinding(
        adminCheck,
        'FAIL',
        `${adminUsers.length} admin users`,
        '3 or fewer admin users',
        { id: account.id, type: 'account', name: account.name }
      ));
    } else {
      findings.push(this.securityBaseline.createFinding(
        adminCheck,
        'PASS',
        `${adminUsers.length} admin users`,
        '3 or fewer admin users',
        { id: account.id, type: 'account', name: account.name }
      ));
    }

    // Check 3: Audit Log Monitoring
    const auditLogCheck = accountChecks.find(c => c.id === 'CFL-ACC-004');
    
    if (auditLogs.length === 0) {
      findings.push(this.securityBaseline.createFinding(
        auditLogCheck,
        'FAIL',
        'Audit logs not available',
        'Audit logs enabled and monitored',
        { id: account.id, type: 'account', name: account.name }
      ));
    } else {
      findings.push(this.securityBaseline.createFinding(
        auditLogCheck,
        'PASS',
        `Audit logs available (${auditLogs.length} recent events)`,
        'Audit logs enabled and monitored',
        { id: account.id, type: 'account', name: account.name }
      ));
    }

    assessment.findings.push(...findings);
  }

  /**
   * Assess DNS security configurations
   */
  async assessDNSSecurity(zone, dnsRecords, dnssecSettings, assessment) {
    const findings = [];
    const dnsChecks = this.securityBaseline.getChecksByCategory('dns');

    // Check DNSSEC
    const dnssecCheck = dnsChecks.find(c => c.id === 'CFL-DNS-001');
    
    // Debug DNSSEC status
    logger.debug('DNSSEC status check', {
      zone: zone.name,
      status: dnssecSettings?.status,
      fullSettings: dnssecSettings
    });
    
    if (dnssecSettings?.status === 'active' || dnssecSettings?.status === 'pending') {
      findings.push(this.securityBaseline.createFinding(
        dnssecCheck,
        'PASS',
        `DNSSEC is ${dnssecSettings.status}`,
        'DNSSEC enabled',
        { id: zone.id, type: 'zone', name: zone.name }
      ));
    } else {
      findings.push(this.securityBaseline.createFinding(
        dnssecCheck,
        'FAIL',
        `DNSSEC is ${dnssecSettings?.status || 'not active'}`,
        'Enable DNSSEC for enhanced DNS security',
        { id: zone.id, type: 'zone', name: zone.name }
      ));
    }

    // Check for wildcard DNS records
    const wildcardRecords = dnsRecords.filter(record => record.name.includes('*'));
    if (wildcardRecords.length > 0) {
      findings.push({
        id: uuidv4(),
        checkId: 'CFL-DNS-003',
        checkTitle: 'Wildcard DNS Records',
        service: 'dns',
        severity: 'low',
        status: 'WARNING',
        description: `${wildcardRecords.length} wildcard DNS records found. Review for necessity.`,
        remediation: 'Limit wildcard records to minimize attack surface.',
        resourceId: zone.id,
        resourceType: 'zone',
        timestamp: new Date(),
        metadata: {
          zoneName: zone.name,
          wildcardCount: wildcardRecords.length
        }
      });
    }

    assessment.findings.push(...findings);
  }

  /**
   * Assess SSL/TLS security configurations
   */
  async assessSSLSecurity(zone, sslSettings, assessment, zoneSettings) {
    const findings = [];
    const sslChecks = this.securityBaseline.getChecksByCategory('ssl');

    // Check SSL mode
    const sslMode = sslSettings?.settings?.value || 'off';
    const sslModeCheck = sslChecks.find(c => c.id === 'CFL-SSL-001');
    
    if (sslMode === 'full' || sslMode === 'strict') {
      findings.push(this.securityBaseline.createFinding(
        sslModeCheck,
        'PASS',
        `SSL mode is ${sslMode}`,
        'Full or Strict SSL mode',
        { id: zone.id, type: 'zone', name: zone.name }
      ));
    } else {
      findings.push(this.securityBaseline.createFinding(
        sslModeCheck,
        'FAIL',
        `SSL mode is ${sslMode}`,
        'Use Full or Strict SSL mode for better security',
        { id: zone.id, type: 'zone', name: zone.name }
      ));
    }

    // Check minimum TLS version
    const minTLSVersion = zoneSettings?.min_tls_version?.value || '1.0';
    const tlsVersionCheck = sslChecks.find(c => c.id === 'CFL-SSL-002');
    
    if (minTLSVersion === '1.2' || minTLSVersion === '1.3') {
      findings.push(this.securityBaseline.createFinding(
        tlsVersionCheck,
        'PASS',
        `Minimum TLS version is ${minTLSVersion}`,
        'TLS 1.2 or higher',
        { id: zone.id, type: 'zone', name: zone.name }
      ));
    } else {
      findings.push(this.securityBaseline.createFinding(
        tlsVersionCheck,
        'FAIL',
        `Minimum TLS version is ${minTLSVersion}`,
        'Set minimum TLS version to 1.2 or higher',
        { id: zone.id, type: 'zone', name: zone.name }
      ));
    }

    // Check HSTS
    const hsts = zoneSettings?.security_header?.value?.strict_transport_security;
    const hstsCheck = sslChecks.find(c => c.id === 'CFL-SSL-004');
    
    if (hsts?.enabled) {
      findings.push(this.securityBaseline.createFinding(
        hstsCheck,
        'PASS',
        'HSTS is enabled',
        'HSTS enabled with appropriate settings',
        { id: zone.id, type: 'zone', name: zone.name }
      ));
    } else {
      findings.push(this.securityBaseline.createFinding(
        hstsCheck,
        'FAIL',
        'HSTS is not enabled',
        'Enable HSTS to prevent protocol downgrade attacks',
        { id: zone.id, type: 'zone', name: zone.name }
      ));
    }

    assessment.findings.push(...findings);
  }

  /**
   * Assess WAF security configurations
   */
  async assessWAFSecurity(zone, wafData, assessment) {
    const findings = [];
    const wafChecks = this.securityBaseline.getChecksByCategory('waf');
    const rulesets = wafData.rulesets || [];

    // Check security level
    const securityLevel = wafData.securityLevel?.value || 'medium';
    if (securityLevel === 'essentially_off' || securityLevel === 'low') {
      findings.push({
        id: uuidv4(),
        checkId: 'CFL-WAF-001',
        checkTitle: 'Low Security Level',
        service: 'waf',
        severity: 'high',
        status: 'FAIL',
        description: `Security level is set to "${securityLevel}". This provides minimal protection.`,
        remediation: 'Set security level to "Medium" or "High" for better protection.',
        resourceId: zone.id,
        resourceType: 'zone',
        timestamp: new Date(),
        metadata: {
          zoneName: zone.name,
          currentLevel: securityLevel
        }
      });
    }

    // Check firewall rules
    if (wafData.firewallRules.length === 0 && zone.plan?.name !== 'Free') {
      findings.push({
        id: uuidv4(),
        checkId: 'CFL-WAF-002',
        checkTitle: 'No Custom Firewall Rules',
        service: 'waf',
        severity: 'medium',
        status: 'WARNING',
        description: 'No custom firewall rules configured.',
        remediation: 'Consider adding custom firewall rules for enhanced protection.',
        resourceId: zone.id,
        resourceType: 'zone',
        timestamp: new Date(),
        metadata: {
          zoneName: zone.name
        }
      });
    }

    // Check rate limiting
    const hasRateLimitingRuleset = rulesets.some(rs =>
      rs.phase === 'http_ratelimit' || rs.phase === 'http_request_rate_limit'
    );
    if (wafData.rateLimitingRules.length === 0 && !hasRateLimitingRuleset) {
      findings.push({
        id: uuidv4(),
        checkId: 'CFL-WAF-003',
        checkTitle: 'No Rate Limiting Rules',
        service: 'waf',
        severity: 'medium',
        status: 'WARNING',
        description: 'No rate limiting rules configured.',
        remediation: 'Implement rate limiting to protect against abuse and DDoS attacks.',
        resourceId: zone.id,
        resourceType: 'zone',
        timestamp: new Date(),
        metadata: {
          zoneName: zone.name
        }
      });
    }

    // Check managed rulesets (OWASP/managed WAF)
    const managedRulesets = rulesets.filter(rs => rs.phase === 'http_request_firewall_managed');
    if (managedRulesets.length === 0) {
      findings.push(this.securityBaseline.createFinding(
        wafChecks.find(c => c.id === 'CFL-WAF-005'),
        'FAIL',
        'Managed WAF rulesets not enabled',
        'Enable managed WAF rulesets (OWASP) for HTTP traffic',
        { id: zone.id, type: 'zone', name: zone.name }
      ));
    }

    assessment.findings.push(...findings);
  }

  async assessAPIGateway(zone, apiGateway, assessment) {
    const findings = [];

    if (!apiGateway?.enabled) {
      findings.push({
        id: uuidv4(),
        checkId: 'CFL-API-001',
        checkTitle: 'API Gateway Not Configured',
        service: 'api',
        severity: 'medium',
        status: 'WARNING',
        description: 'API Gateway (API Shield) is not configured to protect API endpoints.',
        remediation: 'Enable API Gateway and configure discovery and schema validation.',
        resourceId: zone.id,
        resourceType: 'zone',
        timestamp: new Date(),
        metadata: {
          zoneName: zone.name
        }
      });
    } else if ((apiGateway.schemas || []).length === 0) {
      findings.push({
        id: uuidv4(),
        checkId: 'CFL-API-002',
        checkTitle: 'No API Schemas Configured',
        service: 'api',
        severity: 'low',
        status: 'WARNING',
        description: 'API Gateway is enabled but no schemas are configured for validation.',
        remediation: 'Upload OpenAPI schemas to enable request validation.',
        resourceId: zone.id,
        resourceType: 'zone',
        timestamp: new Date(),
        metadata: {
          zoneName: zone.name,
          operationsDiscovered: apiGateway.discoveryOperations?.length || 0
        }
      });
    }

    assessment.findings.push(...findings);
  }

  async assessSecurityTxt(zone, securityTxt, assessment) {
    const findings = [];
    if (securityTxt?.error) {
      return;
    }
    const enabled = securityTxt?.enabled;
    const contacts = securityTxt?.contact || [];
    const policies = securityTxt?.policy || [];
    const expires = securityTxt?.expires || null;

    const enabledCheck = this.securityBaseline.getChecksByCategory('securitytxt')
      .find(c => c.id === 'CFL-SEC-001');
    const fieldsCheck = this.securityBaseline.getChecksByCategory('securitytxt')
      .find(c => c.id === 'CFL-SEC-002');

    if (!enabled) {
      findings.push(this.securityBaseline.createFinding(
        enabledCheck,
        'FAIL',
        'security.txt not enabled',
        'security.txt enabled with contact and expiry',
        { id: zone.id, type: 'zone', name: zone.name }
      ));
    } else {
      findings.push(this.securityBaseline.createFinding(
        enabledCheck,
        'PASS',
        'security.txt enabled',
        'security.txt enabled with contact and expiry',
        { id: zone.id, type: 'zone', name: zone.name }
      ));
    }

    const hasRequired = contacts.length > 0 && policies.length > 0 && Boolean(expires);
    if (!hasRequired) {
      findings.push(this.securityBaseline.createFinding(
        fieldsCheck,
        'FAIL',
        'Missing required fields in security.txt',
        'Contact, policy, and expires fields configured',
        { id: zone.id, type: 'zone', name: zone.name }
      ));
    } else {
      findings.push(this.securityBaseline.createFinding(
        fieldsCheck,
        'PASS',
        'Required fields present in security.txt',
        'Contact, policy, and expires fields configured',
        { id: zone.id, type: 'zone', name: zone.name }
      ));
    }

    assessment.findings.push(...findings);
  }

  async assessTurnstile(account, widgets, assessment) {
    const findings = [];
    const check = this.securityBaseline.getChecksByCategory('turnstile')
      .find(c => c.id === 'CFL-TURN-001');

    if ((widgets || []).length === 0) {
      findings.push(this.securityBaseline.createFinding(
        check,
        'WARNING',
        'No Turnstile widgets configured',
        'Turnstile widgets configured for protected applications',
        { id: account.id, type: 'account', name: account.name }
      ));
    } else {
      findings.push(this.securityBaseline.createFinding(
        check,
        'PASS',
        `${widgets.length} Turnstile widgets configured`,
        'Turnstile widgets configured for protected applications',
        { id: account.id, type: 'account', name: account.name }
      ));
    }

    assessment.findings.push(...findings);
  }

  async assessDNSFirewall(account, dnsFirewallRules, assessment) {
    const findings = [];
    const check = this.securityBaseline.getChecksByCategory('dns-firewall')
      .find(c => c.id === 'CFL-DNS-005');

    if ((dnsFirewallRules || []).length === 0) {
      findings.push(this.securityBaseline.createFinding(
        check,
        'WARNING',
        'No DNS Firewall policies configured',
        'DNS Firewall policies configured for upstream resolver protection',
        { id: account.id, type: 'account', name: account.name }
      ));
    } else {
      findings.push(this.securityBaseline.createFinding(
        check,
        'PASS',
        `${dnsFirewallRules.length} DNS Firewall policies configured`,
        'DNS Firewall policies configured for upstream resolver protection',
        { id: account.id, type: 'account', name: account.name }
      ));
    }

    assessment.findings.push(...findings);
  }

  async assessLogpush(resource, logpushJobs, scope, assessment) {
    const findings = [];
    const check = this.securityBaseline.getChecksByCategory('logpush')
      .find(c => c.id === 'CFL-LOG-001');
    const datasets = (logpushJobs || []).map(job => job.dataset).filter(Boolean);
    const hasSecurityDataset = datasets.some(dataset =>
      /firewall|http|dns|spectrum|audit|waf/i.test(dataset)
    );

    if (logpushJobs.length === 0 || !hasSecurityDataset) {
      findings.push(this.securityBaseline.createFinding(
        check,
        'WARNING',
        'No security-focused Logpush datasets configured',
        'Logpush configured for security datasets (firewall, HTTP, DNS)',
        { id: resource.id, type: scope, name: resource.name }
      ));
    } else {
      findings.push(this.securityBaseline.createFinding(
        check,
        'PASS',
        `Security Logpush datasets configured (${datasets.length} datasets)`,
        'Logpush configured for security datasets (firewall, HTTP, DNS)',
        { id: resource.id, type: scope, name: resource.name }
      ));
    }

    assessment.findings.push(...findings);
  }

  async assessMtls(resource, mtlsData, assessment) {
    const findings = [];
    const certificates = mtlsData?.accessCertificates || [];
    const mtlsCertificates = mtlsData?.mtlsCertificates || [];
    const check = this.securityBaseline.getChecksByCategory('mtls')
      .find(c => c.id === 'CFL-MTLS-001');
    const expiryCheck = this.securityBaseline.getChecksByCategory('mtls')
      .find(c => c.id === 'CFL-MTLS-002');

    const totalCerts = certificates.length + mtlsCertificates.length;
    if (totalCerts === 0) {
      findings.push(this.securityBaseline.createFinding(
        check,
        'WARNING',
        'No mTLS/Access certificates configured',
        'mTLS certificates configured for sensitive services',
        { id: resource.id, type: resource.type || 'account', name: resource.name }
      ));
    } else {
      findings.push(this.securityBaseline.createFinding(
        check,
        'PASS',
        `${totalCerts} mTLS/Access certificates configured`,
        'mTLS certificates configured for sensitive services',
        { id: resource.id, type: resource.type || 'account', name: resource.name }
      ));
    }

    const expiringSoon = [...certificates, ...mtlsCertificates].filter(cert => {
      const expiry = cert.expires_on || cert.expiresOn || cert.not_after || cert.notAfter;
      if (!expiry) return false;
      const expiryDate = new Date(expiry);
      if (Number.isNaN(expiryDate.getTime())) return false;
      const days = (expiryDate.getTime() - Date.now()) / (1000 * 60 * 60 * 24);
      return days < 30;
    });

    if (expiringSoon.length > 0) {
      findings.push(this.securityBaseline.createFinding(
        expiryCheck,
        'FAIL',
        `${expiringSoon.length} certificates expiring within 30 days`,
        'No mTLS certificates expiring within 30 days',
        { id: resource.id, type: resource.type || 'account', name: resource.name }
      ));
    } else {
      findings.push(this.securityBaseline.createFinding(
        expiryCheck,
        'PASS',
        'No mTLS certificates expiring soon',
        'No mTLS certificates expiring within 30 days',
        { id: resource.id, type: resource.type || 'account', name: resource.name }
      ));
    }

    assessment.findings.push(...findings);
  }

  async assessAttackSurface(account, attackSurface, assessment) {
    const findings = [];
    const issues = attackSurface?.issues || [];
    if (issues.length === 0) {
      return;
    }

    const criticalIssues = issues.filter(issue => issue.severity === 'Critical');
    const moderateIssues = issues.filter(issue => issue.severity === 'Moderate');
    const lowIssues = issues.filter(issue => issue.severity === 'Low');

    const criticalCheck = this.securityBaseline.getChecksByCategory('attack-surface')
      .find(c => c.id === 'CFL-ASM-001');
    const moderateCheck = this.securityBaseline.getChecksByCategory('attack-surface')
      .find(c => c.id === 'CFL-ASM-002');

    if (criticalIssues.length > 0) {
      findings.push(this.securityBaseline.createFinding(
        criticalCheck,
        'FAIL',
        `${criticalIssues.length} critical attack surface issues`,
        'No critical attack surface issues',
        { id: account.id, type: 'account', name: account.name }
      ));
    }

    if (moderateIssues.length > 0 || lowIssues.length > 0) {
      findings.push(this.securityBaseline.createFinding(
        moderateCheck,
        'WARNING',
        `${moderateIssues.length + lowIssues.length} moderate/low attack surface issues`,
        'Minimize moderate/low attack surface issues',
        { id: account.id, type: 'account', name: account.name }
      ));
    }

    assessment.findings.push(...findings);
  }

  /**
   * Assess Zero Trust configurations
   */
  async assessZeroTrust(zeroTrustData, assessment) {
    const findings = [];

    // Check identity providers
    if (zeroTrustData.identityProviders?.length === 0) {
      findings.push({
        id: uuidv4(),
        checkId: "CFL-ZT-001",
        checkTitle: "No Identity Providers Configured",
        service: "zerotrust",
        severity: "high",
        status: "FAIL",
        description: "No identity providers configured for Zero Trust.",
        remediation: "Configure at least one identity provider for authentication.",
        resourceId: assessment.account.id,
        resourceType: "account",
        timestamp: new Date()
      });
    }

    // Check applications
    if (zeroTrustData.applications?.length > 0) {
      const appsWithoutPolicies = zeroTrustData.applications.filter(app => {
        const appPolicies = zeroTrustData.policies?.filter(p => p.application_id === app.id) || [];
        return appPolicies.length === 0;
      });

      if (appsWithoutPolicies.length > 0) {
        findings.push({
          id: uuidv4(),
          checkId: "CFL-ZT-002",
          checkTitle: "Applications Without Access Policies",
          service: "zerotrust",
          severity: "high",
          status: "FAIL",
          description: `${appsWithoutPolicies.length} Zero Trust applications have no access policies configured. Applications: ${appsWithoutPolicies.map(a => a.name).join(', ')}.`,
          remediation: `Configure access policies for these applications in Zero Trust > Access > Applications: ${appsWithoutPolicies.map(a => a.name).join(', ')}.`,
          resourceId: assessment.account.id,
          resourceType: "account",
          resourceName: assessment.account.name,
          timestamp: new Date(),
          metadata: {
            accountName: assessment.account.name,
            applicationsWithoutPolicies: appsWithoutPolicies.map(a => a.name),
            applicationsCount: appsWithoutPolicies.length
          }
        });
      }
    }

    // Check device enrollment rules
    if (zeroTrustData.deviceEnrollmentRules?.length === 0) {
      findings.push({
        id: uuidv4(),
        checkId: "CFL-ZT-003",
        checkTitle: "No Device Enrollment Rules Configured",
        service: "zerotrust",
        severity: "medium",
        status: "FAIL",
        description: `No device enrollment rules configured for Zero Trust account "${assessment.account.name}". This allows any device to potentially access Zero Trust protected resources.`,
        remediation: "Configure device enrollment rules in Zero Trust > Settings > Device enrollment to control which devices can access your network.",
        resourceId: assessment.account.id,
        resourceType: "account",
        resourceName: assessment.account.name,
        timestamp: new Date(),
        metadata: {
          accountName: assessment.account.name,
          recommendation: "Enable device enrollment to improve security posture"
        }
      });
    }

    // Check Gateway settings
    if (zeroTrustData.gatewaySettings && zeroTrustData.gatewaySettings.rules?.length === 0) {
      findings.push({
        id: uuidv4(),
        checkId: "CFL-ZT-004",
        checkTitle: "No Gateway Rules Configured",
        service: "zerotrust",
        severity: "medium",
        status: "FAIL",
        description: "No Gateway filtering rules configured.",
        remediation: "Configure Gateway rules to filter and secure network traffic.",
        resourceId: assessment.account.id,
        resourceType: "account",
        timestamp: new Date()
      });
    }

    // Check DLP settings
    if (zeroTrustData.dlpSettings && zeroTrustData.dlpSettings.profiles?.length === 0) {
      findings.push({
        id: uuidv4(),
        checkId: "CFL-ZT-005",
        checkTitle: "No DLP Profiles Configured",
        service: "zerotrust",
        severity: "medium",
        status: "FAIL",
        description: "No Data Loss Prevention profiles configured.",
        remediation: "Configure DLP profiles to prevent sensitive data leakage.",
        resourceId: assessment.account.id,
        resourceType: "account",
        timestamp: new Date()
      });
    }

    // Check service token rotation
    if (zeroTrustData.serviceTokens?.length > 0) {
      const oldTokens = zeroTrustData.serviceTokens.filter(token => {
        const tokenAge = Date.now() - new Date(token.created_at).getTime();
        const ninetyDaysMs = 90 * 24 * 60 * 60 * 1000;
        return tokenAge > ninetyDaysMs;
      });

      if (oldTokens.length > 0) {
        findings.push({
          id: uuidv4(),
          checkId: "CFL-ZT-006",
          checkTitle: "Service Tokens Not Rotated",
          service: "zerotrust",
          severity: "medium",
          status: "FAIL",
          description: `${oldTokens.length} service tokens are older than 90 days.`,
          remediation: "Rotate service tokens regularly for security.",
          resourceId: assessment.account.id,
          resourceType: "account",
          timestamp: new Date(),
          metadata: {
            oldTokensCount: oldTokens.length,
            totalTokens: zeroTrustData.serviceTokens.length
          }
        });
      }
    }

    assessment.findings.push(...findings);
  }

  /**
   * Check zone-level security configurations
   */
  async checkZoneSecurity(zone, zoneDetails, analytics, assessment, allZoneSettings) {
    const findings = [];

    // Check zone status
    if (zone.status !== 'active') {
      findings.push({
        id: uuidv4(),
        checkId: 'cf-zone-001',
        checkTitle: 'Zone Not Active',
        service: 'dns',
        severity: 'medium',
        status: 'FAIL',
        description: `Zone ${zone.name} is not active (status: ${zone.status}).`,
        remediation: 'Ensure zone is properly configured and DNS is pointing to Cloudflare.',
        resourceId: zone.id,
        resourceType: 'zone',
        timestamp: new Date(),
        metadata: {
          zoneName: zone.name,
          currentStatus: zone.status
        }
      });
    }

    // Check development mode
    if (zoneDetails?.development_mode > Date.now() / 1000) {
      findings.push({
        id: uuidv4(),
        checkId: 'cf-zone-002',
        checkTitle: 'Development Mode Enabled',
        service: 'performance',
        severity: 'low',
        status: 'FAIL',
        description: `Development mode is enabled for ${zone.name}, bypassing Cloudflare cache.`,
        remediation: 'Disable development mode in production to ensure optimal performance and security.',
        resourceId: zone.id,
        resourceType: 'zone',
        timestamp: new Date(),
        metadata: {
          zoneName: zone.name,
          developmentModeExpiry: new Date(zoneDetails.development_mode * 1000)
        }
      });
    }

    // Check plan limitations
    if (zone.plan?.name === 'Free') {
      findings.push({
        id: uuidv4(),
        checkId: 'cf-zone-003',
        checkTitle: 'Free Plan Limitations',
        service: 'account',
        severity: 'informational',
        status: 'WARNING',
        description: `Domain ${zone.name} is on the Free plan with limited security features.`,
        remediation: `Consider upgrading ${zone.name} to Pro or Business plan for enhanced security features.`,
        resourceId: zone.id,
        resourceName: zone.name,
        resourceType: 'zone',
        timestamp: new Date(),
        metadata: {
          zoneName: zone.name,
          currentPlan: zone.plan?.name,
          recommendation: 'Upgrade for WAF, DDoS protection, and other security features'
        }
      });
    }

    assessment.findings.push(...findings);
  }

  /**
   * Assess performance configurations
   */
  async assessPerformance(zone, performanceSettings, allZoneSettings, assessment) {
    const findings = [];

    // Check Brotli compression
    if (!performanceSettings?.brotli?.value) {
      findings.push({
        id: uuidv4(),
        checkId: 'CFL-PERF-001',
        checkTitle: 'Brotli Compression Disabled',
        service: 'performance',
        severity: 'medium',
        status: 'FAIL',
        description: 'Brotli compression is not enabled. This can improve performance by up to 20% over gzip.',
        remediation: 'Enable Brotli compression in Speed > Optimization > Content Optimization.',
        resourceId: zone.id,
        resourceType: 'zone',
        timestamp: new Date(),
        metadata: {
          zoneName: zone.name,
          currentValue: 'disabled'
        }
      });
    }

    // Check HTTP/2 and HTTP/3
    const http2Enabled = allZoneSettings?.http2?.value;
    const http3Enabled = allZoneSettings?.http3?.value;
    
    if (!http2Enabled) {
      findings.push({
        id: uuidv4(),
        checkId: 'CFL-PERF-002',
        checkTitle: 'HTTP/2 Not Enabled',
        service: 'performance',
        severity: 'medium',
        status: 'FAIL',
        description: 'HTTP/2 is not enabled. This protocol significantly improves performance.',
        remediation: 'Enable HTTP/2 in Network settings.',
        resourceId: zone.id,
        resourceType: 'zone',
        timestamp: new Date(),
        metadata: {
          zoneName: zone.name
        }
      });
    }

    if (!http3Enabled) {
      findings.push({
        id: uuidv4(),
        checkId: 'CFL-PERF-003',
        checkTitle: 'HTTP/3 Not Enabled',
        service: 'performance',
        severity: 'low',
        status: 'WARNING',
        description: 'HTTP/3 (QUIC) is not enabled. Consider enabling for improved performance.',
        remediation: 'Enable HTTP/3 in Network settings.',
        resourceId: zone.id,
        resourceType: 'zone',
        timestamp: new Date(),
        metadata: {
          zoneName: zone.name
        }
      });
    }

    // Check minification settings
    const minifySettings = performanceSettings?.minify?.value || {};
    if (!minifySettings.js || !minifySettings.css || !minifySettings.html) {
      findings.push({
        id: uuidv4(),
        checkId: 'CFL-PERF-004',
        checkTitle: 'Minification Not Fully Enabled',
        service: 'performance',
        severity: 'low',
        status: 'WARNING',
        description: `Minification not enabled for: ${!minifySettings.js ? 'JS ' : ''}${!minifySettings.css ? 'CSS ' : ''}${!minifySettings.html ? 'HTML' : ''}`.trim(),
        remediation: 'Enable minification for all content types in Speed > Optimization.',
        resourceId: zone.id,
        resourceType: 'zone',
        timestamp: new Date(),
        metadata: {
          zoneName: zone.name,
          js: minifySettings.js || false,
          css: minifySettings.css || false,
          html: minifySettings.html || false
        }
      });
    }

    // Check Rocket Loader
    if (performanceSettings?.rocket_loader?.value === 'off') {
      findings.push({
        id: uuidv4(),
        checkId: 'CFL-PERF-005',
        checkTitle: 'Rocket Loader Disabled',
        service: 'performance',
        severity: 'informational',
        status: 'WARNING',
        description: 'Rocket Loader is disabled. Consider enabling to improve JavaScript loading performance.',
        remediation: 'Enable Rocket Loader in Speed > Optimization if compatible with your site.',
        resourceId: zone.id,
        resourceType: 'zone',
        timestamp: new Date(),
        metadata: {
          zoneName: zone.name
        }
      });
    }

    assessment.findings.push(...findings);
  }

  /**
   * Assess Workers security
   */
  async assessWorkers(workers, assessment) {
    const findings = [];

    if (!workers || workers.length === 0) {
      return; // No workers to assess
    }

    workers.forEach(worker => {
      // Check for error handling patterns
      const hasErrorHandling = worker.script?.includes('try') && worker.script?.includes('catch');
      if (!hasErrorHandling && worker.script) {
        findings.push({
          id: uuidv4(),
          checkId: 'CFL-WORK-001',
          checkTitle: 'Worker Without Error Handling',
          service: 'workers',
          severity: 'medium',
          status: 'FAIL',
          description: `Worker "${worker.name}" appears to lack proper error handling.`,
          remediation: 'Implement try-catch blocks and proper error responses in Workers.',
          resourceId: worker.id,
          resourceType: 'worker',
          timestamp: new Date(),
          metadata: {
            workerName: worker.name
          }
        });
      }

      // Check for rate limiting implementation
      if (!worker.script?.includes('getRateLimit') && !worker.script?.includes('rateLimit')) {
        findings.push({
          id: uuidv4(),
          checkId: 'CFL-WORK-002',
          checkTitle: 'Worker Without Rate Limiting',
          service: 'workers',
          severity: 'medium',
          status: 'WARNING',
          description: `Worker "${worker.name}" may lack rate limiting implementation.`,
          remediation: 'Consider implementing rate limiting in Workers handling user requests.',
          resourceId: worker.id,
          resourceType: 'worker',
          timestamp: new Date(),
          metadata: {
            workerName: worker.name
          }
        });
      }
    });

    assessment.findings.push(...findings);
  }

  /**
   * Assess Bot Management
   */
  async assessBotManagement(zone, botManagement, assessment) {
    const findings = [];

    if (!botManagement?.enabled || botManagement?.bot_fight_mode === 'off') {
      findings.push({
        id: uuidv4(),
        checkId: 'CFL-BOT-001',
        checkTitle: 'Bot Fight Mode Disabled',
        service: 'bot',
        severity: 'medium',
        status: 'FAIL',
        description: 'Bot Fight Mode is not enabled to protect against malicious bots.',
        remediation: 'Enable Bot Fight Mode in Security > Bots.',
        resourceId: zone.id,
        resourceType: 'zone',
        timestamp: new Date(),
        metadata: {
          zoneName: zone.name,
          currentStatus: botManagement?.bot_fight_mode || 'off'
        }
      });
    }

    assessment.findings.push(...findings);
  }

  /**
   * Assess API Shield
   */
  async assessAPIShield(zone, apiShield, assessment) {
    const findings = [];

    if (!apiShield?.enabled) {
      findings.push({
        id: uuidv4(),
        checkId: 'CFL-API-001',
        checkTitle: 'API Shield Not Configured',
        service: 'api',
        severity: 'medium',
        status: 'WARNING',
        description: 'API Shield is not configured to protect API endpoints.',
        remediation: 'Configure API Shield with schema validation in Security > API Shield.',
        resourceId: zone.id,
        resourceType: 'zone',
        timestamp: new Date(),
        metadata: {
          zoneName: zone.name
        }
      });
    } else if (apiShield.schemas?.length === 0) {
      findings.push({
        id: uuidv4(),
        checkId: 'CFL-API-002',
        checkTitle: 'No API Schemas Configured',
        service: 'api',
        severity: 'low',
        status: 'WARNING',
        description: 'API Shield is enabled but no schemas are configured for validation.',
        remediation: 'Upload OpenAPI schemas to enable API request validation.',
        resourceId: zone.id,
        resourceType: 'zone',
        timestamp: new Date(),
        metadata: {
          zoneName: zone.name,
          endpointsCount: apiShield.endpoints?.length || 0
        }
      });
    }

    assessment.findings.push(...findings);
  }

  /**
   * Assess Load Balancing
   */
  async assessLoadBalancing(zone, loadBalancers, assessment) {
    const findings = [];

    if (!loadBalancers || loadBalancers.load_balancers?.length === 0) {
      return; // No load balancers to assess
    }

    loadBalancers.load_balancers.forEach(lb => {
      // Check for health monitoring
      const hasHealthCheck = loadBalancers.monitors?.some(m => 
        lb.default_pools?.includes(m.id) || lb.fallback_pool === m.id
      );

      if (!hasHealthCheck) {
        findings.push({
          id: uuidv4(),
          checkId: 'CFL-LB-001',
          checkTitle: 'Load Balancer Without Health Checks',
          service: 'loadbalancing',
          severity: 'high',
          status: 'FAIL',
          description: `Load balancer "${lb.name}" lacks health monitoring.`,
          remediation: 'Configure health checks for all load balancer pools.',
          resourceId: lb.id,
          resourceType: 'loadbalancer',
          timestamp: new Date(),
          metadata: {
            loadBalancerName: lb.name,
            zoneName: zone.name
          }
        });
      }

      // Check for session affinity
      if (lb.session_affinity === 'none' && lb.default_pools?.length > 1) {
        findings.push({
          id: uuidv4(),
          checkId: 'CFL-LB-002',
          checkTitle: 'No Session Affinity Configured',
          service: 'loadbalancing',
          severity: 'low',
          status: 'WARNING',
          description: `Load balancer "${lb.name}" has no session affinity configured.`,
          remediation: 'Consider enabling session affinity if your application requires it.',
          resourceId: lb.id,
          resourceType: 'loadbalancer',
          timestamp: new Date(),
          metadata: {
            loadBalancerName: lb.name,
            zoneName: zone.name
          }
        });
      }
    });

    assessment.findings.push(...findings);
  }

  /**
   * Assess Pages projects
   */
  async assessPages(pagesProjects, assessment) {
    const findings = [];

    if (!pagesProjects || pagesProjects.length === 0) {
      return; // No Pages projects to assess
    }

    pagesProjects.forEach(project => {
      // Check for environment variables that might contain secrets
      if (project.deployment_configs?.production?.env_vars) {
        const envVars = Object.keys(project.deployment_configs.production.env_vars);
        const sensitivePatterns = ['KEY', 'SECRET', 'TOKEN', 'PASSWORD', 'CREDENTIAL'];
        
        const potentialSecrets = envVars.filter(key => 
          sensitivePatterns.some(pattern => key.includes(pattern))
        );

        if (potentialSecrets.length > 0) {
          findings.push({
            id: uuidv4(),
            checkId: 'CFL-PAGE-001',
            checkTitle: 'Potential Secrets in Environment Variables',
            service: 'pages',
            severity: 'high',
            status: 'WARNING',
            description: `Pages project "${project.name}" has environment variables that may contain secrets.`,
            remediation: 'Use encrypted secrets management for sensitive values.',
            resourceId: project.id,
            resourceType: 'pages_project',
            timestamp: new Date(),
            metadata: {
              projectName: project.name,
              suspiciousVars: potentialSecrets
            }
          });
        }
      }

      // Check build configuration
      if (!project.build_config?.build_command) {
        findings.push({
          id: uuidv4(),
          checkId: 'CFL-PAGE-002',
          checkTitle: 'No Build Command Configured',
          service: 'pages',
          severity: 'low',
          status: 'WARNING',
          description: `Pages project "${project.name}" has no build command configured.`,
          remediation: 'Configure appropriate build commands for your Pages project.',
          resourceId: project.id,
          resourceType: 'pages_project',
          timestamp: new Date(),
          metadata: {
            projectName: project.name
          }
        });
      }
    });

    assessment.findings.push(...findings);
  }

  /**
   * Assess Email Routing
   */
  async assessEmailRouting(zone, emailRoutingRules, dnsRecords, assessment) {
    const findings = [];

    // Check for SPF records
    const spfRecords = dnsRecords.filter(r => 
      r.type === 'TXT' && r.content?.includes('v=spf1')
    );

    if (spfRecords.length === 0) {
      findings.push({
        id: uuidv4(),
        checkId: 'CFL-EMAIL-001',
        checkTitle: 'No SPF Record Found',
        service: 'email',
        severity: 'high',
        status: 'FAIL',
        description: 'No SPF record found for email authentication.',
        remediation: 'Add an SPF TXT record to prevent email spoofing.',
        resourceId: zone.id,
        resourceType: 'zone',
        timestamp: new Date(),
        metadata: {
          zoneName: zone.name
        }
      });
    }

    // Check for DKIM records
    const dkimRecords = dnsRecords.filter(r => 
      r.name.includes('._domainkey') || (r.type === 'TXT' && r.content?.includes('v=DKIM1'))
    );

    if (dkimRecords.length === 0) {
      findings.push({
        id: uuidv4(),
        checkId: 'CFL-EMAIL-002',
        checkTitle: 'No DKIM Records Found',
        service: 'email',
        severity: 'medium',
        status: 'WARNING',
        description: 'No DKIM records found for email authentication.',
        remediation: 'Configure DKIM records for better email deliverability.',
        resourceId: zone.id,
        resourceType: 'zone',
        timestamp: new Date(),
        metadata: {
          zoneName: zone.name
        }
      });
    }

    // Check for DMARC record
    const dmarcRecords = dnsRecords.filter(r => 
      r.name.includes('_dmarc') || (r.type === 'TXT' && r.content?.includes('v=DMARC1'))
    );

    if (dmarcRecords.length === 0) {
      findings.push({
        id: uuidv4(),
        checkId: 'CFL-EMAIL-003',
        checkTitle: 'No DMARC Record Found',
        service: 'email',
        severity: 'high',
        status: 'FAIL',
        description: 'No DMARC record found for email policy enforcement.',
        remediation: 'Add a DMARC record to protect against email spoofing.',
        resourceId: zone.id,
        resourceType: 'zone',
        timestamp: new Date(),
        metadata: {
          zoneName: zone.name
        }
      });
    }

    assessment.findings.push(...findings);
  }

  /**
   * Calculate assessment summary statistics
   */
  calculateSummary(assessment) {
    const summary = {
      totalChecks: assessment.findings.length,
      passedChecks: 0,
      failedChecks: 0,
      manualChecks: 0,
      notApplicableChecks: 0,
      criticalFindings: 0,
      highFindings: 0,
      mediumFindings: 0,
      lowFindings: 0,
      informationalFindings: 0,
      complianceScore: 0,
      total: assessment.findings.length,
      passed: 0,
      failed: 0,
      warnings: 0,
      bySeverity: {
        critical: 0,
        high: 0,
        medium: 0,
        low: 0,
        informational: 0
      },
      byService: {}
    };

    assessment.findings.forEach(finding => {
      // Count by status
      const oscfStatus = finding.status?.toLowerCase();
      switch (oscfStatus) {
        case 'pass':
          summary.passedChecks++;
          summary.passed++;
          break;
        case 'fail':
          summary.failedChecks++;
          summary.failed++;
          // Count severity-specific failures
          switch (finding.severity?.toLowerCase()) {
            case 'critical':
              summary.criticalFindings++;
              break;
            case 'high':
              summary.highFindings++;
              break;
            case 'medium':
              summary.mediumFindings++;
              break;
            case 'low':
              summary.lowFindings++;
              break;
            case 'informational':
              summary.informationalFindings++;
              break;
          }
          break;
        case 'manual':
          summary.manualChecks++;
          break;
        case 'notapplicable':
          summary.notApplicableChecks++;
          break;
        default:
          if (finding.status === 'WARNING') {
            summary.warnings++;
            summary.failedChecks++;
            // Count severity for warnings too
            switch (finding.severity?.toLowerCase()) {
              case 'critical':
                summary.criticalFindings++;
                break;
              case 'high':
                summary.highFindings++;
                break;
              case 'medium':
                summary.mediumFindings++;
                break;
              case 'low':
                summary.lowFindings++;
                break;
              case 'informational':
                summary.informationalFindings++;
                break;
            }
          }
      }

      // Count by severity (legacy)
      const severity = finding.severity?.toLowerCase() || 'informational';
      if (summary.bySeverity.hasOwnProperty(severity)) {
        summary.bySeverity[severity]++;
      }

      // Count by service
      const service = finding.service || 'general';
      summary.byService[service] = (summary.byService[service] || 0) + 1;
    });

    // Calculate compliance score
    if (summary.totalChecks > 0) {
      const applicableChecks = summary.totalChecks - summary.notApplicableChecks;
      if (applicableChecks > 0) {
        summary.complianceScore = Math.round((summary.passedChecks / applicableChecks) * 100);
      }
    }

    assessment.summary = summary;
  }

  /**
   * Assess Security Center Insights
   */
  async assessSecurityInsights(insightsData, resourceType, resourceId, assessment) {
    const findings = [];
    const insights = insightsData.insights || [];
    
    if (insights.length === 0) {
      // No insights is actually good - means no security issues detected
      return;
    }

    // Process each insight
    for (const insight of insights) {
      const severityMapping = {
        'Critical': 'critical',
        'High': 'high',
        'Moderate': 'medium',
        'Low': 'low'
      };

      const finding = {
        id: uuidv4(),
        checkId: `CFL-INSIGHT-${insight.issue_type || 'UNKNOWN'}`,
        checkTitle: insight.issue_type || 'Security Insight',
        service: 'security-insights',
        severity: severityMapping[insight.severity] || 'medium',
        status: 'FAIL',
        description: `Security Center detected: ${insight.subject || 'Security issue'}`,
        remediation: insight.resolve_text || 'Follow Cloudflare Security Center recommendations',
        resourceId: resourceId,
        resourceType: resourceType,
        timestamp: new Date(),
        metadata: {
          insightId: insight.id,
          issueClass: insight.issue_class,
          issueType: insight.issue_type,
          severity: insight.severity,
          since: insight.since,
          detectedAt: insight.timestamp,
          resolveLink: insight.resolve_link,
          dismissed: insight.dismissed || false,
          payload: insight.payload
        }
      };

      // Add more specific description based on issue type
      if (insight.issue_type) {
        switch (insight.issue_type) {
          case 'exposed_credentials':
            finding.description = `Exposed credentials detected: ${insight.subject}`;
            finding.remediation = 'Immediately rotate the exposed credentials and review access logs';
            break;
          case 'ssl_certificate_expiring':
            finding.description = `SSL certificate expiring soon: ${insight.subject}`;
            finding.remediation = 'Renew the SSL certificate before expiration';
            break;
          case 'dns_record_exposing_origin':
            finding.description = `DNS record exposing origin IP: ${insight.subject}`;
            finding.remediation = 'Proxy the DNS record through Cloudflare to hide origin IP';
            break;
          case 'insecure_ssl_tls':
            finding.description = `Insecure SSL/TLS configuration: ${insight.subject}`;
            finding.remediation = 'Update SSL/TLS settings to use secure protocols only';
            break;
          case 'missing_security_headers':
            finding.description = `Missing security headers: ${insight.subject}`;
            finding.remediation = 'Configure appropriate security headers for the domain';
            break;
          case 'vulnerable_software':
            finding.description = `Vulnerable software detected: ${insight.subject}`;
            finding.remediation = 'Update the software to patch known vulnerabilities';
            break;
          default:
            // Keep generic description for unknown types
            break;
        }
      }

      findings.push(finding);
    }

    // Add summary finding if there are multiple insights
    if (insights.length > 1) {
      const summary = insightsData.summary;
      findings.push({
        id: uuidv4(),
        checkId: 'CFL-INSIGHT-SUMMARY',
        checkTitle: 'Multiple Security Insights Detected',
        service: 'security-insights',
        severity: summary.bySeverity.critical > 0 ? 'critical' : 
                  summary.bySeverity.high > 0 ? 'high' : 'medium',
        status: 'FAIL',
        description: `Security Center detected ${insights.length} security issues: ${summary.bySeverity.critical} critical, ${summary.bySeverity.high} high, ${summary.bySeverity.moderate} moderate, ${summary.bySeverity.low} low`,
        remediation: 'Review and address all security insights in Cloudflare Security Center',
        resourceId: resourceId,
        resourceType: resourceType,
        timestamp: new Date(),
        metadata: {
          totalInsights: insights.length,
          bySeverity: summary.bySeverity,
          byClass: summary.byClass,
          byType: summary.byType
        }
      });
    }

    assessment.findings.push(...findings);
  }
}

module.exports = AssessmentService;
