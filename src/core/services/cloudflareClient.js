/**
 * @fileoverview Cloudflare API Client Service
 * @description Native API client using Cloudflare v5 SDK for security assessments with debug logging
 * @module services/cloudflareClient
 */

const Cloudflare = require('cloudflare');
const { APIError } = require('cloudflare/error');
const logger = require('../utils/logger');

class CloudflareClient {
  constructor(apiToken) {
    if (!apiToken) {
      throw new Error('Cloudflare API token is required');
    }

    this.debugMode = process.env.CLOUDFLARE_DEBUG === 'true' || process.env.DEBUG === 'true';

    logger.cloudflare('Initializing Cloudflare client', {
      hasApiToken: true,
      tokenLength: apiToken?.length || 0,
      debugMode: this.debugMode
    });

    // Initialize Cloudflare client with API token
    // v5 SDK uses same apiToken property; added maxRetries for resilience
    const clientConfig = {
      apiToken: apiToken.trim()
    };

    if (this.debugMode) {
      logger.cloudflare('Creating Cloudflare client with config', {
        configKeys: Object.keys(clientConfig),
        hasApiToken: !!clientConfig.apiToken,
        sdkVersion: '5.2.0'
      });
    }

    try {
      this.client = new Cloudflare(clientConfig);

      if (!this.client) {
        throw new Error('Failed to initialize Cloudflare client');
      }

      logger.cloudflare('Cloudflare client created successfully');
    } catch (initError) {
      logger.error('Failed to initialize Cloudflare client', {
        error: initError.message,
        stack: initError.stack
      });
      throw new Error(`Cloudflare client initialization failed: ${initError.message}`);
    }

    this.apiToken = apiToken;
    this.rateLimitRemaining = 1200;
    this.rateLimitReset = Date.now() + (5 * 60 * 1000);
    this.requestCount = 0;
  }

  /**
   * Normalize v5 list responses to a consistent { result, result_info } shape.
   * v5 list calls return Page objects with .result array; auto-pagination
   * may return a plain array. This helper ensures downstream code can
   * always access .result safely.
   */
  _unwrapList(page) {
    if (Array.isArray(page)) {
      return { result: page, result_info: { total_count: page.length } };
    }
    if (page && typeof page === 'object' && 'result' in page) {
      return page;
    }
    return { result: page || [], result_info: null };
  }

  /**
   * Update rate limit information from response headers
   */
  updateRateLimit(headers) {
    if (headers['x-ratelimit-remaining']) {
      this.rateLimitRemaining = parseInt(headers['x-ratelimit-remaining']);
    }
    if (headers['x-ratelimit-reset']) {
      this.rateLimitReset = parseInt(headers['x-ratelimit-reset']) * 1000;
    }
  }

  /**
   * Check if we're approaching rate limits
   */
  checkRateLimit() {
    const now = Date.now();
    if (this.rateLimitRemaining < 50 && now < this.rateLimitReset) {
      const waitTime = this.rateLimitReset - now;
      logger.warn(`Approaching rate limit. ${this.rateLimitRemaining} requests remaining. Waiting ${waitTime}ms`);
      return waitTime;
    }
    return 0;
  }

  /**
   * Execute API call with rate limit handling
   */
  async executeWithRateLimit(apiCall) {
    const waitTime = this.checkRateLimit();
    if (waitTime > 0) {
      await new Promise(resolve => setTimeout(resolve, waitTime));
    }

    const requestId = `cf-req-${++this.requestCount}`;
    const startTime = Date.now();

    try {
      if (this.debugMode) {
        logger.cloudflare(`Starting API request ${requestId}`, {
          requestId,
          requestCount: this.requestCount
        });
      }

      const result = await apiCall();

      const duration = Date.now() - startTime;
      if (this.debugMode) {
        logger.cloudflare(`API request ${requestId} completed`, {
          requestId,
          duration,
          hasResult: !!result,
          resultKeys: result ? Object.keys(result) : []
        });
      }

      return result;
    } catch (error) {
      const duration = Date.now() - startTime;

      // v5 SDK throws typed APIError subclasses with .status and .errors
      const errorDetails = {
        requestId,
        duration,
        message: error.message,
        statusCode: error.status || error.statusCode,
        errors: error.errors || [],
        isAPIError: error instanceof APIError
      };

      logger.error('Cloudflare API error:', errorDetails);

      // If it's a 403, provide more specific error message
      if (error.status === 403 || error.message?.includes('403')) {
        const errorMessage = error.errors?.[0]?.message || error.message;
        throw new Error(`Cloudflare API Authentication Failed (403): ${errorMessage}. Please verify your API token has the required permissions.`);
      }

      throw error;
    }
  }

  /**
   * Execute raw API request using fetch
   */
  async rawRequest(path, options = {}) {
    const method = options.method || 'GET';
    const body = options.body ? JSON.stringify(options.body) : undefined;

    return this.executeWithRateLimit(async () => {
      const response = await fetch(`https://api.cloudflare.com/client/v4${path}`, {
        method,
        headers: {
          'Authorization': `Bearer ${this.apiToken}`,
          'Content-Type': 'application/json'
        },
        body
      });

      const headers = {};
      response.headers.forEach((value, key) => {
        headers[key.toLowerCase()] = value;
      });
      this.updateRateLimit(headers);

      const data = await response.json().catch(() => null);
      if (!response.ok || (data && data.success === false)) {
        const errorMessage = data?.errors?.[0]?.message || response.statusText || 'Unknown error';
        const error = new Error(`Cloudflare API request failed (${response.status}): ${errorMessage}`);
        error.status = response.status;
        throw error;
      }

      return data;
    });
  }

  sanitizeResponseData(data) {
    if (!data || typeof data !== 'object') {
      return data;
    }

    try {
      const clone = JSON.parse(JSON.stringify(data));
      if (Array.isArray(clone.errors)) {
        clone.errors = clone.errors.map(entry => ({
          code: entry.code,
          message: entry.message
        }));
      }
      if (Array.isArray(clone.messages)) {
        clone.messages = clone.messages.map(entry => ({
          code: entry.code,
          message: entry.message
        }));
      }
      return clone;
    } catch {
      return { message: 'Unable to serialize response data safely' };
    }
  }

  /**
   * Test API connection and get account info
   */
  async testConnection() {
    try {
      logger.info('Testing Cloudflare connection', { hasToken: !!this.apiToken });

      return await this.executeWithRateLimit(async () => {
        logger.info('Fetching zones to test connection...');

        if (this.debugMode) {
          logger.cloudflare('Calling client.zones.list()', {
            method: 'GET',
            endpoint: '/zones'
          });
        }

        const zonesPage = await this.client.zones.list({});
        const zones = this._unwrapList(zonesPage);

        if (this.debugMode) {
          logger.cloudflare('Zones response received', {
            count: zones.result?.length || 0,
            totalCount: zones.result_info?.total_count,
            zoneNames: zones.result?.map(z => z.name) || []
          });
        }

        logger.info('Zones fetched successfully', { count: zones.result?.length || 0 });

        // Try to get user info if possible, but don't fail if it doesn't work
        let userInfo = null;
        let accountInfo = null;

        try {
          logger.info('Attempting to fetch user info...');

          if (this.debugMode) {
            logger.cloudflare('Calling client.user.get()', {
              method: 'GET',
              endpoint: '/user'
            });
          }

          // v5: .get() returns the user object directly (no .result wrapper)
          const user = await this.client.user.get();

          if (this.debugMode) {
            logger.cloudflare('User response received', {
              userId: user?.id,
              email: user?.email
            });
          }

          userInfo = user;

          if (zones.result?.length > 0) {
            const firstZone = zones.result[0];
            accountInfo = {
              id: firstZone.account?.id || userInfo?.id || 'unknown',
              email: userInfo?.email || 'unknown',
              name: firstZone.account?.name || userInfo?.organizations?.[0]?.name || 'Cloudflare Account',
              type: firstZone.account?.type || 'standard'
            };
          }
        } catch (userError) {
          logger.warn('Could not fetch user info (may need additional permissions)', {
            error: userError.message
          });

          if (zones.result?.length > 0) {
            const firstZone = zones.result[0];
            accountInfo = {
              id: firstZone.account?.id || 'unknown',
              email: 'unknown',
              name: firstZone.account?.name || 'Cloudflare Account',
              type: firstZone.account?.type || 'standard'
            };
          } else {
            accountInfo = {
              id: 'unknown',
              email: 'unknown',
              name: 'Cloudflare Account',
              type: 'standard'
            };
          }
        }

        return {
          success: true,
          account: accountInfo,
          zonesCount: zones.result_info?.total_count || zones.result?.length || 0,
          zones: zones.result || []
        };
      });
    } catch (error) {
      logger.error('Test connection failed', {
        message: error.message,
        statusCode: error.status
      });

      if (error.message?.includes('9109') || error.message?.includes('Valid user-level authentication')) {
        return {
          success: false,
          error: 'API token lacks required permissions. Ensure the token has at least Zone:Read permissions.'
        };
      }

      return {
        success: false,
        error: `Failed to connect to Cloudflare API: ${error.message}`
      };
    }
  }

  /**
   * Get zone by ID
   */
  async getZone(zoneId) {
    return this.executeWithRateLimit(async () => {
      if (this.debugMode) {
        logger.cloudflare('Getting zone details', {
          zoneId,
          method: 'GET',
          endpoint: `/zones/${zoneId}`
        });
      }

      // v5: .get() returns the zone object directly
      const zone = await this.client.zones.get({ zone_id: zoneId });

      if (this.debugMode) {
        logger.cloudflare('Zone details received', {
          zoneId,
          name: zone?.name,
          status: zone?.status,
          plan: zone?.plan?.name
        });
      }

      return zone;
    });
  }

  /**
   * List all zones
   */
  async listZones() {
    return this.executeWithRateLimit(async () => {
      const zonesPage = await this.client.zones.list({});
      const zones = this._unwrapList(zonesPage);
      return zones.result || [];
    });
  }

  /**
   * Get all zones (alias for listZones for backward compatibility)
   */
  async getZones() {
    return this.listZones();
  }

  /**
   * Get DNS records for a zone
   */
  async getDNSRecords(zoneId) {
    return this.executeWithRateLimit(async () => {
      try {
        if (this.debugMode) {
          logger.cloudflare('Getting DNS records', {
            zoneId,
            method: 'GET',
            endpoint: `/zones/${zoneId}/dns_records`
          });
        }

        // v5: DNS is a top-level resource
        const recordsPage = await this.client.dns.records.list({ zone_id: zoneId });
        const records = this._unwrapList(recordsPage);

        if (this.debugMode) {
          logger.cloudflare('DNS records received', {
            zoneId,
            count: records.result?.length || 0,
            types: [...new Set(records.result?.map(r => r.type) || [])],
            proxiedCount: records.result?.filter(r => r.proxied).length || 0
          });
        }

        return records.result || [];
      } catch (error) {
        logger.error('Failed to get DNS records', { error: error.message, zoneId });
        return [];
      }
    });
  }

  /**
   * Get analytics for a zone (requires analytics permissions)
   */
  async getZoneAnalytics(zoneId) {
    return this.executeWithRateLimit(async () => {
      try {
        // v5 SDK has no client.zones.analytics — use rawRequest
        const since = new Date(Date.now() - 24 * 60 * 60 * 1000).toISOString();
        const until = new Date().toISOString();

        const data = await this.rawRequest(
          `/zones/${zoneId}/analytics/dashboard?since=${encodeURIComponent(since)}&until=${encodeURIComponent(until)}`
        );
        return data?.result || null;
      } catch (error) {
        logger.warn('Analytics not available:', { error: error.message });
        return null;
      }
    });
  }

  /**
   * Get SSL/TLS settings for a zone
   */
  async getSSLSettings(zoneId) {
    return this.executeWithRateLimit(async () => {
      try {
        // zones.settings.get('ssl', ...) is unchanged in v5
        const sslMode = await this.client.zones.settings.get('ssl', {
          zone_id: zoneId
        });
        // v5: .get() returns the setting value directly
        const sslValue = sslMode?.value || sslMode?.result?.value || 'flexible';

        // v5: SSL resources are top-level
        let universalSSL = null;
        let certificatePacks = [];
        let customCerts = [];

        try {
          [universalSSL, certificatePacks, customCerts] = await Promise.all([
            this.client.ssl.universal.settings.get({ zone_id: zoneId }).catch(() => null),
            this._unwrapList(await this.client.ssl.certificatePacks.list({ zone_id: zoneId }).catch(() => ({ result: [] }))),
            this._unwrapList(await this.client.customCertificates.list({ zone_id: zoneId }).catch(() => ({ result: [] })))
          ]);
        } catch (e) {
          logger.debug('SSL sub-resources not available:', e.message);
        }

        return {
          settings: {
            value: sslValue,
            mode: sslValue,
            universal_ssl: universalSSL?.enabled ?? universalSSL?.result?.enabled
          },
          certificates: certificatePacks?.result || [],
          customCertificates: customCerts?.result || [],
          universal: universalSSL || {}
        };
      } catch (error) {
        logger.error('Failed to get SSL settings', { error: error.message, zoneId });
        return {
          settings: { value: 'unknown' },
          certificates: [],
          customCertificates: [],
          universal: {}
        };
      }
    });
  }

  /**
   * Get WAF settings and rules
   */
  async getWAFSettings(zoneId) {
    return this.executeWithRateLimit(async () => {
      try {
        const settings = {};

        // zones.settings.get is unchanged in v5
        try {
          const securityLevel = await this.client.zones.settings.get('security_level', {
            zone_id: zoneId
          });
          settings.security_level = securityLevel?.value || securityLevel?.result?.value || 'medium';
        } catch (e) {
          settings.security_level = 'medium';
        }

        // v5: WAF is under client.firewall.waf
        let wafRules = [];
        try {
          const wafPackagesPage = await this.client.firewall.waf.packages.list({ zone_id: zoneId });
          const wafPackages = this._unwrapList(wafPackagesPage);
          wafRules = wafPackages?.result || [];
        } catch (e) {
          logger.debug('WAF packages not available:', e.message);
        }

        return {
          firewallRules: [],
          accessRules: [],
          rateLimitRules: [],
          settings,
          wafRules
        };
      } catch (error) {
        logger.error('Failed to get WAF settings', { error: error.message, zoneId });
        return {
          firewallRules: [],
          accessRules: [],
          rateLimitRules: [],
          settings: { security_level: 'medium' }
        };
      }
    });
  }

  /**
   * Get Zero Trust settings (if account has Access)
   */
  async getZeroTrustSettings(accountId) {
    return this.executeWithRateLimit(async () => {
      try {
        // Try multiple endpoints to detect Zero Trust availability
        let zeroTrustAvailable = false;
        let applications = null;
        let organization = null;

        try {
          organization = await this.client.zeroTrust.organizations.get({
            account_id: accountId
          });
          zeroTrustAvailable = true;
        } catch (e) {
          logger.debug('Zero Trust organization check failed:', e.message);
        }

        try {
          const appsPage = await this.client.zeroTrust.access.applications.list({
            account_id: accountId
          });
          applications = this._unwrapList(appsPage);
          zeroTrustAvailable = true;
        } catch (e) {
          logger.debug('Zero Trust applications check failed:', e.message);
        }

        let accessGroups = null;
        try {
          const groupsPage = await this.client.zeroTrust.access.groups.list({
            account_id: accountId
          });
          accessGroups = this._unwrapList(groupsPage);
          zeroTrustAvailable = true;
        } catch (e) {
          logger.debug('Zero Trust groups check failed:', e.message);
        }

        if (!zeroTrustAvailable) {
          return {
            error: 'Zero Trust not enabled',
            details: 'Zero Trust is not enabled for this account. Enable it at https://one.dash.cloudflare.com'
          };
        }

        // Fetch all Zero Trust components in parallel
        const [
          policies,
          identityProviders,
          serviceTokens,
          tunnels,
          devicePolicies,
          warpSettings,
          gatewayRules,
          dlpProfiles
        ] = await Promise.all([
          this.getZeroTrustPolicies(accountId),
          this.client.zeroTrust.identityProviders.list({
            account_id: accountId
          }).then(p => this._unwrapList(p)).catch(() => ({ result: [] })),
          this.client.zeroTrust.access.serviceTokens.list({
            account_id: accountId
          }).then(p => this._unwrapList(p)).catch(() => ({ result: [] })),
          this.client.zeroTrust.tunnels.list({
            account_id: accountId
          }).then(p => this._unwrapList(p)).catch(() => ({ result: [] })),
          this.client.zeroTrust.devices.policies.list({
            account_id: accountId
          }).then(p => this._unwrapList(p)).catch(() => ({ result: [] })),
          this.getWARPSettings(accountId),
          this.client.zeroTrust.gateway.rules.list({
            account_id: accountId
          }).then(p => this._unwrapList(p)).catch(() => ({ result: [] })),
          this.client.zeroTrust.dlp.profiles.list({
            account_id: accountId
          }).then(p => this._unwrapList(p)).catch(() => ({ result: [] }))
        ]);

        const deviceEnrollmentRules = await this.client.zeroTrust.devices.enrollmentRules.list({
          account_id: accountId
        }).then(p => this._unwrapList(p)).catch(() => ({ result: [] }));

        return {
          applications: applications?.result || [],
          policies: policies || [],
          identityProviders: identityProviders?.result || [],
          serviceTokens: serviceTokens?.result || [],
          tunnels: tunnels?.result || [],
          devicePolicies: devicePolicies?.result || [],
          deviceEnrollmentRules: deviceEnrollmentRules?.result || [],
          warpSettings: warpSettings || {},
          accessGroups: accessGroups?.result || [],
          // v5: .get() returns result directly
          organization: organization || {},
          gatewayRules: gatewayRules?.result || [],
          dlpProfiles: dlpProfiles?.result || [],
          error: null
        };
      } catch (error) {
        logger.debug('Zero Trust assessment error:', error.message);
        return {
          error: 'Zero Trust not enabled',
          details: error.message
        };
      }
    });
  }

  /**
   * Get Zero Trust Access Policies
   */
  async getZeroTrustPolicies(accountId) {
    try {
      // v5: policies are accessed via client.zeroTrust.access.policies
      // but we also iterate applications for app-context enrichment
      const appsPage = await this.client.zeroTrust.access.applications.list({
        account_id: accountId
      }).catch(() => ({ result: [] }));
      const applications = this._unwrapList(appsPage);

      const allPolicies = [];

      for (const app of (applications.result || [])) {
        try {
          // v5: try per-app policies first, fall back to direct list
          let appPolicies;
          try {
            const policiesPage = await this.client.zeroTrust.access.applications.policies.list({
              account_id: accountId,
              uuid: app.id
            });
            appPolicies = this._unwrapList(policiesPage);
          } catch (e) {
            // If per-app policies fails, skip this app
            continue;
          }

          const policiesWithContext = (appPolicies.result || []).map(policy => ({
            ...policy,
            application_id: app.id,
            application_name: app.name,
            application_domain: app.domain
          }));

          allPolicies.push(...policiesWithContext);
        } catch (error) {
          logger.debug(`Failed to get policies for app ${app.id}:`, error.message);
        }
      }

      return allPolicies;
    } catch (error) {
      logger.debug('Failed to get Zero Trust policies:', error.message);
      return [];
    }
  }

  /**
   * Get WARP settings
   */
  async getWARPSettings(accountId) {
    try {
      // v5: .get() returns result directly
      const settings = await this.client.zeroTrust.devices.settings.get({
        account_id: accountId
      }).catch(() => null);

      if (!settings) {
        const warpClientSettings = await this.client.zeroTrust.gateway.configurations.get({
          account_id: accountId
        }).catch(() => null);

        return warpClientSettings || {};
      }

      return settings || {};
    } catch (error) {
      logger.debug('Failed to get WARP settings:', error.message);
      return {};
    }
  }

  /**
   * Get account members
   */
  async getAccountMembers(accountId) {
    return this.executeWithRateLimit(async () => {
      try {
        if (this.debugMode) {
          logger.cloudflare('Getting account members', {
            accountId,
            method: 'GET',
            endpoint: `/accounts/${accountId}/members`
          });
        }

        // accounts.members.list is unchanged in v5
        const membersPage = await this.client.accounts.members.list({
          account_id: accountId
        });
        const members = this._unwrapList(membersPage);

        if (this.debugMode) {
          logger.cloudflare('Account members received', {
            accountId,
            count: members.result?.length || 0,
            roles: [...new Set(members.result?.map(m => m.roles?.[0]?.name) || [])],
            sampleMember: members.result?.[0] ? {
              id: members.result[0].id,
              email: members.result[0].email,
              userKeys: members.result[0].user ? Object.keys(members.result[0].user) : [],
              user_twoFA: members.result[0].user?.two_factor_authentication_enabled,
              user_mfa: members.result[0].user?.mfa_enabled,
              user_email: members.result[0].user?.email,
              allKeys: Object.keys(members.result[0])
            } : null
          });
        }

        return members.result || [];
      } catch (error) {
        logger.debug('Could not fetch account members:', error.message);
        return [];
      }
    });
  }

  /**
   * Get audit logs (requires audit log permissions)
   */
  async getAuditLogs(accountId, params = {}) {
    return this.executeWithRateLimit(async () => {
      try {
        // v5: auditLogs is a top-level resource
        const logsPage = await this.client.auditLogs.list({
          account_id: accountId,
          ...params
        });
        const logs = this._unwrapList(logsPage);
        return logs.result || [];
      } catch (error) {
        logger.debug('Audit logs not available:', error.message);
        return [];
      }
    });
  }

  /**
   * Get performance settings for a zone
   */
  async getPerformanceSettings(zoneId) {
    return this.executeWithRateLimit(async () => {
      try {
        const performanceSettings = [
          'minify',
          'brotli',
          'rocket_loader',
          'mirage',
          'polish',
          'h2_prioritization',
          'automatic_platform_optimization'
        ];

        const settings = {};

        await Promise.all(
          performanceSettings.map(async (setting) => {
            try {
              // zones.settings.get is unchanged in v5
              const result = await this.client.zones.settings.get(setting, {
                zone_id: zoneId
              });
              // v5: .get() returns the setting value directly
              settings[setting] = result?.value || result?.result || result;
            } catch (e) {
              settings[setting] = null;
            }
          })
        );

        return settings;
      } catch (error) {
        logger.error('Failed to get performance settings', { error: error.message, zoneId });
        return {};
      }
    });
  }

  /**
   * Get DNSSEC settings for a zone
   */
  async getDNSSECSettings(zoneId) {
    return this.executeWithRateLimit(async () => {
      try {
        // Try SDK first (v5: DNSSEC is under client.dns.dnssec)
        try {
          if (this.debugMode) {
            logger.cloudflare('Getting DNSSEC settings', {
              zoneId,
              method: 'GET',
              endpoint: `/zones/${zoneId}/dnssec`
            });
          }

          // v5: .get() returns result directly
          const dnssec = await this.client.dns.dnssec.get({ zone_id: zoneId });

          logger.info('DNSSEC API Response', {
            zoneId,
            status: dnssec?.status,
            algorithm: dnssec?.algorithm,
            digest_type: dnssec?.digest_type
          });

          if (this.debugMode) {
            logger.cloudflare('DNSSEC settings received', {
              zoneId,
              status: dnssec?.status,
              algorithm: dnssec?.algorithm,
              digest_type: dnssec?.digest_type
            });
          }

          return dnssec || { status: 'disabled' };
        } catch (sdkError) {
          logger.debug('DNSSEC SDK call failed, trying raw API:', sdkError.message);
        }

        // Fallback: raw API
        try {
          const dnssecResponse = await this.rawRequest(`/zones/${zoneId}/dnssec`);

          logger.info('DNSSEC Raw API Response', {
            zoneId,
            hasResult: !!dnssecResponse?.result,
            status: dnssecResponse?.result?.status
          });

          if (dnssecResponse?.result) {
            return dnssecResponse.result;
          }
        } catch (rawError) {
          logger.debug('Raw DNSSEC API failed:', rawError.message);
        }

        return { status: 'disabled', error: 'DNSSEC API not available' };
      } catch (error) {
        logger.error('Failed to get DNSSEC settings', { error: error.message, zoneId });
        return { status: 'error', error: error.message };
      }
    });
  }

  /**
   * Get security analytics for a zone
   */
  async getSecurityAnalytics(zoneId) {
    return this.executeWithRateLimit(async () => {
      try {
        // v5 SDK has no zones.analytics — use rawRequest
        const since = new Date(Date.now() - 24 * 60 * 60 * 1000).toISOString();
        const until = new Date().toISOString();

        const data = await this.rawRequest(
          `/zones/${zoneId}/analytics/dashboard?since=${encodeURIComponent(since)}&until=${encodeURIComponent(until)}`
        );

        const analyticsResult = data?.result?.data?.[0] || {};
        return {
          threats_blocked: analyticsResult.threats || 0,
          requests_challenged: analyticsResult.pageviews || 0,
          requests_passed: analyticsResult.requests || 0
        };
      } catch (error) {
        logger.warn('Security analytics not available:', { error: error.message });
        return null;
      }
    });
  }

  /**
   * Get all zone settings including security settings
   */
  async getAllZoneSettings(zoneId) {
    return this.executeWithRateLimit(async () => {
      try {
        const settingNames = [
          'ssl', 'always_use_https', 'min_tls_version', 'opportunistic_encryption',
          'tls_1_3', 'automatic_https_rewrites', 'security_level', 'challenge_ttl',
          'browser_check', 'development_mode', 'minify', 'brotli', 'http2',
          'http3', 'websockets', 'ip_geolocation', 'privacy_pass', 'email_obfuscation',
          'server_side_exclude', 'hotlink_protection', 'security_header'
        ];

        const settings = {};

        const results = await Promise.allSettled(
          settingNames.map(async (setting) => {
            try {
              // zones.settings.get is unchanged in v5
              const result = await this.client.zones.settings.get(setting, {
                zone_id: zoneId
              });
              // v5: .get() returns the setting value directly
              return { name: setting, value: result?.value || result?.result || result };
            } catch (e) {
              return { name: setting, value: null, error: e.message };
            }
          })
        );

        results.forEach(result => {
          if (result.status === 'fulfilled' && result.value) {
            settings[result.value.name] = result.value.value;
          }
        });

        return settings;
      } catch (error) {
        logger.error('Failed to get zone settings', { error: error.message, zoneId });
        return {};
      }
    });
  }

  /**
   * Get firewall rules for a zone
   */
  async getFirewallRules(zoneId) {
    return this.executeWithRateLimit(async () => {
      try {
        // v5: rulesets is a top-level resource
        const rulesetsPage = await this.client.rulesets.list({ zone_id: zoneId });
        const rulesets = this._unwrapList(rulesetsPage);

        const firewallRulesets = rulesets.result?.filter(rs =>
          rs.phase === 'http_request_firewall_custom'
        ) || [];

        const allRules = [];
        for (const ruleset of firewallRulesets) {
          // v5: .get(rulesetId, { zone_id }) — positional rulesetId arg
          const rules = await this.client.rulesets.get(ruleset.id, {
            zone_id: zoneId
          });
          allRules.push(...(rules?.rules || []));
        }

        return allRules;
      } catch (error) {
        logger.error('Failed to get firewall rules', { error: error.message, zoneId });
        return [];
      }
    });
  }

  /**
   * Get access rules for a zone
   */
  async getAccessRules(zoneId) {
    return this.executeWithRateLimit(async () => {
      try {
        // v5: accessRules is under client.firewall
        const rulesPage = await this.client.firewall.accessRules.list({
          zone_id: zoneId
        });
        const rules = this._unwrapList(rulesPage);
        return rules.result || [];
      } catch (error) {
        logger.error('Failed to get access rules', { error: error.message, zoneId });
        return [];
      }
    });
  }

  /**
   * Get page rules for a zone
   */
  async getPageRules(zoneId) {
    return this.executeWithRateLimit(async () => {
      try {
        // v5: pageRules is a top-level resource
        const rulesPage = await this.client.pageRules.list({ zone_id: zoneId });
        const rules = this._unwrapList(rulesPage);
        return rules.result || [];
      } catch (error) {
        logger.error('Failed to get page rules', { error: error.message, zoneId });
        return [];
      }
    });
  }

  /**
   * Get rate limiting rules for a zone
   */
  async getRateLimitingRules(zoneId) {
    return this.executeWithRateLimit(async () => {
      try {
        // v5: rateLimits is a top-level resource
        const rulesPage = await this.client.rateLimits.list({ zone_id: zoneId });
        const rules = this._unwrapList(rulesPage);
        return rules.result || [];
      } catch (error) {
        logger.error('Failed to get rate limiting rules', { error: error.message, zoneId });
        return [];
      }
    });
  }

  /**
   * Get load balancers for a zone
   */
  async getLoadBalancers(zoneId, accountId) {
    return this.executeWithRateLimit(async () => {
      try {
        // v5: loadBalancers is a top-level resource
        const loadBalancersPage = await this.client.loadBalancers.list({ zone_id: zoneId });
        const loadBalancers = this._unwrapList(loadBalancersPage);

        if (loadBalancers.result?.length > 0 && accountId) {
          const [pools, monitors] = await Promise.all([
            this.client.loadBalancers.pools.list({ account_id: accountId })
              .then(p => this._unwrapList(p)).catch(() => ({ result: [] })),
            this.client.loadBalancers.monitors.list({ account_id: accountId })
              .then(p => this._unwrapList(p)).catch(() => ({ result: [] }))
          ]);

          return {
            load_balancers: loadBalancers.result || [],
            pools: pools.result || [],
            monitors: monitors.result || []
          };
        }

        return {
          load_balancers: [],
          pools: [],
          monitors: []
        };
      } catch (error) {
        logger.error('Failed to get load balancers', { error: error.message, zoneId });
        return null;
      }
    });
  }

  /**
   * Get bot management settings
   */
  async getBotManagement(zoneId) {
    return this.executeWithRateLimit(async () => {
      try {
        // zones.settings.get is unchanged in v5
        const botFightMode = await this.client.zones.settings.get('bot_fight_mode', {
          zone_id: zoneId
        });
        // v5: .get() returns setting value directly
        const botFightValue = botFightMode?.value || botFightMode?.result?.value;

        let superBotFightMode = null;
        try {
          superBotFightMode = await this.client.zones.settings.get('super_bot_fight_mode', {
            zone_id: zoneId
          });
        } catch (e) {
          // Super bot fight mode not available on free plans
        }

        const superBotValue = superBotFightMode?.value || superBotFightMode?.result?.value;

        return {
          enabled: botFightValue === 'on' || superBotValue === 'on',
          bot_fight_mode: botFightValue,
          super_bot_fight_mode: superBotValue
        };
      } catch (error) {
        logger.debug('Bot management settings not available:', error.message);
        return null;
      }
    });
  }

  /**
   * Get workers deployed on account
   */
  async getWorkers(accountId) {
    return this.executeWithRateLimit(async () => {
      try {
        // v5: workers is a top-level resource
        const scriptsPage = await this.client.workers.scripts.list({
          account_id: accountId
        });
        const scripts = this._unwrapList(scriptsPage);

        const workers = [];

        for (const script of (scripts.result || [])) {
          try {
            // v5: .get() returns the script details directly
            const details = await this.client.workers.scripts.get({
              account_id: accountId,
              script_name: script.id
            });
            workers.push({
              ...script,
              ...details
            });
          } catch (e) {
            workers.push(script);
          }
        }

        return { workers };
      } catch (error) {
        logger.debug('Workers not available:', error.message);
        return { workers: [] };
      }
    });
  }

  /**
   * Get Pages projects
   */
  async getPages(accountId) {
    return this.executeWithRateLimit(async () => {
      try {
        // v5: pages is a top-level resource
        const projectsPage = await this.client.pages.projects.list({
          account_id: accountId
        });
        const projects = this._unwrapList(projectsPage);

        return {
          projects: projects.result || []
        };
      } catch (error) {
        logger.debug('Pages not available:', error.message);
        return { projects: [] };
      }
    });
  }

  /**
   * Get API Shield settings
   */
  async getAPIShield(zoneId) {
    return this.executeWithRateLimit(async () => {
      try {
        // v5: API Shield is under client.apiGateway
        const [schemasPage, endpointsPage] = await Promise.all([
          this.client.apiGateway.schemas.list({ zone_id: zoneId })
            .then(p => this._unwrapList(p)).catch(() => ({ result: [] })),
          this.client.apiGateway.endpoints.list({ zone_id: zoneId })
            .then(p => this._unwrapList(p)).catch(() => ({ result: [] }))
        ]);

        return {
          source: 'sdk-v5',
          enabled: (schemasPage.result?.length || 0) > 0 || (endpointsPage.result?.length || 0) > 0,
          schemas: schemasPage.result || [],
          endpoints: endpointsPage.result || []
        };
      } catch (error) {
        logger.debug('API Shield not available:', error.message);
        return null;
      }
    });
  }

  /**
   * Get email routing rules
   */
  async getEmailRoutingRules(zoneId) {
    return this.executeWithRateLimit(async () => {
      try {
        // v5: emailRouting is a top-level resource
        const rulesPage = await this.client.emailRouting.rules.list({
          zone_id: zoneId
        });
        const rules = this._unwrapList(rulesPage);
        return rules.result || [];
      } catch (error) {
        logger.debug('Email routing not available:', error.message);
        return [];
      }
    });
  }

  /**
   * Get Security Center Insights for account or zone
   */
  async getSecurityInsights(params = {}) {
    return this.executeWithRateLimit(async () => {
      try {
        if (this.debugMode) {
          logger.cloudflare('Getting Security Center Insights', {
            hasAccountId: !!params.accountId,
            hasZoneId: !!params.zoneId,
            method: 'GET',
            endpoint: '/security-center/insights'
          });
        }

        const apiParams = {
          dismissed: false,
          per_page: 100
        };

        if (params.accountId) {
          apiParams.account_id = params.accountId;
        } else if (params.zoneId) {
          apiParams.zone_id = params.zoneId;
        } else {
          throw new Error('Either accountId or zoneId is required for Security Insights');
        }

        if (params.severity) {
          apiParams.severity = Array.isArray(params.severity) ? params.severity : [params.severity];
        }
        if (params.issueClass) {
          apiParams.issue_class = Array.isArray(params.issueClass) ? params.issueClass : [params.issueClass];
        }
        if (params.issueType) {
          apiParams.issue_type = Array.isArray(params.issueType) ? params.issueType : [params.issueType];
        }

        // securityCenter.insights.list path is unchanged in v5
        const response = await this.client.securityCenter.insights.list(apiParams);

        if (this.debugMode) {
          logger.cloudflare('Security Insights response received', {
            count: response.count || 0,
            pageCount: response.issues?.length || 0,
            severities: [...new Set(response.issues?.map(i => i.severity) || [])],
            issueTypes: [...new Set(response.issues?.map(i => i.issue_type) || [])]
          });
        }

        const insights = response.issues || [];

        const severityOrder = { 'Critical': 0, 'High': 1, 'Moderate': 2, 'Low': 3 };
        insights.sort((a, b) => {
          const severityDiff = (severityOrder[a.severity] || 999) - (severityOrder[b.severity] || 999);
          if (severityDiff !== 0) return severityDiff;
          return new Date(b.timestamp || 0) - new Date(a.timestamp || 0);
        });

        return {
          insights,
          count: response.count || insights.length,
          summary: {
            total: insights.length,
            bySeverity: {
              critical: insights.filter(i => i.severity === 'Critical').length,
              high: insights.filter(i => i.severity === 'High').length,
              moderate: insights.filter(i => i.severity === 'Moderate').length,
              low: insights.filter(i => i.severity === 'Low').length
            },
            byClass: insights.reduce((acc, insight) => {
              const cls = insight.issue_class || 'unknown';
              acc[cls] = (acc[cls] || 0) + 1;
              return acc;
            }, {}),
            byType: insights.reduce((acc, insight) => {
              const type = insight.issue_type || 'unknown';
              acc[type] = (acc[type] || 0) + 1;
              return acc;
            }, {})
          }
        };
      } catch (error) {
        logger.error('Failed to get Security Insights', {
          error: error.message,
          accountId: params.accountId,
          zoneId: params.zoneId
        });

        if (error.status === 403 || error.message?.includes('403') || error.message?.includes('not authorized')) {
          return {
            insights: [],
            error: 'Insufficient permissions to access Security Center Insights'
          };
        }

        return {
          insights: [],
          error: error.message
        };
      }
    });
  }

  /**
   * Get custom error pages
   */
  async getCustomErrorPages(zoneId) {
    return this.executeWithRateLimit(async () => {
      try {
        // v5: customPages is a top-level resource
        const pagesPage = await this.client.customPages.list({
          zone_id: zoneId
        });
        const pages = this._unwrapList(pagesPage);
        return pages.result || [];
      } catch (error) {
        logger.debug('Custom error pages not available:', error.message);
        return [];
      }
    });
  }

  /**
   * Get Turnstile widgets for account
   */
  async getTurnstileWidgets(accountId) {
    try {
      const response = await this.rawRequest(`/accounts/${accountId}/challenges/widgets`);
      return response?.result || [];
    } catch (error) {
      logger.debug('Turnstile widgets not available:', error.message);
      return [];
    }
  }

  /**
   * Get DNS Firewall policies for account
   */
  async getDNSFirewall(accountId) {
    try {
      const response = await this.rawRequest(`/accounts/${accountId}/dns_firewall`);
      return response?.result || [];
    } catch (error) {
      logger.debug('DNS Firewall not available:', error.message);
      return [];
    }
  }

  /**
   * Get Logpush jobs for account or zone
   */
  async getLogpushJobs({ accountId, zoneId }) {
    try {
      const basePath = accountId
        ? `/accounts/${accountId}`
        : `/zones/${zoneId}`;
      const response = await this.rawRequest(`${basePath}/logpush/jobs`);
      return response?.result || [];
    } catch (error) {
      logger.debug('Logpush not available:', error.message);
      return [];
    }
  }

  /**
   * Get Access certificates for account or zone
   */
  async getAccessCertificates({ accountId, zoneId }) {
    try {
      const basePath = accountId
        ? `/accounts/${accountId}`
        : `/zones/${zoneId}`;
      const response = await this.rawRequest(`${basePath}/access/certificates`);
      return response?.result || [];
    } catch (error) {
      logger.debug('Access certificates not available:', error.message);
      return [];
    }
  }

  /**
   * Get mTLS certificates for account
   */
  async getMtlsCertificates({ accountId }) {
    try {
      const response = await this.rawRequest(`/accounts/${accountId}/mtls_certificates`);
      return response?.result || [];
    } catch (error) {
      logger.debug('mTLS certificates not available:', error.message);
      return [];
    }
  }

  /**
   * Get Attack Surface Report issues
   */
  async getAttackSurfaceIssues(accountId) {
    try {
      const response = await this.rawRequest(`/accounts/${accountId}/intel/attack-surface-report/issues?per_page=100`);
      const result = response?.result || {};
      return {
        issues: result.issues || [],
        count: result.count || (result.issues ? result.issues.length : 0)
      };
    } catch (error) {
      logger.debug('Attack Surface Report not available:', error.message);
      return { issues: [], count: 0 };
    }
  }

  /**
   * Get API Gateway configuration
   */
  async getApiGateway(zoneId) {
    try {
      const [
        configuration,
        discovery,
        discoveryOperations,
        operations,
        schemas,
        schemaValidation
      ] = await Promise.all([
        this.rawRequest(`/zones/${zoneId}/api_gateway/configuration`).catch(() => null),
        this.rawRequest(`/zones/${zoneId}/api_gateway/discovery`).catch(() => null),
        this.rawRequest(`/zones/${zoneId}/api_gateway/discovery/operations?per_page=100`).catch(() => null),
        this.rawRequest(`/zones/${zoneId}/api_gateway/operations?per_page=100`).catch(() => null),
        this.rawRequest(`/zones/${zoneId}/api_gateway/schemas?per_page=100`).catch(() => null),
        this.rawRequest(`/zones/${zoneId}/api_gateway/settings/schema_validation`).catch(() => null)
      ]);

      const schemaList = Array.isArray(schemas?.result) ? schemas.result : [];
      const discoveryOps = Array.isArray(discoveryOperations?.result) ? discoveryOperations.result : [];
      const operationsList = Array.isArray(operations?.result) ? operations.result : [];
      const enabled = Boolean(
        configuration?.result?.enabled ||
        schemaList.length ||
        operationsList.length ||
        (Array.isArray(discoveryOps) && discoveryOps.length)
      );

      return {
        enabled,
        configuration: configuration?.result || null,
        discovery: discovery?.result || null,
        discoveryOperations: Array.isArray(discoveryOps) ? discoveryOps : [],
        operations: operationsList,
        schemas: schemaList,
        schemaValidation: schemaValidation?.result || null
      };
    } catch (error) {
      logger.debug('API Gateway not available:', error.message);
      return { enabled: false, schemas: [], operations: [] };
    }
  }

  /**
   * Get security.txt configuration
   */
  async getSecurityTxt(zoneId) {
    try {
      const response = await this.rawRequest(`/zones/${zoneId}/security-center/securitytxt`);
      return response?.result || {};
    } catch (error) {
      logger.debug('security.txt not available:', error.message);
      return { error: error.message };
    }
  }

  /**
   * Get rulesets for zone
   */
  async getRulesets(zoneId) {
    return this.executeWithRateLimit(async () => {
      try {
        // v5: rulesets is a top-level resource
        const rulesetsPage = await this.client.rulesets.list({ zone_id: zoneId });
        const rulesets = this._unwrapList(rulesetsPage);
        return rulesets.result || [];
      } catch (error) {
        logger.debug('Rulesets not available:', error.message);
        return [];
      }
    });
  }

  /**
   * Get DLP profiles and rules for account
   */
  async getDLPProfiles(accountId) {
    try {
      const [profiles, rules] = await Promise.all([
        this.rawRequest(`/accounts/${accountId}/dlp/profiles?per_page=100`).catch(() => null),
        this.rawRequest(`/accounts/${accountId}/dlp/rules?per_page=100`).catch(() => null)
      ]);
      return {
        profiles: profiles?.result || [],
        rules: rules?.result || []
      };
    } catch (error) {
      logger.debug('DLP not available:', error.message);
      return { profiles: [], rules: [] };
    }
  }

  /**
   * Get Page Shield configuration for zone
   */
  async getPageShield(zoneId) {
    try {
      const response = await this.rawRequest(`/zones/${zoneId}/page_shield`);
      return response?.result || {};
    } catch (error) {
      logger.debug('Page Shield not available:', error.message);
      return { error: error.message };
    }
  }

  /**
   * Get Cloudflare Tunnels for account
   */
  async getTunnels(accountId) {
    try {
      const response = await this.rawRequest(`/accounts/${accountId}/cfd_tunnel?per_page=100`);
      return response?.result || [];
    } catch (error) {
      logger.debug('Tunnels not available:', error.message);
      return [];
    }
  }

  /**
   * Get Gateway policies (DNS and HTTP) for account
   */
  async getGatewayPolicies(accountId) {
    try {
      const [dns, http, l4] = await Promise.all([
        this.rawRequest(`/accounts/${accountId}/gateway/dns?per_page=100`).catch(() => null),
        this.rawRequest(`/accounts/${accountId}/gateway/http?per_page=100`).catch(() => null),
        this.rawRequest(`/accounts/${accountId}/gateway/l4?per_page=100`).catch(() => null)
      ]);
      return {
        dns: dns?.result || [],
        http: http?.result || [],
        l4: l4?.result || []
      };
    } catch (error) {
      logger.debug('Gateway policies not available:', error.message);
      return { dns: [], http: [], l4: [] };
    }
  }

  /**
   * Get Spectrum applications for account
   */
  async getSpectrumApps(accountId) {
    try {
      const response = await this.rawRequest(`/accounts/${accountId}/spectrum/apps?per_page=100`);
      return response?.result || [];
    } catch (error) {
      logger.debug('Spectrum not available:', error.message);
      return [];
    }
  }

  /**
   * Get AI Gateway configuration for account
   */
  async getAIGateway(accountId) {
    try {
      const response = await this.rawRequest(`/accounts/${accountId}/ai-gateway?per_page=100`);
      return response?.result || [];
    } catch (error) {
      logger.debug('AI Gateway not available:', error.message);
      return [];
    }
  }

  /**
   * Get Cache Deception Armor for zone
   */
  async getCacheDeceptionArmor(zoneId) {
    try {
      const response = await this.rawRequest(`/zones/${zoneId}/cache_deception_armor`);
      return response?.result || {};
    } catch (error) {
      logger.debug('Cache Deception Armor not available:', error.message);
      return { error: error.message };
    }
  }

  /**
   * Get Snippets for zone
   */
  async getSnippets(zoneId) {
    try {
      const response = await this.rawRequest(`/zones/${zoneId}/snippets?per_page=100`);
      return response?.result || [];
    } catch (error) {
      logger.debug('Snippets not available:', error.message);
      return [];
    }
  }

  /**
   * Get Custom Hostnames for zone
   */
  async getCustomHostnames(zoneId) {
    try {
      const response = await this.rawRequest(`/zones/${zoneId}/custom_hostnames?per_page=100`);
      return response?.result || [];
    } catch (error) {
      logger.debug('Custom Hostnames not available:', error.message);
      return [];
    }
  }

  /**
   * Get Waiting Rooms for zone
   */
  async getWaitingRooms(zoneId) {
    try {
      const response = await this.rawRequest(`/zones/${zoneId}/waiting_rooms?per_page=100`);
      return response?.result || [];
    } catch (error) {
      logger.debug('Waiting Rooms not available:', error.message);
      return [];
    }
  }

  /**
   * Get Origin Certificates for zone
   */
  async getOriginCertificates(zoneId) {
    try {
      const response = await this.rawRequest(`/zones/${zoneId}/origin_tls_client_auth/hostnames/certificates?per_page=100`);
      return response?.result || [];
    } catch (error) {
      logger.debug('Origin Certificates not available:', error.message);
      return [];
    }
  }

  /**
   * Get Configuration Rules for zone
   */
  async getConfigurationRules(zoneId) {
    try {
      const response = await this.rawRequest(`/zones/${zoneId}/rulesets/phases/http_request_config/entrypoint`);
      return response?.result || {};
    } catch (error) {
      logger.debug('Configuration Rules not available:', error.message);
      return { error: error.message };
    }
  }

  /**
   * Get Transform Rules for zone
   */
  async getTransformRules(zoneId) {
    try {
      const [requestMods, responseMods, urlRewrites] = await Promise.all([
        this.rawRequest(`/zones/${zoneId}/rulesets/phases/http_request_late/entrypoint`).catch(() => null),
        this.rawRequest(`/zones/${zoneId}/rulesets/phases/http_response_headers/entrypoint`).catch(() => null),
        this.rawRequest(`/zones/${zoneId}/rulesets/phases/http_request_transform/entrypoint`).catch(() => null)
      ]);
      return {
        requestModifications: requestMods?.result?.rules || [],
        responseModifications: responseMods?.result?.rules || [],
        urlRewrites: urlRewrites?.result?.rules || []
      };
    } catch (error) {
      logger.debug('Transform Rules not available:', error.message);
      return { requestModifications: [], responseModifications: [], urlRewrites: [] };
    }
  }

  /**
   * Get Radar insights for account
   */
  async getRadarInsights(accountId) {
    try {
      const response = await this.rawRequest(`/accounts/${accountId}/radar/attacks/layer3/timeseries?per_page=100`);
      return response?.result || {};
    } catch (error) {
      logger.debug('Radar not available:', error.message);
      return { error: error.message };
    }
  }

  /**
   * Get Cloudflare One Agent enrollment status for account
   */
  async getDevicePolicy(accountId) {
    try {
      const response = await this.rawRequest(`/accounts/${accountId}/devices/policy?per_page=100`);
      return response?.result || {};
    } catch (error) {
      logger.debug('Device policy not available:', error.message);
      return { error: error.message };
    }
  }

  /**
   * Verify the current API token (active, not expired, scope summary).
   * GET /user/tokens/verify
   * Returns { id, status, not_before, expires_on, ... } or { error }.
   */
  async verifyToken() {
    try {
      // v5: user.tokens.verify path unchanged; returns result directly
      const res = await this.client.user.tokens.verify();
      return res || {};
    } catch (error) {
      logger.debug('Token verify failed, trying raw:', error.message);
      try {
        const response = await this.rawRequest('/user/tokens/verify');
        return response?.result || {};
      } catch (rawError) {
        logger.debug('Raw token verify also failed:', rawError.message);
        return { error: rawError.message };
      }
    }
  }

  /**
   * List R2 buckets in the account.
   * GET /accounts/{account_id}/r2/buckets
   */
  async getR2Buckets(accountId) {
    try {
      const response = await this.rawRequest(`/accounts/${accountId}/r2/buckets?per_page=100`);
      const buckets = response?.result?.buckets || response?.result || [];
      const enriched = await Promise.all(
        (Array.isArray(buckets) ? buckets : []).map(async (bucket) => {
          const name = bucket.name || bucket.bucket_name || bucket.id;
          if (!name) return bucket;
          const [domains, lifecycle, eventNotifs, cors] = await Promise.all([
            this.rawRequest(`/accounts/${accountId}/r2/buckets/${encodeURIComponent(name)}/domains/custom`)
              .then(r => r?.result?.domains || r?.result || [])
              .catch(() => []),
            this.rawRequest(`/accounts/${accountId}/r2/buckets/${encodeURIComponent(name)}/lifecycle`)
              .then(r => r?.result?.rules || r?.result || [])
              .catch(() => []),
            this.rawRequest(`/accounts/${accountId}/event_notifications/r2/${encodeURIComponent(name)}/configuration`)
              .then(r => r?.result?.queues || r?.result || [])
              .catch(() => []),
            this.rawRequest(`/accounts/${accountId}/r2/buckets/${encodeURIComponent(name)}/cors`)
              .then(r => r?.result?.rules || r?.result || [])
              .catch(() => [])
          ]);
          return {
            ...bucket,
            name,
            customDomains: domains,
            lifecycleRules: lifecycle,
            eventNotifications: eventNotifs,
            corsRules: cors
          };
        })
      );
      return enriched;
    } catch (error) {
      logger.debug('R2 not available:', error.message);
      return { error: error.message };
    }
  }

  /**
   * Get WAF managed rulesets deployed at zone scope.
   * GET /zones/{zone_id}/rulesets
   * Filters for kind=managed, phase=http_request_firewall_managed.
   * Each entry includes id, version, action overrides — used to detect log-only drift.
   */
  async getWAFManagedRulesets(zoneId) {
    try {
      // v5: rulesets is a top-level resource
      const rulesetsPage = await this.client.rulesets.list({ zone_id: zoneId });
      const rulesetsRes = this._unwrapList(rulesetsPage);
      const rulesets = rulesetsRes.result || [];

      const entryPoints = rulesets.filter(r =>
        r.kind === 'zone' && r.phase === 'http_request_firewall_managed'
      );

      const managedDeployments = [];
      for (const ep of entryPoints) {
        try {
          // v5: .get(rulesetId, { zone_id }) — positional rulesetId arg
          const detail = await this.client.rulesets.get(ep.id, { zone_id: zoneId });
          const rules = detail?.rules || [];
          for (const rule of rules) {
            if (rule.action === 'execute' && rule.action_parameters?.id) {
              managedDeployments.push({
                rulesetId: rule.action_parameters.id,
                rulesetVersion: rule.action_parameters.version || 'latest',
                ruleId: rule.id,
                enabled: rule.enabled !== false,
                expression: rule.expression,
                description: rule.description,
                overrides: rule.action_parameters.overrides || null,
                ref: rule.ref
              });
            }
          }
        } catch (err) {
          logger.debug(`Failed to fetch entry point ${ep.id}:`, err.message);
        }
      }
      return managedDeployments;
    } catch (error) {
      logger.debug('WAF managed rulesets not available:', error.message);
      return { error: error.message };
    }
  }

  // ---------------------------------------------------------------------------
  // Phase 2-4 read surface: leaked creds, rulesets, security.txt, notifications,
  // DNS records, zone hold, account members, workers, KV, D1, queues, zaraz,
  // account-scoped WAF/posture/access/CASB/email-security/RBI/magic. Read-only.
  // ---------------------------------------------------------------------------

  /**
   * Read Leaked Credentials Detection status for a zone.
   * @returns {Promise<{value: {enabled: boolean}, raw: object}>}
   */
  async getLeakedCredChecks(zoneId) {
    try {
      const data = await this.rawRequest(`/zones/${zoneId}/leaked-credential-checks`);
      return { value: data?.result || { enabled: false }, raw: data?.result || null };
    } catch (error) {
      return { value: { enabled: false }, raw: { error: error.message } };
    }
  }

  /**
   * Read a specific ruleset phase entrypoint for a zone (e.g. http_request_firewall_managed,
   * ddos_l7). Returns {id, rules, kind, phase, ...} or null if not found.
   */
  async getRulesetPhase(zoneId, phase) {
    try {
      const data = await this.rawRequest(`/zones/${zoneId}/rulesets/phases/${phase}/entrypoint`);
      return data?.result || null;
    } catch (error) {
      if (error.status === 404 || /not found/i.test(error.message)) return null;
      throw error;
    }
  }

  /** List account-scoped rulesets (read for coverage assessment). */
  async getAccountRulesets(accountId) {
    try {
      const data = await this.rawRequest(`/accounts/${accountId}/rulesets`);
      return data?.result || [];
    } catch (error) {
      return { error: error.message };
    }
  }

  /** Read DDoS L7 ruleset posture for a zone (read-only). */
  async getDDoSL7Ruleset(zoneId) {
    try {
      const data = await this.rawRequest(`/zones/${zoneId}/rulesets/phases/ddos_l7/entrypoint`);
      return data?.result || null;
    } catch (error) {
      return { error: error.message };
    }
  }

  /** Read existing security.txt (already exposes getSecurityTxt above; alias for clarity). */

  /** List notification policies for an account. */
  async getNotificationPolicies(accountId) {
    try {
      const data = await this.rawRequest(`/accounts/${accountId}/alerting/v3/policies`);
      return data?.result || [];
    } catch (error) {
      return { error: error.message };
    }
  }

  /** List available alert types for an account (drives the notification recipes). */
  async getAvailableAlerts(accountId) {
    try {
      const data = await this.rawRequest(`/accounts/${accountId}/alerting/v3/available_alerts`);
      return data?.result || [];
    } catch (error) {
      return { error: error.message };
    }
  }

  /** Read zone hold status. */
  async getZoneHold(zoneId) {
    try {
      const data = await this.rawRequest(`/zones/${zoneId}/hold`);
      return data?.result || null;
    } catch (error) {
      return { error: error.message };
    }
  }

  /** List Workers scripts for an account. */
  async getWorkersScripts(accountId) {
    try {
      const data = await this.rawRequest(`/accounts/${accountId}/workers/scripts`);
      return data?.result || [];
    } catch (error) {
      return { error: error.message };
    }
  }

  /** List Workers script bindings (top-level array per v5 API). */
  async getWorkersBindings(accountId, scriptName) {
    try {
      const data = await this.rawRequest(`/accounts/${accountId}/workers/scripts/${scriptName}/bindings`);
      return Array.isArray(data) ? data : (data?.result || []);
    } catch (error) {
      return { error: error.message };
    }
  }

  /** List Workers routes (zone-scoped). */
  async getWorkersRoutes(zoneId) {
    try {
      const data = await this.rawRequest(`/zones/${zoneId}/workers/routes`);
      return data?.result || [];
    } catch (error) {
      return { error: error.message };
    }
  }

  /** List KV namespaces for an account. */
  async getKVNamespaces(accountId) {
    try {
      const data = await this.rawRequest(`/accounts/${accountId}/storage/kv/namespaces`);
      return data?.result || [];
    } catch (error) {
      return { error: error.message };
    }
  }

  /** List D1 databases for an account. */
  async getD1Databases(accountId) {
    try {
      const data = await this.rawRequest(`/accounts/${accountId}/d1/database`);
      return data?.result || [];
    } catch (error) {
      return { error: error.message };
    }
  }

  /** List Queues for an account. */
  async getQueues(accountId) {
    try {
      const data = await this.rawRequest(`/accounts/${accountId}/queues`);
      return data?.result || [];
    } catch (error) {
      return { error: error.message };
    }
  }

  /** Read Zaraz published config (excludes secret values). */
  async getZarazConfig(zoneId) {
    try {
      const data = await this.rawRequest(`/zones/${zoneId}/settings/zaraz/config`);
      return data?.result || null;
    } catch (error) {
      return { error: error.message };
    }
  }

  /** List device posture rules (Enterprise, account-scoped). */
  async getDevicePosture(accountId) {
    try {
      const data = await this.rawRequest(`/accounts/${accountId}/devices/posture`);
      return data?.result || [];
    } catch (error) {
      return { error: error.message };
    }
  }

  /** List Access applications + their policies (Enterprise, account-scoped). */
  async getAccessApplications(accountId) {
    try {
      const apps = await this.rawRequest(`/accounts/${accountId}/access/applications`);
      const appList = apps?.result || [];
      // Fetch policies for each app (best-effort, bounded)
      const enriched = await Promise.all(appList.slice(0, 50).map(async app => {
        try {
          const pols = await this.rawRequest(`/accounts/${accountId}/access/applications/${app.id}/policies`);
          return { ...app, policies: pols?.result || [] };
        } catch {
          return { ...app, policies: [], policyError: 'unreadable' };
        }
      }));
      return enriched;
    } catch (error) {
      return { error: error.message };
    }
  }

  /** List CASB integrations and findings (Enterprise, account-scoped). */
  async getCASBFindings(accountId) {
    try {
      const data = await this.rawRequest(`/accounts/${accountId}/casb/findings`);
      return data?.result || [];
    } catch (error) {
      return { error: error.message };
    }
  }

  /** List Cloud Email Security policies (Enterprise, account-scoped). */
  async getEmailSecurityPolicies(accountId) {
    try {
      const data = await this.rawRequest(`/accounts/${accountId}/email-security/policies`);
      return data?.result || [];
    } catch (error) {
      return { error: error.message };
    }
  }

  /** Inspect gateway HTTP policies for browser-isolation actions (Enterprise). */
  async getBrowserIsolationPolicies(accountId) {
    try {
      const data = await this.rawRequest(`/accounts/${accountId}/gateway/rules`);
      const rules = data?.result || [];
      return rules.filter(r => (r.actions || []).some(a => a === 'isolate' || a?.action === 'isolate'));
    } catch (error) {
      return { error: error.message };
    }
  }

  /** List Magic Transit/Firewall ruleset IDs (Enterprise). */
  async getMagicFirewallRulesets(accountId) {
    try {
      const data = await this.rawRequest(`/accounts/${accountId}/rulesets?phase=magic_transit`);
      return data?.result || [];
    } catch (error) {
      return { error: error.message };
    }
  }

  // ---------------------------------------------------------------------------
  // Mutation wrappers (remediation)
  //
  // The assessment surface of this client is read-only. The methods below are
  // the ONLY sanctioned write paths and are used exclusively by the remediation
  // recipe registry. Every write is logged via logger.mutation for auditability.
  // ---------------------------------------------------------------------------

  /**
   * Read a single zone setting value.
   * @returns {Promise<{value: *, raw: object}>}
   */
  async getZoneSetting(zoneId, setting) {
    const data = await this.rawRequest(`/zones/${zoneId}/settings/${setting}`);
    return { value: data?.result?.value ?? null, raw: data?.result ?? null };
  }

  /**
   * Patch a single zone setting (e.g. ssl, min_tls_version, always_use_https).
   * @returns {Promise<object>} the Cloudflare result object
   */
  async patchZoneSetting(zoneId, setting, value) {
    logger.mutation(`PATCH /zones/${zoneId}/settings/${setting}`, { value });
    const data = await this.rawRequest(`/zones/${zoneId}/settings/${setting}`, {
      method: 'PATCH',
      body: { value }
    });
    return data?.result ?? null;
  }

  /**
   * Read DNSSEC status for a zone.
   * @returns {Promise<{value: string|null, raw: object}>}
   */
  async getDnssec(zoneId) {
    const data = await this.rawRequest(`/zones/${zoneId}/dnssec`);
    return { value: data?.result?.status ?? null, raw: data?.result ?? null };
  }

  /**
   * Update DNSSEC status for a zone ('active' | 'disabled').
   * @returns {Promise<object>} the Cloudflare result object
   */
  async setDnssec(zoneId, status) {
    logger.mutation(`PATCH /zones/${zoneId}/dnssec`, { status });
    const data = await this.rawRequest(`/zones/${zoneId}/dnssec`, {
      method: 'PATCH',
      body: { status }
    });
    return data?.result ?? null;
  }

  // --- Phase 2-4 mutation wrappers: create/delete recipes --------------------

  /**
   * Enable/disable Leaked Credentials Detection for a zone (non-blocking,
   * detection-only — does not change traffic behavior).
   * @returns {Promise<object>} the Cloudflare result object
   */
  async setLeakedCredChecks(zoneId, enabled) {
    logger.mutation(`POST /zones/${zoneId}/leaked-credential-checks`, { enabled });
    const data = await this.rawRequest(`/zones/${zoneId}/leaked-credential-checks`, {
      method: 'POST',
      body: { enabled: !!enabled }
    });
    return data?.result ?? null;
  }

  /**
   * PUT a ruleset phase entrypoint (e.g. deploy WAF managed in log mode).
   * @param {string} zoneId
   * @param {string} phase e.g. 'http_request_firewall_managed'
   * @param {object[]} rules rules array
   * @returns {Promise<object>}
   */
  async putRulesetPhase(zoneId, phase, rules) {
    logger.mutation(`PUT /zones/${zoneId}/rulesets/phases/${phase}/entrypoint`, { ruleCount: rules.length });
    const data = await this.rawRequest(`/zones/${zoneId}/rulesets/phases/${phase}/entrypoint`, {
      method: 'PUT',
      body: { rules }
    });
    return data?.result ?? null;
  }

  /**
   * Add a single rule to a ruleset (returns the created rule with id).
   * @returns {Promise<{id: string, ...}>}
   */
  async createRulesetRule(zoneId, rulesetId, body) {
    logger.mutation(`POST /zones/${zoneId}/rulesets/${rulesetId}/rules`, { action: body?.action });
    const data = await this.rawRequest(`/zones/${zoneId}/rulesets/${rulesetId}/rules`, {
      method: 'POST',
      body
    });
    return data?.result ?? null;
  }

  /** Delete a single rule from a ruleset (by id). */
  async deleteRulesetRule(zoneId, rulesetId, ruleId) {
    logger.mutation(`DELETE /zones/${zoneId}/rulesets/${rulesetId}/rules/${ruleId}`);
    await this.rawRequest(`/zones/${zoneId}/rulesets/${rulesetId}/rules/${ruleId}`, {
      method: 'DELETE'
    });
    return true;
  }

  /**
   * PUT security.txt for a zone. Fields: contact[], expires, enabled, encryption[],
   * policy[], canonical[], acknowledgments[], hiring[], preferred_languages.
   * @returns {Promise<object>}
   */
  async putSecurityTxt(zoneId, payload) {
    logger.mutation(`PUT /zones/${zoneId}/security-center/securitytxt`, {
      enabled: payload?.enabled, contactCount: payload?.contact?.length, expires: payload?.expires
    });
    const data = await this.rawRequest(`/zones/${zoneId}/security-center/securitytxt`, {
      method: 'PUT',
      body: payload
    });
    return data?.result ?? null;
  }

  /** Delete security.txt for a zone (revert). */
  async deleteSecurityTxt(zoneId) {
    logger.mutation(`DELETE /zones/${zoneId}/security-center/securitytxt`);
    await this.rawRequest(`/zones/${zoneId}/security-center/securitytxt`, {
      method: 'DELETE'
    });
    return true;
  }

  /**
   * Create a notification policy. Body shape: {name, description, enabled, alert_type,
   * mechanisms: {email:[{id}], webhooks:[{id}]}, filters}.
   * @returns {Promise<{id: string, ...}>} the new policy
   */
  async createNotificationPolicy(accountId, body) {
    logger.mutation(`POST /accounts/${accountId}/alerting/v3/policies`, {
      name: body?.name, alert_type: body?.alert_type, enabled: body?.enabled
    });
    const data = await this.rawRequest(`/accounts/${accountId}/alerting/v3/policies`, {
      method: 'POST',
      body
    });
    return data?.result ?? null;
  }

  /** Delete a notification policy by id. */
  async deleteNotificationPolicy(accountId, policyId) {
    logger.mutation(`DELETE /accounts/${accountId}/alerting/v3/policies/${policyId}`);
    await this.rawRequest(`/accounts/${accountId}/alerting/v3/policies/${policyId}`, {
      method: 'DELETE'
    });
    return true;
  }

  /**
   * Create a DNS record. Body shape: {type, name, content, ttl, proxied?, comment?}.
   * @returns {Promise<{id: string, ...}>}
   */
  async createDNSRecord(zoneId, body) {
    logger.mutation(`POST /zones/${zoneId}/dns_records`, {
      type: body?.type, name: body?.name
    });
    const data = await this.rawRequest(`/zones/${zoneId}/dns_records`, {
      method: 'POST',
      body
    });
    return data?.result ?? null;
  }

  /** Delete a DNS record by id. */
  async deleteDNSRecord(zoneId, recordId) {
    logger.mutation(`DELETE /zones/${zoneId}/dns_records/${recordId}`);
    await this.rawRequest(`/zones/${zoneId}/dns_records/${recordId}`, {
      method: 'DELETE'
    });
    return true;
  }

  /**
   * Enable zone hold (anti-takeover). Body: {include_subdomains: bool, hold_after?: ISO}.
   * @returns {Promise<{id?: string, hold: boolean, ...}>}
   */
  async setZoneHold(zoneId, body) {
    logger.mutation(`POST /zones/${zoneId}/hold`, body);
    const data = await this.rawRequest(`/zones/${zoneId}/hold`, {
      method: 'POST',
      body: body || {}
    });
    return data?.result ?? null;
  }

  /** Remove zone hold. */
  async removeZoneHold(zoneId) {
    logger.mutation(`DELETE /zones/${zoneId}/hold`);
    await this.rawRequest(`/zones/${zoneId}/hold`, { method: 'DELETE' });
    return true;
  }

  /**
   * Toggle account-wide 2FA enforcement. Body: {settings: {enforce_twofactor: bool}}.
   * @returns {Promise<object>}
   */
  async enforceAccount2FA(accountId, enabled) {
    logger.mutation(`PUT /accounts/${accountId}`, { enforce_twofactor: !!enabled });
    const data = await this.rawRequest(`/accounts/${accountId}`, {
      method: 'PUT',
      body: { settings: { enforce_twofactor: !!enabled } }
    });
    return data?.result ?? null;
  }
}

module.exports = CloudflareClient;