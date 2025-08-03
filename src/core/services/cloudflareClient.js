/**
 * @fileoverview Cloudflare API Client Service
 * @description Native API client using Cloudflare v4 SDK for security assessments with debug logging
 * @module services/cloudflareClient
 */

const Cloudflare = require('cloudflare');
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
      tokenPrefix: apiToken?.substring(0, 10) + '...',
      debugMode: this.debugMode
    });

    // Initialize Cloudflare client with API token only
    // v4 SDK uses apiToken property
    const clientConfig = {
      apiToken: apiToken.trim() // Ensure no whitespace
    };
    
    if (this.debugMode) {
      logger.cloudflare('Creating Cloudflare client with config', {
        configKeys: Object.keys(clientConfig),
        hasApiToken: !!clientConfig.apiToken,
        tokenType: apiToken.startsWith('v1.0-') ? 'Custom Token' : 'Standard Token',
        sdkVersion: '4.5.0'
      });
    }
    
    try {
      this.client = new Cloudflare(clientConfig);
      
      // Test if the client was initialized properly
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
    this.rateLimitRemaining = 1200; // Default Cloudflare rate limit
    this.rateLimitReset = Date.now() + (5 * 60 * 1000); // 5 minutes from now
    this.requestCount = 0;
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
      
      // Enhanced error logging for debugging
      const errorDetails = {
        requestId,
        duration,
        message: error.message,
        code: error.code,
        statusCode: error.response?.status || error.statusCode,
        responseData: error.response?.data || error.data,
        responseBody: error.response?.body,
        headers: error.response?.headers,
        config: {
          url: error.config?.url,
          method: error.config?.method,
          headers: error.config?.headers ? Object.keys(error.config.headers) : []
        }
      };
      
      logger.error('Cloudflare API error:', errorDetails);
      
      // If it's a 403, provide more specific error message
      if (error.response?.status === 403 || error.message?.includes('403')) {
        const errorData = error.response?.data || error.data || {};
        const errorMessage = errorData.errors?.[0]?.message || error.message;
        throw new Error(`Cloudflare API Authentication Failed (403): ${errorMessage}. Please verify your API token has the required permissions.`);
      }
      
      throw error;
    }
  }

  /**
   * Test API connection and get account info
   */
  async testConnection() {
    try {
      logger.info('Testing Cloudflare connection', { hasToken: !!this.apiToken });
      
      return await this.executeWithRateLimit(async () => {
        // Start with zones list - requires less permissions than user.get()
        logger.info('Fetching zones to test connection...');
        
        if (this.debugMode) {
          logger.cloudflare('Calling client.zones.list()', {
            method: 'GET',
            endpoint: '/zones'
          });
        }
        
        const zones = await this.client.zones.list({});
        
        if (this.debugMode) {
          logger.cloudflare('Zones response received', {
            count: zones.result?.length || 0,
            totalCount: zones.result_info?.total_count,
            success: zones.success,
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
          
          const user = await this.client.user.get();
          
          if (this.debugMode) {
            logger.cloudflare('User response received', {
              userId: user.result?.id,
              email: user.result?.email,
              success: user.success
            });
          }
          
          userInfo = user.result;
          
          // Try to get account info from zones or user data
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
          
          // Fallback: get account info from first zone if available
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
        code: error.code,
        stack: error.stack,
        response: error.response?.data
      });
      
      // Check if it's a permission error
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
      
      const zone = await this.client.zones.get({ zone_id: zoneId });
      
      if (this.debugMode) {
        logger.cloudflare('Zone details received', {
          zoneId,
          name: zone.result?.name,
          status: zone.result?.status,
          plan: zone.result?.plan?.name
        });
      }
      
      return zone.result;
    });
  }

  /**
   * List all zones
   */
  async listZones() {
    return this.executeWithRateLimit(async () => {
      const zones = await this.client.zones.list({});
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
        // v4 SDK: Check if DNS records endpoint exists
        if (!this.client.zones?.dnsRecords?.list) {
          logger.debug('DNS records API not available on this client/token', { zoneId });
          return [];
        }
        
        if (this.debugMode) {
          logger.cloudflare('Getting DNS records', {
            zoneId,
            method: 'GET',
            endpoint: `/zones/${zoneId}/dns_records`
          });
        }
        
        // v4 SDK: Correct API path
        const records = await this.client.zones.dnsRecords.list({ zone_id: zoneId });
        
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
        // v4 SDK: Analytics API has different structure
        const since = new Date(Date.now() - 24 * 60 * 60 * 1000).toISOString();
        const until = new Date().toISOString();
        
        const analytics = await this.client.zones.analytics.dashboard({ 
          zone_id: zoneId,
          since,
          until
        });
        return analytics.result;
      } catch (error) {
        logger.warn('Analytics not available:', error.message);
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
        // Get SSL/TLS mode setting
        const sslMode = await this.client.zones.settings.get('ssl', { 
          zone_id: zoneId 
        });
        
        // Get other SSL-related settings
        let universalSSL = { result: null };
        let certificatePacks = { result: [] };
        let customCerts = { result: [] };
        
        // Check if SSL endpoints exist
        if (this.client.zones?.ssl) {
          [universalSSL, certificatePacks, customCerts] = await Promise.all([
            this.client.zones.ssl.universalSettings?.get({ zone_id: zoneId }).catch(e => ({ result: null })) || { result: null },
            this.client.zones.ssl.certificatePacks?.list({ zone_id: zoneId }).catch(e => ({ result: [] })) || { result: [] },
            this.client.zones.ssl.customCertificates?.list({ zone_id: zoneId }).catch(e => ({ result: [] })) || { result: [] }
          ]);
        }

        return {
          settings: {
            value: sslMode?.result?.value || 'flexible',
            mode: sslMode?.result?.value || 'flexible',
            universal_ssl: universalSSL?.result?.enabled
          },
          certificates: certificatePacks?.result || [],
          customCertificates: customCerts?.result || [],
          universal: universalSSL?.result || {}
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
        
        // Get security level setting
        try {
          const securityLevel = await this.client.zones.settings.get('security_level', { 
            zone_id: zoneId 
          });
          settings.security_level = securityLevel?.result?.value || 'medium';
        } catch (e) {
          settings.security_level = 'medium';
        }
        
        // Check if WAF packages endpoint exists before using it
        let wafRules = [];
        if (this.client.zones?.waf?.packages?.list) {
          try {
            const wafPackages = await this.client.zones.waf.packages.list({ zone_id: zoneId });
            wafRules = wafPackages?.result || [];
          } catch (e) {
            logger.debug('WAF packages not available:', e.message);
          }
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
        // Check if Zero Trust endpoints exist
        // In SDK v4.5.0, Zero Trust resources are accessed via zeroTrust property
        const hasZeroTrustAPI = !!(
          this.client.zeroTrust?.access?.applications?.list ||
          this.client.zeroTrust?.organizations?.get ||
          this.client.zeroTrust?.access?.groups?.list
        );

        if (!hasZeroTrustAPI) {
          logger.debug('Zero Trust API endpoints not found in SDK', { accountId });
          return { error: 'Zero Trust API not available' };
        }
        
        // Try multiple endpoints to detect Zero Trust availability
        let zeroTrustAvailable = false;
        let applications = null;
        let organization = null;

        // Try to get organization settings first (least permission required)
        try {
          if (this.client.zeroTrust?.organizations?.get) {
            organization = await this.client.zeroTrust.organizations.get({ 
              account_id: accountId 
            });
            zeroTrustAvailable = true;
          }
        } catch (e) {
          logger.debug('Zero Trust organization check failed:', e.message);
        }

        // Try to get applications
        try {
          if (this.client.zeroTrust?.access?.applications?.list) {
            applications = await this.client.zeroTrust.access.applications.list({ 
              account_id: accountId 
            });
            zeroTrustAvailable = true;
          }
        } catch (e) {
          logger.debug('Zero Trust applications check failed:', e.message);
        }

        // Try to get access groups as another indicator
        let accessGroups = null;
        try {
          if (this.client.zeroTrust?.access?.groups?.list) {
            accessGroups = await this.client.zeroTrust.access.groups.list({ 
              account_id: accountId 
            });
            zeroTrustAvailable = true;
          }
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
          // Access Policies
          this.getZeroTrustPolicies(accountId),
          // Identity Providers
          this.client.zeroTrust?.identityProviders?.list({ 
            account_id: accountId 
          }).catch(() => ({ result: [] })),
          // Service Tokens
          this.client.zeroTrust?.access?.serviceTokens?.list({ 
            account_id: accountId 
          }).catch(() => ({ result: [] })),
          // Tunnels
          this.client.zeroTrust?.tunnels?.list({ 
            account_id: accountId 
          }).catch(() => ({ result: [] })),
          // Device Policies
          this.client.zeroTrust?.devices?.policies?.list({ 
            account_id: accountId 
          }).catch(() => ({ result: [] })),
          // WARP Settings
          this.getWARPSettings(accountId),
          // Gateway Rules
          this.client.zeroTrust?.gateway?.rules?.list({ 
            account_id: accountId 
          }).catch(() => ({ result: [] })),
          // DLP Profiles
          this.client.zeroTrust?.dlp?.profiles?.list({ 
            account_id: accountId 
          }).catch(() => ({ result: [] }))
        ]);

        // Get device enrollment rules if available
        const deviceEnrollmentRules = await this.client.zeroTrust?.devices?.enrollmentRules?.list({
          account_id: accountId
        }).catch(() => ({ result: [] }));

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
          organization: organization?.result || {},
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
      // Fetch all Access policies for all applications
      const applications = await this.client.zeroTrust?.access?.applications?.list({ 
        account_id: accountId 
      }).catch(() => ({ result: [] }));

      const allPolicies = [];
      
      // Get policies for each application
      for (const app of (applications.result || [])) {
        try {
          const appPolicies = await this.client.zeroTrust?.access?.applications?.policies?.list({
            account_id: accountId,
            uuid: app.id
          });
          
          // Add application context to each policy
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
      // WARP settings might be under different endpoints
      const settings = await this.client.zeroTrust?.devices?.settings?.get({
        account_id: accountId
      }).catch(() => null);
      
      if (!settings) {
        // Try alternative endpoint for WARP client settings
        const warpClientSettings = await this.client.zeroTrust?.gateway?.configurations?.get({
          account_id: accountId
        }).catch(() => null);
        
        return warpClientSettings?.result || {};
      }
      
      return settings.result || {};
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
        
        const members = await this.client.accounts.members.list({ 
          account_id: accountId 
        });
        
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
        if (this.debugMode) {
          logger.cloudflare('Account members fetch failed', {
            accountId,
            error: error.message,
            code: error.code
          });
        }
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
        const logs = await this.client.accounts.auditLogs.list({ 
          account_id: accountId,
          ...params
        });
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
        // Get various performance-related settings
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
              const result = await this.client.zones.settings.get(setting, { 
                zone_id: zoneId 
              });
              settings[setting] = result?.result;
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
        // The Cloudflare v4 SDK doesn't have a direct DNSSEC endpoint
        // We need to make a raw API request using Node.js built-in fetch (Node 18+)
        const makeRawRequest = async (path, method = 'GET') => {
          const response = await fetch(`https://api.cloudflare.com/client/v4${path}`, {
            method,
            headers: {
              'Authorization': `Bearer ${this.apiToken}`,
              'Content-Type': 'application/json'
            }
          });
          return response.json();
        };
        
        // Try to get DNSSEC status via raw API
        try {
          const dnssecResponse = await makeRawRequest(`/zones/${zoneId}/dnssec`);
          
          logger.info('DNSSEC Raw API Response', {
            zoneId,
            success: dnssecResponse?.success,
            errors: dnssecResponse?.errors,
            hasResult: !!dnssecResponse?.result,
            status: dnssecResponse?.result?.status,
            rawResult: JSON.stringify(dnssecResponse?.result)
          });
          
          if (dnssecResponse?.success && dnssecResponse?.result) {
            return dnssecResponse.result;
          }
        } catch (rawError) {
          logger.debug('Raw DNSSEC API failed:', rawError.message);
        }
        
        // Fallback: Check if DNSSEC endpoint exists in SDK (for compatibility)
        if (!this.client.zones?.dnssec?.get) {
          logger.debug('DNSSEC API not available in SDK', { zoneId });
          return { status: 'disabled', error: 'API not available' };
        }
        
        if (this.debugMode) {
          logger.cloudflare('Getting DNSSEC settings', {
            zoneId,
            method: 'GET',
            endpoint: `/zones/${zoneId}/dnssec`
          });
        }
        
        const dnssec = await this.client.zones.dnssec.get({ zone_id: zoneId });
        
        // Enhanced debugging to understand DNSSEC response structure
        logger.info('DNSSEC API Response', {
          zoneId,
          success: dnssec?.success,
          hasResult: !!dnssec?.result,
          resultKeys: dnssec?.result ? Object.keys(dnssec.result) : [],
          status: dnssec?.result?.status,
          flags: dnssec?.result?.flags,
          algorithm: dnssec?.result?.algorithm,
          digest_type: dnssec?.result?.digest_type,
          digest_algorithm: dnssec?.result?.digest_algorithm,
          digest: dnssec?.result?.digest,
          ds: dnssec?.result?.ds,
          key_tag: dnssec?.result?.key_tag,
          public_key: dnssec?.result?.public_key ? 'present' : 'absent',
          rawResult: JSON.stringify(dnssec?.result)
        });
        
        if (this.debugMode) {
          logger.cloudflare('DNSSEC settings received', {
            zoneId,
            status: dnssec.result?.status,
            algorithm: dnssec.result?.algorithm,
            digest_type: dnssec.result?.digest_type
          });
        }
        
        return dnssec.result || { status: 'disabled' };
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
        // Check if analytics endpoint exists
        if (!this.client.zones?.analytics?.dashboard) {
          logger.debug('Analytics API not available on this client/token', { zoneId });
          return null;
        }
        
        const since = new Date(Date.now() - 24 * 60 * 60 * 1000).toISOString();
        const until = new Date().toISOString();
        
        const analytics = await this.client.zones.analytics.dashboard({ 
          zone_id: zoneId,
          since,
          until
        });
        
        const data = analytics?.result?.data?.[0] || {};
        return {
          threats_blocked: data.threats || 0,
          requests_challenged: data.pageviews || 0,
          requests_passed: data.requests || 0
        };
      } catch (error) {
        logger.warn('Security analytics not available:', error.message);
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
        
        // Fetch all settings in parallel
        const results = await Promise.allSettled(
          settingNames.map(async (setting) => {
            try {
              const result = await this.client.zones.settings.get(setting, { 
                zone_id: zoneId 
              });
              return { name: setting, value: result?.result };
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
        // v4 SDK: Check if rulesets endpoint exists
        if (!this.client.zones?.rulesets?.list) {
          logger.debug('Rulesets API not available on this client/token', { zoneId });
          return [];
        }
        
        // v4 SDK: Firewall rules are now part of Rulesets
        const rulesets = await this.client.zones.rulesets.list({ zone_id: zoneId });
        
        // Filter for firewall rulesets
        const firewallRulesets = rulesets.result?.filter(rs => 
          rs.phase === 'http_request_firewall_custom'
        ) || [];
        
        // Get rules for each ruleset
        const allRules = [];
        for (const ruleset of firewallRulesets) {
          const rules = await this.client.zones.rulesets.get({ 
            zone_id: zoneId, 
            ruleset_id: ruleset.id 
          });
          allRules.push(...(rules.result?.rules || []));
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
        // v4 SDK: Check if access rules endpoint exists
        if (!this.client.zones?.accessRules?.list) {
          logger.debug('Access rules API not available on this client/token', { zoneId });
          return [];
        }
        
        // v4 SDK: IP Access Rules
        const rules = await this.client.zones.accessRules.list({ 
          zone_id: zoneId 
        });
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
        // v4 SDK: Check if page rules endpoint exists
        if (!this.client.zones?.pagerules?.list) {
          logger.debug('Page rules API not available on this client/token', { zoneId });
          return [];
        }
        
        const rules = await this.client.zones.pagerules.list({ zone_id: zoneId });
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
        // v4 SDK: Check if rate limiting endpoint exists
        if (!this.client.zones?.ratelimits?.list) {
          logger.debug('Rate limiting API not available on this client/token', { zoneId });
          return [];
        }
        
        // v4 SDK: Rate limiting rules are now handled differently
        const rules = await this.client.zones.ratelimits.list({ zone_id: zoneId });
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
        // v4 SDK: Check if load balancers endpoint exists
        if (!this.client.zones?.loadBalancers?.list) {
          logger.debug('Load balancers API not available on this client/token', { zoneId });
          return {
            load_balancers: [],
            pools: [],
            monitors: []
          };
        }
        
        const loadBalancers = await this.client.zones.loadBalancers.list({ 
          zone_id: zoneId 
        });
        
        // Get pools and monitors if load balancers exist (these are account-level)
        if (loadBalancers.result?.length > 0 && accountId) {
          const [pools, monitors] = await Promise.all([
            this.client.accounts.loadBalancers.pools.list({ account_id: accountId }).catch(() => ({ result: [] })),
            this.client.accounts.loadBalancers.monitors.list({ account_id: accountId }).catch(() => ({ result: [] }))
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
        // v4 SDK: Bot management settings are under zone settings
        const botFightMode = await this.client.zones.settings.get('bot_fight_mode', { 
          zone_id: zoneId
        });
        
        // Also try to get super bot fight mode for paid plans
        let superBotFightMode = null;
        try {
          superBotFightMode = await this.client.zones.settings.get('super_bot_fight_mode', { 
            zone_id: zoneId
          });
        } catch (e) {
          // Super bot fight mode not available on free plans
        }
        
        return {
          enabled: botFightMode?.result?.value === 'on' || superBotFightMode?.result?.value === 'on',
          bot_fight_mode: botFightMode?.result?.value,
          super_bot_fight_mode: superBotFightMode?.result?.value
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
        // v4 SDK: Workers are account-level, not zone-level
        const scripts = await this.client.accounts.workers.scripts.list({ 
          account_id: accountId 
        });
        
        const workers = [];
        
        // Get details for each worker
        for (const script of (scripts.result || [])) {
          try {
            const details = await this.client.accounts.workers.scripts.get({ 
              account_id: accountId,
              script_name: script.id
            });
            workers.push({
              ...script,
              ...details.result
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
        const projects = await this.client.accounts.pages.projects.list({ 
          account_id: accountId 
        });
        
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
        // v4 SDK: API Shield endpoints
        const [schemas, endpoints] = await Promise.all([
          this.client.zones.apiShield.schemas.list({ zone_id: zoneId }).catch(() => ({ result: [] })),
          this.client.zones.apiShield.endpoints.list({ zone_id: zoneId }).catch(() => ({ result: [] }))
        ]);
        
        return {
          enabled: (schemas.result?.length || 0) > 0 || (endpoints.result?.length || 0) > 0,
          schemas: schemas.result || [],
          endpoints: endpoints.result || []
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
        // v4 SDK: Check if email routing endpoint exists
        if (!this.client.zones?.emailRouting?.rules?.list) {
          logger.debug('Email routing API not available on this client/token', { zoneId });
          return [];
        }
        
        const rules = await this.client.zones.emailRouting.rules.list({ 
          zone_id: zoneId 
        });
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
        // Check if Security Center API exists
        if (!this.client.securityCenter?.insights?.list) {
          logger.debug('Security Center API not available on this client/token');
          return {
            insights: [],
            error: 'Security Center API not available'
          };
        }

        if (this.debugMode) {
          logger.cloudflare('Getting Security Center Insights', {
            hasAccountId: !!params.accountId,
            hasZoneId: !!params.zoneId,
            method: 'GET',
            endpoint: '/security-center/insights'
          });
        }

        // Prepare API parameters
        const apiParams = {
          dismissed: false, // Only get active insights
          per_page: 100    // Get more insights per page
        };

        // Either account_id or zone_id is required
        if (params.accountId) {
          apiParams.account_id = params.accountId;
        } else if (params.zoneId) {
          apiParams.zone_id = params.zoneId;
        } else {
          throw new Error('Either accountId or zoneId is required for Security Insights');
        }

        // Add optional filters
        if (params.severity) {
          apiParams.severity = Array.isArray(params.severity) ? params.severity : [params.severity];
        }
        if (params.issueClass) {
          apiParams.issue_class = Array.isArray(params.issueClass) ? params.issueClass : [params.issueClass];
        }
        if (params.issueType) {
          apiParams.issue_type = Array.isArray(params.issueType) ? params.issueType : [params.issueType];
        }

        // Fetch insights
        const response = await this.client.securityCenter.insights.list(apiParams);
        
        if (this.debugMode) {
          logger.cloudflare('Security Insights response received', {
            count: response.count || 0,
            pageCount: response.issues?.length || 0,
            severities: [...new Set(response.issues?.map(i => i.severity) || [])],
            issueTypes: [...new Set(response.issues?.map(i => i.issue_type) || [])]
          });
        }

        // Process and return insights
        const insights = response.issues || [];
        
        // Sort by severity (Critical > High > Moderate > Low)
        const severityOrder = { 'Critical': 0, 'High': 1, 'Moderate': 2, 'Low': 3 };
        insights.sort((a, b) => {
          const severityDiff = (severityOrder[a.severity] || 999) - (severityOrder[b.severity] || 999);
          if (severityDiff !== 0) return severityDiff;
          // If same severity, sort by timestamp (newest first)
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
        
        // Check for permission errors
        if (error.message?.includes('403') || error.message?.includes('not authorized')) {
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
        // v4 SDK: Check if custom error pages endpoint exists
        if (!this.client.zones?.customErrorPages?.list) {
          logger.debug('Custom error pages API not available on this client/token', { zoneId });
          return [];
        }
        
        const pages = await this.client.zones.customErrorPages.list({ 
          zone_id: zoneId 
        });
        return pages.result || [];
      } catch (error) {
        logger.debug('Custom error pages not available:', error.message);
        return [];
      }
    });
  }
}

module.exports = CloudflareClient;