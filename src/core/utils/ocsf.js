/**
 * @fileoverview OCSF (Open Cybersecurity Schema Framework) Utility
 * @description Utility functions to ensure findings comply with OCSF schema
 * @module core/utils/ocsf
 */

/**
 * OCSF Activity IDs for security findings
 */
const OCSF_ACTIVITIES = {
  CREATE: 1,
  READ: 2,
  UPDATE: 3,
  DELETE: 4,
  EVALUATE: 5,
  REMEDIATE: 6
};

/**
 * OCSF Class UIDs
 */
const OCSF_CLASSES = {
  SECURITY_FINDING: 2001,
  COMPLIANCE_FINDING: 2002,
  VULNERABILITY_FINDING: 2003
};

/**
 * OCSF Category UIDs
 */
const OCSF_CATEGORIES = {
  FINDINGS: 2,
  DISCOVERY: 5,
  NETWORK_ACTIVITY: 4
};

/**
 * OCSF Severity mapping
 */
const OCSF_SEVERITY = {
  'critical': { id: 5, name: 'Critical' },
  'high': { id: 4, name: 'High' },
  'medium': { id: 3, name: 'Medium' },
  'low': { id: 2, name: 'Low' },
  'informational': { id: 1, name: 'Informational' }
};

/**
 * OCSF Status mapping for findings
 */
const OCSF_STATUS = {
  'PASS': { id: 1, name: 'Pass' },
  'FAIL': { id: 2, name: 'Fail' },
  'WARNING': { id: 3, name: 'Warning' },
  'NOT_APPLICABLE': { id: 4, name: 'Not Applicable' },
  'MANUAL': { id: 5, name: 'Manual Review Required' }
};

/**
 * OCSF Resource Types mapping
 */
const OCSF_RESOURCE_TYPES = {
  'account': 'Account',
  'zone': 'DNS Zone',
  'dns-record': 'DNS Record',
  'certificate': 'Certificate',
  'application': 'Application',
  'policy': 'Policy',
  'device-policy': 'Device Policy',
  'identity-provider': 'Identity Provider',
  'access-rule': 'Access Rule'
};

/**
 * Transform a finding to be OCSF compliant
 * @param {Object} finding - The original finding
 * @param {Object} options - Additional options
 * @returns {Object} OCSF compliant finding
 */
function toOCSF(finding, options = {}) {
  const severity = OCSF_SEVERITY[finding.severity] || OCSF_SEVERITY['informational'];
  const status = OCSF_STATUS[finding.status] || OCSF_STATUS['FAIL'];
  
  return {
    // Core OCSF fields
    activity_id: OCSF_ACTIVITIES.EVALUATE,
    activity_name: 'Evaluate',
    class_uid: OCSF_CLASSES.SECURITY_FINDING,
    class_name: 'Security Finding',
    category_uid: OCSF_CATEGORIES.FINDINGS,
    category_name: 'Findings',
    type_uid: 200101, // Security Finding: Evaluate
    type_name: 'Security Finding: Evaluate',
    
    // Original fields (for backward compatibility)
    id: finding.id,
    checkId: finding.checkId,
    checkTitle: finding.checkTitle,
    service: finding.service,
    
    // OCSF severity
    severity_id: severity.id,
    severity: finding.severity,
    
    // OCSF status
    status_id: status.id,
    status: finding.status,
    status_detail: status.name,
    
    // Finding content
    message: finding.description,
    description: finding.description,
    remediation: finding.remediation,
    
    // Resource information
    resources: [{
      uid: finding.resourceId,
      type: OCSF_RESOURCE_TYPES[finding.resourceType] || finding.resourceType,
      name: finding.resourceId,
      data: finding.metadata || {}
    }],
    
    // Legacy fields for backward compatibility
    resourceId: finding.resourceId,
    resourceType: finding.resourceType,
    resourceArn: finding.resourceArn,
    region: finding.region,
    
    // Timestamps
    time: finding.timestamp ? Math.floor(new Date(finding.timestamp).getTime() / 1000) : Math.floor(Date.now() / 1000),
    timestamp: finding.timestamp ? new Date(finding.timestamp) : new Date(),
    
    // Metadata
    metadata: {
      ...finding.metadata,
      product: {
        name: 'FlareInspect',
        vendor_name: 'IONSEC.IO',
        version: '1.0.0'
      },
      version: '1.0.0'
    },
    
    // Compliance frameworks mapping (if available)
    compliance: finding.compliance || [],
    
    // Additional OCSF fields
    finding_info: {
      title: finding.checkTitle,
      uid: finding.checkId,
      types: [finding.service],
      first_seen_time: finding.timestamp ? Math.floor(new Date(finding.timestamp).getTime() / 1000) : Math.floor(Date.now() / 1000),
      last_seen_time: finding.timestamp ? Math.floor(new Date(finding.timestamp).getTime() / 1000) : Math.floor(Date.now() / 1000),
      created_time: finding.timestamp ? Math.floor(new Date(finding.timestamp).getTime() / 1000) : Math.floor(Date.now() / 1000),
      modified_time: finding.timestamp ? Math.floor(new Date(finding.timestamp).getTime() / 1000) : Math.floor(Date.now() / 1000)
    }
  };
}

/**
 * Validate if a finding is OCSF compliant
 * @param {Object} finding - The finding to validate
 * @returns {Object} Validation result with isValid and errors
 */
function validateOCSF(finding) {
  const errors = [];
  
  // Check required OCSF fields
  const requiredFields = [
    'activity_id', 'class_uid', 'category_uid', 'type_uid',
    'severity_id', 'status_id', 'time'
  ];
  
  requiredFields.forEach(field => {
    if (finding[field] === undefined || finding[field] === null) {
      errors.push(`Missing required OCSF field: ${field}`);
    }
  });
  
  // Validate severity
  if (finding.severity_id && (finding.severity_id < 1 || finding.severity_id > 5)) {
    errors.push('Invalid severity_id: must be between 1 and 5');
  }
  
  // Validate status
  if (finding.status_id && (finding.status_id < 1 || finding.status_id > 5)) {
    errors.push('Invalid status_id: must be between 1 and 5');
  }
  
  return {
    isValid: errors.length === 0,
    errors
  };
}

/**
 * Create an OCSF compliant finding
 * @param {Object} findingData - The finding data
 * @returns {Object} OCSF compliant finding
 */
function createFinding(findingData) {
  // Ensure required fields have defaults
  const defaultFinding = {
    id: findingData.id || require('uuid').v4(),
    checkId: findingData.checkId || 'unknown-check',
    checkTitle: findingData.checkTitle || 'Unknown Security Check',
    service: findingData.service || 'unknown',
    severity: findingData.severity || 'informational',
    status: findingData.status || 'FAIL',
    description: findingData.description || 'No description provided',
    remediation: findingData.remediation || 'No remediation guidance available',
    resourceId: findingData.resourceId || 'unknown-resource',
    resourceType: findingData.resourceType || 'unknown',
    timestamp: findingData.timestamp || new Date(),
    metadata: findingData.metadata || {}
  };
  
  // Convert to OCSF format
  return toOCSF(defaultFinding);
}

/**
 * Batch convert findings to OCSF format
 * @param {Array} findings - Array of findings
 * @returns {Array} Array of OCSF compliant findings
 */
function convertFindingsToOCSF(findings) {
  return findings.map(finding => toOCSF(finding));
}

module.exports = {
  OCSF_ACTIVITIES,
  OCSF_CLASSES,
  OCSF_CATEGORIES,
  OCSF_SEVERITY,
  OCSF_STATUS,
  OCSF_RESOURCE_TYPES,
  toOCSF,
  validateOCSF,
  createFinding,
  convertFindingsToOCSF
};