# Custom Hostnames Checks

Checks for custom hostname validation and certificate status.

## Check Summary

| Check ID | Title | Severity | Compliance |
|----------|-------|----------|------------|
| CFL-CH-001 | Custom Hostname Validation | medium | CIS 3.8, PCI 4.1, NIST PR.DS-2 |

## Individual Checks

### CFL-CH-001: Custom Hostname Validation

**Severity:** medium | **Category:** custom-hostnames

Custom hostnames with pending, moved, or failed SSL validation status may
serve unencrypted traffic or display certificate errors to visitors.
FlareInspect checks all custom hostnames for validation issues.

**Remediation:** Validate custom hostname certificates and enable hostname fallback origin in SSL/TLS → Custom Hostnames.
