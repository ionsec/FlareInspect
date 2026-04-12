# mTLS Security Checks

Checks for mutual TLS (mTLS) configuration.

## Check Summary

| Check ID | Title | Severity | Compliance |
|----------|-------|----------|------------|
| CFL-MTLS-001 | mTLS Enforcement | high | CIS 3.6, SOC2 CC6.7, PCI 4.1/8.2, NIST PR.DS-2 |
| CFL-MTLS-002 | mTLS Certificate Rotation | medium | CIS 3.7, SOC2 CC6.7, PCI 4.1, NIST PR.DS-2 |

## Individual Checks

### CFL-MTLS-001: mTLS Enforcement

**Severity:** high | **Category:** mtls

mTLS requires clients to present a valid certificate, providing strong
authentication for origin communication. FlareInspect checks whether mTLS is
enabled for the zone.

**Remediation:** Enable mTLS for sensitive zones to require client certificates for origin communication.

### CFL-MTLS-002: mTLS Certificate Rotation

**Severity:** medium | **Category:** mtls

Stale mTLS client certificates reduce security. FlareInspect checks for
certificates approaching expiration.

**Remediation:** Implement certificate rotation policies and monitor certificate expiration.
