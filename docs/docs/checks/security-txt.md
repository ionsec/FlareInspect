# security.txt Checks

Checks for the presence and validity of a security.txt file.

## Check Summary

| Check ID | Title | Severity | Compliance |
|----------|-------|----------|------------|
| CFL-SECTXT-001 | security.txt Presence | low | — |

## Individual Checks

### CFL-SECTXT-001: security.txt Presence

**Severity:** low | **Category:** securitytxt

A `security.txt` file at `/.well-known/security.txt` provides security
researchers with contact information and disclosure policies. FlareInspect
attempts to fetch this file and checks for a valid response.

**Remediation:** Create a security.txt file at `/.well-known/security.txt` with contact information and disclosure policy.
