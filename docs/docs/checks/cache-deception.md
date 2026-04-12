# Cache Deception Checks

Checks for Cloudflare Cache Deception Armor.

## Check Summary

| Check ID | Title | Severity | Compliance |
|----------|-------|----------|------------|
| CFL-CDA-001 | Cache Deception Armor | medium | CIS 4.8, SOC2 CC6.1, PCI 6.5, NIST PR.IP-1 |

## Individual Checks

### CFL-CDA-001: Cache Deception Armor

**Severity:** medium | **Category:** cache

Web cache deception attacks trick the CDN into caching sensitive content by
appending cacheable extensions to URLs. Cache Deception Armor prevents this.
FlareInspect checks whether Cache Deception Armor is enabled.

**Remediation:** Enable Cache Deception Armor in Caching → Configuration to prevent web cache deception attacks.
