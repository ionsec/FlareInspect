==============================
Attack Surface Security Checks
==============================
==============================

Checks that evaluate attack surface reduction including Security Center, exposed credentials, and origin IP exposure.

Check Summary
-------------

===============  ========================  ========  =================================
Check ID         Title                     Severity  Compliance                       
===============  ========================  ========  =================================
CFL-SEC-001      Security Center Insights  high      SOC2 CC3.1, NIST ID.RA-1         
CFL-SEC-002      Exposed Credentials       critical  SOC2 CC6.1, PCI 6.5, NIST PR.DS-5
CFL-INSIGHT-001  Infra Proxy Status        high      SOC2 CC6.1, NIST PR.DS-5         
CFL-INSIGHT-002  Email Security            high      SOC2 CC6.1, PCI 3.4, NIST PR.DS-5
CFL-INSIGHT-003  Security Center Recs      medium    SOC2 CC3.1, NIST ID.RA-1         
CFL-INSIGHT-004  DDoS Protection           high      SOC2 CC6.1, PCI 6.5, NIST PR.DS-5
CFL-INSIGHT-005  Unproxied DNS Records     medium    SOC2 CC6.1, NIST PR.DS-5         
===============  ========================  ========  =================================

CFL-SEC-001: Security Center Insights
^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^

**Severity:** high | **Category:** attack-surface

Security Center provides visibility into infrastructure risks and recommendations.

**Remediation:** Review Security Center recommendations in the Cloudflare Dashboard.

---

CFL-SEC-002: Exposed Credentials
^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^

**Severity:** critical | **Category:** attack-surface

Exposed credentials in code repositories or public data leaks create an immediate compromise risk.

**Remediation:** Rotate exposed credentials immediately. Implement secret scanning in CI/CD pipelines.

---

CFL-INSIGHT-001: Infra Proxy Status
^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^

**Severity:** high | **Category:** attack-surface

Infrastructure not proxied through Cloudflare lacks DDoS protection and WAF coverage.

**Remediation:** Proxy all infrastructure through Cloudflare to enable protection.

---

CFL-INSIGHT-002: Email Security
^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^

**Severity:** high | **Category:** attack-surface

Email security features (routing, SPF/DKIM/DMARC) prevent phishing and email-based attacks.

**Remediation:** Enable email security routing and configure SPF/DKIM/DMARC records.

---

CFL-INSIGHT-003: Security Center Recommendations
^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^

**Severity:** medium | **Category:** attack-surface

Unresolved Security Center recommendations indicate known but unaddressed risks.

**Remediation:** Address Security Center recommendations systematically.

---

CFL-INSIGHT-004: DDoS Protection
^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^

**Severity:** high | **Category:** attack-surface

DDoS protection should be enabled on all zones to absorb volumetric attacks.

**Remediation:** Enable DDoS protection — it is included by default on all Cloudflare plans.

---

CFL-INSIGHT-005: Unproxied DNS Records
^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^

**Severity:** medium | **Category:** attack-surface

DNS records that are not proxied expose origin IPs and bypass Cloudflare protection.

**Remediation:** Enable proxy (orange cloud) on DNS records unless they require direct resolution (e.g., MX, TXT for verification).
