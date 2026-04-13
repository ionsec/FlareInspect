==============================
Bot Management Security Checks
==============================
==============================

Checks for Cloudflare Bot Fight Mode and Turnstile widget configuration.

Check Summary
-------------

============  ================  ========  =================================
Check ID      Title             Severity  Compliance                       
============  ================  ========  =================================
CFL-BOT-001   Bot Fight Mode    medium    CIS 4.4, SOC2 CC6.1, NIST PR.IP-1
CFL-TURN-001  Turnstile Widget  medium    SOC2 CC6.1, NIST PR.IP-1         
============  ================  ========  =================================

CFL-BOT-001: Bot Fight Mode
^^^^^^^^^^^^^^^^^^^^^^^^^^^^

**Severity:** medium | **Category:** bot

Bot Fight Mode provides automated bot detection and mitigation for zones without Bot Management subscriptions.

**Remediation:** Enable Bot Fight Mode in Security → Bots.

---

CFL-TURN-001: Turnstile Widget
^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^

**Severity:** medium | **Category:** bot

Turnstile is a privacy-preserving CAPTCHA alternative. Without it, forms and authentication endpoints are vulnerable to automated abuse.

**Remediation:** Enable Turnstile for authentication and form submission endpoints.
