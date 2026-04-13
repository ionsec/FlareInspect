=====================

Bot Management Checks

=====================




Checks for bot protection and Turnstile configuration.



Check Summary


----


  ==============  ===========================  ==========  ============================================

   Check ID        Title                        Severity    Compliance

  ==============  ===========================  ==========  ============================================

   CFL-BOT-001     Bot Fight Mode               medium      CIS 4.4, SOC2 CC6.1, PCI 6.5, NIST PR.IP-1

   CFL-TURN-001    Turnstile Widget Security    medium      CIS 4.6, SOC2 CC6.1, PCI 6.5, NIST PR.IP-1

  ==============  ===========================  ==========  ============================================


Individual Checks


----


.. rubric:: CFL-BOT-001: Bot Fight Mode



**Severity:** medium | **Category:** bot


Bot Fight Mode provides basic automated traffic detection. Bot Management

(Enterprise) adds advanced fingerprinting and ML-based detection.


**Remediation:** Enable Bot Fight Mode or upgrade to Bot Management for advanced bot protection.



.. rubric:: CFL-TURN-001: Turnstile Widget Security



**Severity:** medium | **Category:** bot


Cloudflare Turnstile is a privacy-preserving alternative to CAPTCHA for

detecting automated traffic on login and registration forms.


**Remediation:** Implement Cloudflare Turnstile on login and registration forms for automated traffic detection.

