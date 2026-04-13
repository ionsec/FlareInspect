=======================

Account Security Checks

=======================




Checks that evaluate account-level security configuration including MFA,

admin access, and audit logging.



Check Summary


----


=============  =============================  ==========  =========================================

   Check ID       Title                          Severity    Compliance

=============  =============================  ==========  =========================================

   CFL-ACC-001    MFA Enforcement                critical    SOC2 CC6.1, PCI 8.3, NIST PR.AC-7

   CFL-ACC-002    API Token Security             high        SOC2 CC6.1, PCI 8.6, NIST PR.AC-1

   CFL-ACC-003    Admin Access Control           high        SOC2 CC6.1/CC6.2, PCI 8.1, NIST PR.AC-4

   CFL-ACC-004    Audit Log Monitoring           medium      SOC2 CC7.2, PCI 10.1, NIST DE.CM-1

   CFL-ACC-005    Account Takeover Protection    high        SOC2 CC6.1, PCI 8.3, NIST PR.AC-7

=============  =============================  ==========  =========================================


Individual Checks


----


.. rubric:: CFL-ACC-001: MFA Enforcement



**Severity:** critical

**Category:** account

**Compliance:** CIS 1.1, SOC2 CC6.1, PCI 8.3, NIST PR.AC-7



**Description**


Ensure all account members have multi-factor authentication enabled. Members

without MFA represent a critical authentication bypass risk.



**What We Check**


The Cloudflare API returns the list of account members and their MFA enrollment

status. FlareInspect counts members with MFA disabled and flags the check as

FAIL if any are found.



**Evidence**


When this check fails:

- **Observed:** Number of members without MFA enabled

- **Expected:** All members have MFA enabled

- **Affected Entities:** Named list of members lacking MFA



**Remediation**


Enable MFA for all account members in Cloudflare Dashboard → My Profile →

Authentication.



----


.. rubric:: CFL-ACC-002: API Token Security



**Severity:** high

**Category:** account

**Compliance:** CIS 1.2, SOC2 CC6.1, PCI 8.6, NIST PR.AC-1



**Description**


Regular audit and rotation of API tokens. Stale or overly permissive tokens

increase the attack surface.



**What We Check**


The API returns the list of API tokens and their permissions. FlareInspect

evaluates token scope and age.



**Remediation**


Audit API tokens regularly. Use scoped tokens with minimum permissions and set

expiration dates.



----


.. rubric:: CFL-ACC-003: Admin Access Control



**Severity:** high

**Category:** account

**Compliance:** CIS 1.3, SOC2 CC6.1/CC6.2, PCI 8.1, NIST PR.AC-4



**Description**


Limit the number of admin users. Excessive admin-level access violates the

principle of least privilege.



**What We Check**


The API returns the member list with roles. FlareInspect counts how many

members hold administrator privileges.



**Evidence**


- **Observed:** Number of admin members

- **Expected:** Minimal admin membership following least privilege

- **Affected Entities:** Named admin members



**Remediation**


Review admin members list. Follow principle of least privilege and minimize

admin-level access.



----


.. rubric:: CFL-ACC-004: Audit Log Monitoring



**Severity:** medium

**Category:** account

**Compliance:** CIS 1.4, SOC2 CC7.2, PCI 10.1, NIST DE.CM-1



**Description**


Enable and monitor Cloudflare audit logs for visibility into account changes.



**What We Check**


FlareInspect checks whether audit logs are accessible with the provided token

and whether a Logpush destination is configured.



**Remediation**


Enable Cloudflare Audit Logs and integrate with SIEM for monitoring and

alerting.



----


.. rubric:: CFL-ACC-005: Account Takeover Protection



**Severity:** high

**Category:** account

**Compliance:** CIS 1.5, SOC2 CC6.1, PCI 8.3, NIST PR.AC-7



**Description**


Enable Super Administrator protection to prevent account takeover.



**What We Check**


FlareInspect checks whether the account has Super Administrator protection

enabled, which adds additional authentication requirements for sensitive

operations.



**Remediation**


Enable Super Administrator protection and enforce strong authentication policies.

