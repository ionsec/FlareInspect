==============================
Enterprise / SASE Advisory Checks
==============================

Advisory checks for Enterprise / SASE features. Each check is
**tier-gated**: the assessor short-circuits when the account or zone
plan is not Enterprise, so Free/Pro/Business tenants will see no
findings in this category.

Check Summary
-------------

==============  ======================================  ========  ============
Check ID        Title                                   Severity  Compliance
==============  ======================================  ========  ============
CFL-HOLD-001    Zone Hold (Anti-Takeover)               high      CIS, SOC2, NIST
CFL-POSTURE-001 Device Posture Rules                    high      SOC2, PCI, NIST
CFL-ZT-007      Access App — No "Allow Everyone"        critical  SOC2, NIST
CFL-ZT-008      Access App Session Duration             medium    SOC2
CFL-ZT-009      Access App Require MFA / Posture        high      SOC2, NIST
CFL-CASB-001    CASB Integrations + Open Findings       high      SOC2, NIST
CFL-EMAILSEC-001 Cloud Email Security Policies          medium    SOC2, NIST
CFL-RBI-001     Browser Isolation Policies              medium    SOC2, NIST
CFL-MAGIC-001   Magic Firewall / Magic Transit          high      CIS, SOC2, NIST
==============  ======================================  ========  ============

CFL-HOLD-001: Zone Hold (Anti-Takeover)
^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^

**Severity:** high | **Category:** account-waf

Zone hold prevents the zone from being transferred to another
account without explicit release. Without it, a compromised admin
session could transfer the zone to an attacker-controlled account.

**Remediation:** Use FlareInspect's recipe to enable zone hold, or
toggle it in *Account → Account Settings → Zone Hold*.

CFL-POSTURE-001: Device Posture Rules
^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^

**Severity:** high | **Category:** posture

Posture rules evaluate device state (OS version, disk encryption,
firewall) before granting access. With no rules, Access applications
effectively trust any device.

**Remediation:** Define posture rules in *Zero Trust → Devices →
Posture*.

CFL-ZT-007/008/009: Access App Hardening
^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^

**Severity:** critical/medium/high

Three checks together assess Access application hygiene:

* CFL-ZT-007: at least one application with an "Allow everyone"
  policy. This is rarely intentional.
* CFL-ZT-008: session duration is bounded (≤24h) on every app.
* CFL-ZT-009: at least one require rule (MFA or posture) on every
  sensitive app.

**Remediation:** Tighten the policies on the flagged applications.

CFL-CASB-001: CASB Integrations and Open Findings
^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^

**Severity:** high | **Category:** casb

Cloudflare CASB scans connected SaaS integrations (Google Workspace,
Microsoft 365, etc.) for misconfigurations and signs of compromise.
Open critical or high findings should be remediated promptly.

**Remediation:** Review open CASB findings in *Zero Trust → CASB*.

CFL-EMAILSEC-001: Cloud Email Security Policies
^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^

**Severity:** medium | **Category:** email-security

Cloud Email Security (formerly Area 1) catches phishing and BEC
attacks before they reach the inbox. At least one policy should be
active.

**Remediation:** Activate Anti-Spoof and Phishing Protection in
*Email Security → Policies*.

CFL-RBI-001: Browser Isolation Policies
^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^

**Severity:** medium | **Category:** rbi

Browser Isolation executes risky web content in a remote browser and
streams pixels to the user, neutralizing zero-day browser exploits.

**Remediation:** Add isolation policies for risky categories
(unknown sites, file uploads).

CFL-MAGIC-001: Magic Firewall / Magic Transit
^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^

**Severity:** high | **Category:** magic

Magic Transit / Magic Firewall rulesets enforce network-layer
allow/deny policies across all of Cloudflare's edge. The check
verifies that at least one ruleset has rules deployed.

**Remediation:** Add Magic Firewall ruleset rules for known-bad
traffic in *Magic Transit → Rulesets*.
