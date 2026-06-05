==============================
Notification Policy Checks
==============================

Detects whether the account has notification policies configured for
the high-signal Cloudflare alert types: WAF anomalies, origin errors,
SSL/TLS certificate events, and L7 DDoS attacks.

Check Summary
-------------

==============  ======================================  ========  ============
Check ID        Title                                   Severity  Compliance
==============  ======================================  ========  ============
CFL-ALERT-001   WAF Anomaly Notification Policy         medium    SOC2, PCI, NIST
CFL-ALERT-002   Origin Error Notification Policy        medium    SOC2, PCI, NIST
CFL-ALERT-003   SSL/TLS Cert Notification Policy        medium    SOC2, PCI, NIST
CFL-ALERT-004   L7 DDoS Notification Policy             medium    SOC2, PCI, NIST
==============  ======================================  ========  ============

How recipes behave
^^^^^^^^^^^^^^^^^^

The notification policy recipes are **operator-prompted**: applying
them via FlareInspect creates a new policy in **disabled** state with
the alert type and your chosen email/webhook destinations. The
operator must enable the policy in the Cloudflare dashboard after
confirming the destination.

This is intentional — auto-enabling a notification policy could spam
operators if the destination is misconfigured. The recipe stops short
of enabling; the operator has the final say.

**Remediation per check:** Create a notification policy in *Account →
Notifications* (or use the recipe) with the alert type listed in the
check title and your preferred email/webhook destination.
