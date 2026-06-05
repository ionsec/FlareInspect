==============================
Bot Management Security Checks
==============================

Checks for Cloudflare Bot Fight Mode and Turnstile widget configuration.

Check Summary
-------------

==============  ======================================  ========  ============
Check ID        Title                                   Severity  Compliance
==============  ======================================  ========  ============
CFL-BOT-001     Bot Fight Mode                          medium    CIS, SOC2, PCI, NIST
==============  ======================================  ========  ============

CFL-BOT-001: Bot Fight Mode
^^^^^^^^^^^^^^^^^^^^^^^^^^^^

**Severity:** medium | **Category:** bot

Bot Fight Mode challenges requests identified as automated and
definitely not from a human. It is one-click to enable and a useful
first line of defense even for zones without a full Bot Management
subscription.

**Remediation:** Use FlareInspect's recipe to enable Bot Fight Mode,
or toggle it on in *Security → Bots → Bot Fight Mode*.

.. warning::

   Bot Fight Mode may challenge legitimate bots (e.g. uptime
   monitors, search engine crawlers). Apply the recipe only after
   testing in log mode if you depend on third-party bots.
