========================
Email Authentication Checks
========================

Detects whether the zone publishes an SPF and DMARC DNS TXT record.

Check Summary
-------------

==============  ======================================  ========  ============
Check ID        Title                                   Severity  Compliance
==============  ======================================  ========  ============
CFL-EMAIL-001   SPF Record Present                      medium    SOC2, NIST
CFL-EMAIL-003   DMARC Record Present                    medium    SOC2, NIST
==============  ======================================  ========  ============

CFL-EMAIL-001: SPF Record Present
^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^

**Severity:** medium | **Category:** email

The Sender Policy Framework (SPF) record lists the hosts authorized
to send email on behalf of the domain. Without SPF, anyone can forge
the envelope sender and your domain becomes a soft target for
spoofing.

**Remediation:** Use FlareInspect's recipe to publish a conservative
``v=spf1 -all`` record at the zone apex. If the zone sends email
from a known provider, replace ``-all`` with the provider's include
statement (e.g. ``v=spf1 include:_spf.google.com -all``).

CFL-EMAIL-003: DMARC Record Present
^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^

**Severity:** medium | **Category:** email

DMARC ties SPF and DKIM together and tells receivers what to do with
messages that fail alignment. Starting with ``p=none`` (monitoring
only) is safe; tighten to ``p=quarantine`` or ``p=reject`` once you
have confidence in your legitimate senders.

**Remediation:** Use FlareInspect's recipe to publish a
``v=DMARC1; p=none; rua=mailto:dmarc-reports@example.com`` record at
``_dmarc.<zone>``. Replace the ``rua`` address with your own
reporting mailbox.
