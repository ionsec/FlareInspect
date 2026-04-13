===============
Getting Started
===============

This guide walks you through running your first Cloudflare security assessment with FlareInspect.

Prerequisites
-------------

======================  ======================================================
Requirement             Details                                               
======================  ======================================================
**Node.js**             Version 20 or later                                   
**Cloudflare account**  With zones you want to assess                         
**API token**           Cloudflare API token with read permissions (see below)
======================  ======================================================

Create a Cloudflare API Token
------------------------------

FlareInspect requires a Cloudflare API token with read-only access to the resources it assesses.

1. Log in to the `Cloudflare dashboard <https://dash.cloudflare.com>`__.
2. Navigate to **My Profile** → **API Tokens**.
3. Click **Create Token**.
4. Select **Create Custom Token** (or start from a template).
5. Configure the following permissions:

===========================  =============================  ======
Permission                   Scope                          Access
===========================  =============================  ======
Zone → Zone                  All zones (or specific zones)  Read  
Zone → DNS                   All zones                      Read  
Zone → SSL and Certificates  All zones                      Read  
Zone → Firewall Services     All zones                      Read  
Account → Account Settings   All accounts                   Read  
===========================  =============================  ======

6. Optionally restrict the token to specific zone or account resources.
7. Click **Continue to summary**, then **Create Token**.
8. Copy the token value — you will pass it to FlareInspect via the ``--token`` flag or the ``CLOUDFLARE_TOKEN`` environment variable.

.. tip::

   Store the token securely. Avoid committing it to source repositories.
   Use environment variables or a secret manager in CI/CD pipelines.

First Assessment
-----------------

Run your first assessment against all zones in your Cloudflare account:

.. code-block:: bash

   flareinspect assess --token YOUR_CLOUDFLARE_TOKEN

Or, if installed from source:

.. code-block:: bash

   node src/cli/index.js assess --token YOUR_CLOUDFLARE_TOKEN

FlareInspect scans your account and zones, runs all check categories, and prints a summary to the terminal. Results are also saved to a timestamped JSON file (e.g. ``flareinspect-20260412-143000.json``).

Scope to Specific Zones
^^^^^^^^^^^^^^^^^^^^^^^

Assess only selected zones:

.. code-block:: bash

   flareinspect assess --token YOUR_CLOUDFLARE_TOKEN --zones example.com,staging.example.com

Run Specific Check Categories
^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^

Run only DNS and SSL checks:

.. code-block:: bash

   flareinspect assess --token YOUR_CLOUDFLARE_TOKEN --checks dns,ssl

Understanding the Output
--------------------------

After each assessment, FlareInspect displays a summary with these components:

Grade and Score
^^^^^^^^^^^^^^^

=========  ====================================================================================
Component  Description                                                                         
=========  ====================================================================================
**Grade**  Letter grade from A (best) to F (worst), derived from the numeric score             
**Score**  Numeric score from 0 to 100, calculated from pass/fail findings weighted by severity
=========  ====================================================================================

Findings by Severity
^^^^^^^^^^^^^^^^^^^^

Each finding has a severity level:

============  =====================================================
Severity      Meaning                                              
============  =====================================================
**Critical**  Immediate risk — requires urgent remediation         
**High**      Significant security gap — should be addressed soon  
**Medium**    Moderate risk — remediation recommended              
**Low**       Minor issue or informational — review when convenient
============  =====================================================

Top Risks
^^^^^^^^^

The summary highlights the most impactful failed checks so you can prioritize remediation.

Generate an HTML Report
------------------------

Convert a saved assessment JSON file into a shareable HTML report:

.. code-block:: bash

   flareinspect export -i flareinspect-20260412-143000.json -f html -o report.html

Open ``report.html`` in any browser to view the full interactive report.

Compare Two Runs
-----------------

Use the ``diff`` command to compare a baseline assessment against a current run and detect security posture drift:

.. code-block:: bash

   flareinspect diff --baseline baseline.json --current latest.json

The diff output shows new findings, resolved findings, regressions, and improvements. An exit code of ``1`` indicates at least one regression was detected.

For a Markdown-formatted drift report:

.. code-block:: bash

   flareinspect diff --baseline baseline.json --current latest.json -f markdown -o drift-report.md
