==============
assess Command
==============

Run a comprehensive Cloudflare security assessment against your account and zones.

Usage
-----

.. code-block:: bash

   flareinspect assess [options]

Options
-------

.. list-table::
   :header-rows: 1
   :widths: 24 58 18

   * - Option
     - Description
     - Default
   * - ``-t, --token <token>``
     - Cloudflare API token *(required)*
     - —
   * - ``-o, --output <file>``
     - Output file path for assessment results
     - Auto-generated timestamped file
   * - ``-f, --format <format>``
     - Output format: ``json``, ``html``, ``sarif``, ``markdown``, ``csv``, or ``ocsf``
     - ``json``
   * - ``--no-export``
     - Skip automatic export of results
     - —
   * - ``--ci``
     - CI/CD mode: JSON to stdout, no spinners, exit codes by threshold
     - —
   * - ``--threshold <score>``
     - Minimum security score (0-100) to pass in CI mode
     - —
   * - ``--fail-on <severity>``
     - Fail if any finding at or above severity ``critical``, ``high``, ``medium``, or ``low``
     - —
   * - ``--zones <zones>``
     - Comma-separated list of zone names to assess
     - All zones
   * - ``--exclude-zones <zones>``
     - Comma-separated list of zone names to exclude
     - —
   * - ``--checks <checks>``
     - Comma-separated list of check categories to run
     - All categories
   * - ``--concurrency <n>``
     - Number of zones to assess in parallel
     - ``3``
   * - ``--compliance <framework>``
     - Generate compliance report: ``cis``, ``soc2``, ``pci``, or ``nist``
     - —
   * - ``--sensitivity <level>``
     - Data sensitivity level: ``critical``, ``high``, ``medium``, or ``low``
     - —
   * - ``--debug``
     - Enable debug logging
     - —

Check Categories
-----------------

The following 34 check categories can be targeted with ``--checks``:

===========================  ===========================================
Category                     Description
===========================  ===========================================
``account``                  Account-level settings and configuration
``account-waf``              Account-scope WAF / DDoS coverage
``access``                   Cloudflare Access application depth (allow-everyone, MFA, posture)
``ai-gateway``               AI Gateway security configuration
``api``                      API gateway and shielding configuration
``attack-surface``           Attack surface reduction rules
``bot``                      Bot management and mitigation
``cache``                    Cache security and configuration
``casb``                     CASB open critical/high findings
``credentials``              Leaked credentials detection
``custom-hostnames``         Custom hostname security
``ddos``                     L7 DDoS posture
``dlp``                      Data Loss Prevention policies
``dns``                      DNS record security and resolution
``email``                    Email routing & SPF / DKIM / DMARC
``email-security``           Cloud Email Security policies
``gateway``                  Secure Web Gateway policies
``loadbalancing``            Load Balancing posture
``logpush``                  Log push destination and coverage
``magic``                    Magic Firewall / Magic Transit rulesets
``mtls``                     Mutual TLS authentication settings
``notifications``            Security notification policies (4 alert types)
``page-shield``              Page Shield script monitoring
``pages``                    Cloudflare Pages deployment security
``performance``              Performance settings (Brotli, HTTP/2-3, cache deception armor)
``posture``                  Device posture rules
``rbi``                      Browser Isolation policies
``rules``                    Rules / rate-limit rules
``security-insights``        Security Center insights
``securitytxt``              Security.txt presence and validity
``snippets``                 Cache and transform snippets
``spectrum``                 Spectrum (TCP/UDP) configuration
``ssl``                      SSL/TLS certificate and configuration
``storage``                  Workers KV / D1 / Queues inventory
``tunnels``                  Cloudflare Tunnels configuration
``turnstile``                Turnstile configuration
``waf``                      Web Application Firewall rules and policies
``workers``                  Workers script inventory and plaintext-secret bindings
``zaraz``                    Zaraz third-party tools and consent
``zerotrust``                Zero Trust network access configuration
===========================  ===========================================

.. note::

   Several category names have **aliases** (e.g. ``leaked-credentials``
   → ``credentials``, ``magic-firewall`` → ``magic``,
   ``device-posture`` → ``posture``, ``browser-isolation`` → ``rbi``).
   The full alias map is in
   ``src/core/services/assessmentService.js``.

CI Mode
--------

CI mode is designed for automated pipelines. It:

- Outputs the full assessment JSON to **stdout** (no spinners or banners)
- Suppresses all interactive terminal output
- Sets the process exit code based on ``--threshold`` and ``--fail-on``

Exit Code Logic
^^^^^^^^^^^^^^^

======================================================  =========
Condition                                               Exit Code
======================================================  =========
Assessment passes threshold and severity gate           ``0``    
Overall score < ``--threshold`` value                   ``1``    
Any finding at or above ``--fail-on`` severity is FAIL  ``1``    
Assessment itself fails (invalid token, API error)      ``1``    
======================================================  =========

Examples
--------

.. rubric:: Basic Assessment

.. code-block:: bash

   flareinspect assess --token $CLOUDFLARE_TOKEN

.. rubric:: Targeted Assessment

.. code-block:: bash

   flareinspect assess --token $CLOUDFLARE_TOKEN --zones example.com --checks dns,ssl,waf

.. rubric:: CI/CD with Gating

.. code-block:: bash

   flareinspect assess --token $CLOUDFLARE_TOKEN --ci --threshold 80 --fail-on high

.. rubric:: With Compliance Report

.. code-block:: bash

   flareinspect assess --token $CLOUDFLARE_TOKEN --compliance cis --sensitivity high
