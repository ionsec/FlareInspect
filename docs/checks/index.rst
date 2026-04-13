Security Checks
===============

FlareInspect runs **40+ security checks** across **21 categories** against your
Cloudflare account and zones.

.. toctree::
   :maxdepth: 1
   :hidden:

   account
   dns
   ssl-tls
   waf
   zerotrust
   workers-pages
   api-gateway
   bot-management
   logpush
   mtls
   security-txt
   attack-surface
   dlp
   tunnels-gateway
   page-shield
   cache-deception
   snippets
   custom-hostnames
   ai-gateway
   origin-certs

Categories
----------

.. list-table::
   :header-rows: 1
   :widths: 25 75

   * - Category
     - Description
   * - Account
     - MFA enforcement, admin access, audit logging
   * - DNS
     - DNSSEC, proxy status, wildcard records, CAA, DoH
   * - SSL/TLS
     - SSL mode, TLS versions, HSTS, certificate validity
   * - WAF
     - Security level, custom rules, rate limiting, OWASP
   * - Zero Trust
     - IdP, access policies, device enrollment, tunnels, Gateway
   * - Workers & Pages
     - Route security, resource limits, deployment protection
   * - API Gateway
     - API Shield, API Discovery
   * - Bot Management
     - Bot Fight Mode, Turnstile widget security
   * - Email Security
     - Routing, SPF/DKIM/DMARC, encryption
   * - Attack Surface
     - Security Center, exposed credentials, origin IP exposure
   * - DLP
     - Data Loss Prevention policies
   * - Page Shield
     - Client-side script monitoring
   * - Tunnels & Gateway
     - Cloudflare Tunnels, Secure Web Gateway
   * - Cache Deception
     - Cache Deception Armor protection
   * - Snippets
     - Edge snippet security
   * - Custom Hostnames
     - Custom hostname validation
   * - AI Gateway
     - AI Gateway configuration security
   * - Origin Certs
     - Origin certificate expiry monitoring
   * - Logpush
     - Logpush destination and coverage
   * - mTLS
     - Mutual TLS enforcement and certificate rotation

Quick Start
-----------

Run only specific check categories:

.. code-block:: bash

   flareinspect assess --token $TOKEN --checks dns,ssl,waf

Or run all checks against all zones:

.. code-block:: bash

   flareinspect assess --token $TOKEN
