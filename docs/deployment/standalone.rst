===========
Standalone
===========

Run FlareInspect as a standalone Node.js process on any server with Node.js 20+.

Quick Start
-----------

.. code-block:: bash

   git clone https://github.com/ionsec/flareinspect.git
   cd flareinspect
   npm install
   node web/server.js

Environment Variables
----------------------

.. list-table::
   :header-rows: 1
   :widths: 35 10 55

   * - Variable
     - Required
     - Description
   * - ``CLOUDFLARE_TOKEN``
     - No
     - Cloudflare API token (can supply via UI)
   * - ``FLAREINSPECT_API_KEY``
     - No
     - API key for dashboard authentication
   * - ``HOST``
     - No
     - Bind address (default: ``127.0.0.1``)
   * - ``PORT``
     - No
     - Port number (default: ``0`` = random available)
   * - ``LOG_LEVEL``
     - No
     - Logging level (default: ``info``)

Production Recommendations
---------------------------

- Use a process manager (pm2, systemd) for auto-restart
- Bind to ``127.0.0.1`` and use a reverse proxy (nginx, Caddy) with TLS
- Set ``FLAREINSPECT_API_KEY`` for authentication
- Set ``NODE_ENV=production`` for optimized performance
