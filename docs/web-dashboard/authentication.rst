==============
Authentication
==============

The FlareInspect web dashboard supports optional API key authentication for non-localhost deployments.

Enabling Authentication
------------------------

Set the ``FLAREINSPECT_API_KEY`` environment variable when starting the server:

.. code-block:: bash

   FLAREINSPECT_API_KEY=your-secret-key node web/server.js

Once set, all API requests must include the ``X-API-Key`` header:

.. code-block:: bash

   curl -H "X-API-Key: your-secret-key" http://localhost:3000/api/assessments

Requests without a valid key receive a ``401 Unauthorized`` response.

Generating a Strong Key
-------------------------

.. code-block:: bash

   # Using OpenSSL
   openssl rand -hex 32

   # Using Node.js
   node -e "console.log(require('crypto').randomBytes(32).toString('hex'))"

Security Best Practices
------------------------

- Bind the dashboard to ``127.0.0.1`` unless you need remote access
- Use a reverse proxy (nginx, Caddy) with TLS when exposing beyond localhost
- Rotate API keys regularly
- Use different keys for different environments
