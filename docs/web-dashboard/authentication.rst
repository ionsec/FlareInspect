==============
Authentication
==============

The FlareInspect web dashboard supports optional API key authentication
for non-localhost deployments, plus a separate edit-scope gate for the
mutating remediation endpoints.

API key
-------

Set the ``FLAREINSPECT_API_KEY`` environment variable when starting the server:

.. code-block:: bash

   FLAREINSPECT_API_KEY=your-secret-key node web/server.js

Once set, all ``/api/*`` requests must include the ``X-API-Key`` header:

.. code-block:: bash

   curl -H "X-API-Key: your-secret-key" http://localhost:3000/api/assessments

Requests without a valid key receive a ``401 Unauthorized`` response.

Generating a strong key
^^^^^^^^^^^^^^^^^^^^^^^

.. code-block:: bash

   # Using OpenSSL
   openssl rand -hex 32

   # Using Node.js
   node -e "console.log(require('crypto').randomBytes(32).toString('hex'))"

Edit-scope gate
---------------

The ``/api/remediate/apply`` and ``/api/remediate/rollback`` endpoints
mutate Cloudflare configuration, so they are gated on **two** checks in
addition to ``FLAREINSPECT_API_KEY``:

1. ``FLAREINSPECT_ALLOW_REMEDIATION`` must be set to ``true`` (the
   global remediation kill switch — off by default).
2. The request body must include a ``token`` field that passes
   :js:func:`verifyEditScope` (see :doc:`/mcp/edit-scope` for the full
   policy).  The same gate protects the MCP ``apply_remediation`` and
   ``rollback`` tools, so the policy is identical across surfaces.

::

   # Run a read-only assessment, then re-enable apply with an
   # env-bound opaque secret
   export FLAREINSPECT_ALLOW_REMEDIATION=true
   export FLAREINSPECT_EDIT_SCOPE="$(openssl rand -hex 32)"
   node web/server.js

   # Apply a plan with that secret in the body
   curl -X POST http://localhost:3000/api/remediate/apply \
        -H "X-API-Key: $FLAREINSPECT_API_KEY" \
        -H "Content-Type: application/json" \
        -d "{ \"assessmentId\": \"...\", \"checkIds\": [\"CFL-SSL-001\"], \"token\": \"$FLAREINSPECT_EDIT_SCOPE\" }"

Security best practices
-----------------------

- Bind the dashboard to ``127.0.0.1`` unless you need remote access.
- Use a reverse proxy (nginx, Caddy) with TLS when exposing beyond localhost.
- Rotate API keys regularly.
- Use different keys for different environments.
- Treat ``FLAREINSPECT_EDIT_SCOPE`` like a credential.  Do not commit
  it; supply it at apply-time (or have the agent fetch it from the
  user's secret store).
