==================
Edit-Scope Policy
==================

The two mutating surfaces in FlareInspect — the MCP
``flareinspect_apply_remediation`` / ``flareinspect_rollback`` tools
and the web ``/api/remediate/apply`` / ``/api/remediate/rollback``
endpoints — share **one** policy, implemented in
``src/core/auth/editScope.js``.  An apply or rollback is allowed only
if **both** conditions below hold.

Conditions
----------

1. The global remediation kill-switch is on:

   .. code-block:: bash

      export FLAREINSPECT_ALLOW_REMEDIATION=true

   ``isRemediationEnabled()`` accepts ``true``, ``1``, ``yes``,
   ``on`` (case-insensitive).  Anything else — including an unset
   variable — disables remediation.

2. The supplied token satisfies ``verifyEditScope(token)``.  A token
   is accepted if **any** of these are true:

   a. The token **equals** the env-bound opaque secret
      ``FLAREINSPECT_EDIT_SCOPE``.  This is the recommended mode for
      a local agent: pick a strong secret, set it in the operator's
      shell, pass the same string back to the MCP tool.

   b. The token is a **JWT** whose payload carries
      ``permission: 'edit'`` — useful when the agent's host
      environment already mints short-lived edit tokens for the
      user.

   c. The token is a JWT whose ``aud`` claim is an array containing a
      string that includes the substring ``tag:edit`` (or a string
      ``aud`` that contains ``tag:edit``).

   d. The token is a JWT whose ``scope`` claim is a string
      containing the word ``edit`` (whitespace-delimited).

Anything else — empty token, wrong shape, wrong secret, read-only
JWT — is rejected.  ``verifyEditScope`` never throws; it returns a
boolean so callers can produce a clean MCP error response.

Quick start
-----------

For a local MCP agent (Claude Code, Cowork, etc.):

.. code-block:: bash

   # 1. Generate a strong secret
   export FLAREINSPECT_EDIT_SCOPE="$(openssl rand -hex 32)"

   # 2. Turn on the kill-switch
   export FLAREINSPECT_ALLOW_REMEDIATION=true

   # 3. Start the MCP server
   node mcp/server.mjs

   # 4. The agent passes $FLAREINSPECT_EDIT_SCOPE as the `token`
   #    argument on every call to flareinspect_apply_remediation or
   #    flareinspect_rollback.

For a web dashboard:

.. code-block:: bash

   export FLAREINSPECT_EDIT_SCOPE="..." FLAREINSPECT_ALLOW_REMEDIATION=true
   node web/server.js

   # Apply a plan with the secret in the body
   curl -X POST http://localhost:3000/api/remediate/apply \
     -H "X-API-Key: $FLAREINSPECT_API_KEY" \
     -H "Content-Type: application/json" \
     -d "{ \"assessmentId\": \"...\", \"checkIds\": [\"CFL-SSL-001\"],
           \"token\": \"$FLAREINSPECT_EDIT_SCOPE\" }"

For an external IdP that already mints edit-scoped JWTs (e.g. an
internal SSO), no env-bound secret is needed — the agent passes the
JWT directly:

.. code-block:: text

   {
     "alg": "RS256",
     "typ": "JWT"
   }
   .
   {
     "sub": "alice@acme.com",
     "aud": ["tag:edit:flareinspect"],
     "exp": 1748604896,
     "permission": "edit"
   }
   .
   <signature>

``verifyEditScope`` decodes the payload (signature verification is
the issuer's responsibility) and accepts the token if claim (b), (c),
or (d) holds.

Policy matrix
-------------

The full policy is unit-tested in ``tests/editScope.test.js``.  Some
highlights:

.. list-table::
   :header-rows: 1
   :widths: 40 12 48

   * - Token
     - Accepted?
     - Reason
   * - ``""`` (empty)
     - no
     - First guard fails
   * - ``"definitely-wrong"``
     - no
     - Doesn't match ``FLAREINSPECT_EDIT_SCOPE``, not a JWT
   * - ``"yes-i-am-the-edit-scope"`` (matches env)
     - **yes**
     - Opaque-secret match
   * - JWT with ``"permission": "edit"``
     - **yes**
     - Claim (b)
   * - JWT with ``"aud": ["flareinspect:tag:edit"]``
     - **yes**
     - Claim (c) — substring match
   * - JWT with ``"scope": "read profile email edit"``
     - **yes**
     - Claim (d) — word boundary match
   * - JWT with ``"permission": "read"``
     - no
     - Permission is not ``"edit"``
   * - JWT with no recognised claim
     - no
     - No claim matches

Security notes
--------------

- Treat ``FLAREINSPECT_EDIT_SCOPE`` like a credential.  Don't commit
  it; supply it at apply-time or have the agent fetch it from the
  user's secret store.
- The ``FLAREINSPECT_ALLOW_REMEDIATION`` kill-switch is **not** a
  substitute for an edit-scope token.  Without a token, even an
  enabled server refuses to apply.
- A read-only Cloudflare API token will not pass the gate — this is
  by design.  Use a different, edit-scoped token for apply.
- ``verifyEditScope`` does **not** verify JWT signatures — the
  issuer is responsible for signing.  A user-supplied JWT must come
  from a trusted source (e.g. the agent's host secret store).

Next steps
----------

- :doc:`index` — the MCP server overview
- :doc:`/web-dashboard/authentication` — the same gate, on the web
  dashboard
- ``src/core/auth/editScope.js`` — the source of truth
- ``tests/editScope.test.js`` — the policy matrix in code
