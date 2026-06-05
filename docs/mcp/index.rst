==================
MCP Server
==================

FlareInspect v2.0 ships a **Model Context Protocol (MCP) server**
that exposes the assess → find → path → plan → apply → rollback loop
to any MCP-aware agent (Claude Code, Cowork, Hermes, OpenClaw).  The
server uses **stdio** transport and re-uses the existing engine
seams — no logic is duplicated.

Install
-------

The MCP server is a binary in the package: ``flareinspect-mcp``,
pointing at ``mcp/server.mjs``.  The Model Context Protocol SDK
(``@modelcontextprotocol/sdk``) is declared as an *optional* dependency
so the package installs cleanly on machines that never need the
server.  When the SDK is missing the server starts and prints a clean
error; when it's present the server comes up immediately.

.. code-block:: bash

   # From a checkout of the repo
   node mcp/server.mjs

   # Or via npx (with the SDK available)
   npx -y flareinspect-mcp

   # Or, if you want the SDK pinned, install it explicitly
   npm install --no-save @modelcontextprotocol/sdk

Register it with an MCP-aware client (Claude Code example, in
``.mcp.json``):

.. code-block:: json

   {
     "mcpServers": {
       "flareinspect": {
         "command": "node",
         "args": ["/absolute/path/to/flareinspect/mcp/server.mjs"],
         "env": { "FLAREINSPECT_ALLOW_REMEDIATION": "true" }
       }
     }
   }

Tools
-----

The server registers six tools, all read-only by default.

.. list-table::
   :header-rows: 1
   :widths: 32 18 50

   * - Tool
     - Mutates?
     - Purpose
   * - ``flareinspect_assess``
     - no
     - Run a new assessment; return the summary
   * - ``flareinspect_list_findings``
     - no
     - Filter findings on an existing assessment (severity / status / limit)
   * - ``flareinspect_get_attack_paths``
     - no
     - Build the resource graph and run all attack-path rules
   * - ``flareinspect_plan_remediation``
     - no
     - Build a remediation plan (before→after diff) — *no mutation*
   * - ``flareinspect_apply_remediation``
     - **gated**
     - Apply a plan — mutates Cloudflare; requires ``FLAREINSPECT_ALLOW_REMEDIATION`` + edit-scope token
   * - ``flareinspect_rollback``
     - **gated**
     - Roll back from a backup bundle — mutates Cloudflare; same gate

The two **gated** tools share the same policy as the web
``/api/remediate/apply`` and ``/api/remediate/rollback`` endpoints.
See :doc:`edit-scope` for the full policy.

Example session
---------------

A typical agent loop looks like:

1. ``flareinspect_assess { token, zones: ["example.com"] }`` →
   returns ``assessmentId``, score, grade, finding count.
2. ``flareinspect_list_findings { assessment, severity: "high" }`` →
   the high-severity findings.
3. ``flareinspect_get_attack_paths { assessment }`` →
   the resource graph and the attack paths the findings participate in.
4. ``flareinspect_plan_remediation { assessment, checks: ["CFL-SSL-001"] }`` →
   the dry-run plan (proposed changes, before→after diff).
5. The agent confirms with the user, then
   ``flareinspect_apply_remediation { assessment, checkIds: ["CFL-SSL-001"], token }`` →
   applies the plan and returns a ``backupId``.
6. If something goes wrong, ``flareinspect_rollback { backupId, token }`` →
   restores the previous state.

Each step calls into the same engine module the CLI and the web API
use; an investigation started in the dashboard can be handed off to
an MCP-aware agent (or vice versa) without re-implementing logic.

Edit-scope policy
-----------------

The two gated tools refuse to run unless **both** conditions hold:

1. ``FLAREINSPECT_ALLOW_REMEDIATION`` is set to ``true`` (or ``1``,
   ``yes``, ``on``).  This is the global kill-switch — it is off by
   default and turning it on is an explicit operator decision.
2. The ``token`` argument the agent supplies satisfies
   :js:func:`verifyEditScope`.  The token may be an **opaque secret**
   matching ``FLAREINSPECT_EDIT_SCOPE``, or a **JWT** whose payload
   carries ``permission: 'edit'`` (or ``aud`` containing ``tag:edit``
   or ``scope`` containing ``edit``).

A read-only Cloudflare API token will fail step 2 — this is by
design.  See :doc:`edit-scope` for the full policy matrix.

Failure modes
-------------

- **SDK missing** — the server prints a clean error pointing at
  ``npm install --no-save @modelcontextprotocol/sdk``.  No stack
  trace.
- **Remediation disabled** — the gated tools throw
  ``Remediation is disabled. Set FLAREINSPECT_ALLOW_REMEDIATION=true
  to enable it.``
- **Token rejected** — the gated tools throw a structured error
  describing which check failed (no token / wrong shape / not
  edit-scoped).
- **Engine error** — propagated as a structured MCP error response;
  the agent sees the message.

.. toctree::
   :maxdepth: 1
   :hidden:

   edit-scope

Next steps
----------

- :doc:`edit-scope` — the token policy in detail
- :doc:`/architecture/overview` — how the MCP server fits into the
  engine seams
- ``mcp/server.mjs`` — the source of truth
