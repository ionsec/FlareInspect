===============
Troubleshooting
===============
===============

Common Errors
--------------

.. rubric:: 403 Forbidden

**Cause:** The API token lacks the required permissions for the endpoint being accessed.

**Fix:** Verify the token has the necessary read permissions. See :doc:`permissions-guide` for the minimum and recommended permission sets.

.. rubric:: No Matching Zones Found

**Cause:** The ``--zones`` filter excluded all zones, or the token cannot enumerate zones in the account.

**Fix:**

- Remove ``--zones`` to assess all visible zones
- Verify the token has **Zone → Read** permission
- Check that zone names match exactly (case-insensitive)

.. rubric:: Unknown Check Categories

**Cause:** The ``--checks`` flag included category names that FlareInspect does not recognize.

**Fix:** Use only supported categories. Run ``flareinspect help assess`` for the full list of 21 categories.

.. rubric:: Unknown Compliance Framework

**Cause:** The ``--compliance`` flag or API request used a framework name outside the supported set.

**Fix:** Use one of: ``cis``, ``soc2``, ``pci``, ``nist``.

.. rubric:: Fewer Zones Than Expected

**Cause:** The token may be scoped to a single Cloudflare account or organization. If your token can only enumerate one zone, the assessment will only cover that zone.

**Fix:** Verify the token scope and which Cloudflare account it can enumerate.

.. rubric:: Assessment Failed

**Cause:** An API error occurred during assessment. Check the error message for details.

**Fix:**

- Run with ``--debug`` for verbose API logging
- Check ``logs/error.log`` for stack traces
- Verify network connectivity to ``api.cloudflare.com``

Debug Mode
-----------

Enable verbose logging:

.. code-block:: bash

   flareinspect assess --token $TOKEN --debug

This sets ``CLOUDFLARE_DEBUG=true`` and logs every API request and response.

Logs
----

FlareInspect writes logs to:

=========================  =========================================
File                       Contents                                 
=========================  =========================================
``logs/flareinspect.log``  All log levels (rotated at 5 MB, 5 files)
``logs/error.log``         Error-level logs only                    
=========================  =========================================

Set ``LOG_LEVEL=debug`` for maximum verbosity.
